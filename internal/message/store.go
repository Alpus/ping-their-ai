// Package message owns inboxes, message receipts, and read permissions.
package message

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"time"
)

type Store struct {
	db        *sql.DB
	widgetKey []byte
	readable  func(context.Context, *sql.Tx, string, string, string, string) error
	approved  func(context.Context, *sql.Tx, string, string, bool) error
	enqueue   func(context.Context, *sql.Tx, string, string, string) error
}

const (
	maxMessageBytes   = 16 * 1024
	maxRequestIDBytes = 128
	maxNoteBytes      = 1024
	sendsPerMinute    = 60
)

const schema = `
CREATE TABLE IF NOT EXISTS mail_widget_secret (
 id INTEGER PRIMARY KEY CHECK(id=1), secret BLOB NOT NULL
);
INSERT OR IGNORE INTO mail_widget_secret(id,secret) VALUES(1,randomblob(32));
CREATE TABLE IF NOT EXISTS mail_accounts (
	subject TEXT PRIMARY KEY NOT NULL,
	handle TEXT UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS mail_contacts (
	owner TEXT NOT NULL REFERENCES mail_accounts(subject),
	peer TEXT NOT NULL REFERENCES mail_accounts(subject),
	note TEXT NOT NULL,
	PRIMARY KEY (owner, peer)
);
CREATE TABLE IF NOT EXISTS mail_messages (
	seq INTEGER PRIMARY KEY,
	id TEXT UNIQUE NOT NULL,
	sender TEXT NOT NULL REFERENCES mail_accounts(subject),
	recipient TEXT NOT NULL REFERENCES mail_accounts(subject),
	request_id TEXT NOT NULL,
	body TEXT NOT NULL,
	body_folded TEXT NOT NULL,
	sent_ns INTEGER NOT NULL,
	read_ns INTEGER,
	approved_ns INTEGER,
	UNIQUE (sender, request_id)
);
CREATE INDEX IF NOT EXISTS mail_send_times ON mail_messages(sender, sent_ns);
CREATE INDEX IF NOT EXISTS mail_messages_from ON mail_messages(sender, seq);
CREATE INDEX IF NOT EXISTS mail_messages_to ON mail_messages(recipient, seq);
CREATE TABLE IF NOT EXISTS mail_trust (
	owner TEXT NOT NULL REFERENCES mail_accounts(subject),
	sender TEXT NOT NULL REFERENCES mail_accounts(subject),
	PRIMARY KEY (owner, sender)
);
-- Invalidate already-open browser forms when the owner revokes a sender.
CREATE TABLE IF NOT EXISTS mail_trust_revisions (
	owner TEXT NOT NULL REFERENCES mail_accounts(subject) ON DELETE CASCADE,
	sender TEXT NOT NULL REFERENCES mail_accounts(subject) ON DELETE CASCADE,
	revision TEXT NOT NULL,
	PRIMARY KEY (owner, sender)
);
CREATE TRIGGER IF NOT EXISTS mail_trust_revoked AFTER DELETE ON mail_trust BEGIN
	INSERT INTO mail_trust_revisions(owner,sender,revision) VALUES(OLD.owner,OLD.sender,hex(randomblob(16)))
	ON CONFLICT(owner,sender) DO UPDATE SET revision=excluded.revision;
END;
`

const approvalSchema = `CREATE TABLE IF NOT EXISTS mail_approvals (
	id TEXT PRIMARY KEY NOT NULL,
	message TEXT NOT NULL REFERENCES mail_messages(id),
	grant_id TEXT NOT NULL,
	client TEXT NOT NULL,
	state TEXT NOT NULL CHECK(state IN ('pending','once')),
	expires_ns INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS mail_read_grant ON mail_approvals(grant_id,expires_ns);
CREATE INDEX IF NOT EXISTS mail_read_expiry ON mail_approvals(expires_ns);
`

func New(ctx context.Context, db *sql.DB, enqueue func(context.Context, *sql.Tx, string, string, string) error, readable func(context.Context, *sql.Tx, string, string, string, string) error, approved func(context.Context, *sql.Tx, string, string, bool) error) (*Store, error) {
	if db == nil || enqueue == nil || readable == nil || approved == nil {
		return nil, errors.New("message store requires a database and event enqueue callback")
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		return nil, err
	}
	if err := prepareApprovals(ctx, db); err != nil {
		return nil, err
	}
	s := &Store{db: db, enqueue: enqueue, readable: readable, approved: approved}
	if err := db.QueryRowContext(ctx, "SELECT secret FROM mail_widget_secret WHERE id=1").Scan(&s.widgetKey); err != nil {
		return nil, err
	}
	return s, nil
}

func prepareApprovals(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Existing read receipts and one-time grants are not durable consent.
	var hasMessageApproval bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pragma_table_info('mail_messages') WHERE name='approved_ns')`).Scan(&hasMessageApproval); err != nil {
		return err
	}
	if !hasMessageApproval {
		if _, err := tx.ExecContext(ctx, "ALTER TABLE mail_messages ADD COLUMN approved_ns INTEGER"); err != nil {
			return err
		}
	}
	// Older schemas used a single pending decision per message and OAuth grant.
	var old bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pragma_index_list('mail_approvals') WHERE origin='u')`).Scan(&old); err != nil {
		return err
	}
	if old {
		if _, err = tx.ExecContext(ctx, "ALTER TABLE mail_approvals RENAME TO mail_approvals_legacy"); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, approvalSchema); err != nil {
		return err
	}
	if old {
		if _, err = tx.ExecContext(ctx, `INSERT INTO mail_approvals(id,message,grant_id,client,state,expires_ns)
  SELECT id,message,grant_id,client,state,expires_ns FROM mail_approvals_legacy; DROP TABLE mail_approvals_legacy`); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func result(status string) map[string]any {
	return map[string]any{"status": status}
}

var validHandle = regexp.MustCompile(`^[a-z][a-z0-9_]{2,31}$`)

// The auth service owns the signup grammar. Ping accepts the same immutable
// reserved handle in bare or display form, without changing its spelling in notes.
func canonical(handle string) string {
	handle = strings.TrimPrefix(strings.TrimSpace(handle), "@")
	for _, r := range handle {
		if r > 127 {
			return ""
		}
	}
	handle = strings.ToLower(handle)
	if !validHandle.MatchString(handle) {
		return ""
	}
	return handle
}

func display(handle string) string { return "@" + handle }

func (s *Store) Registered(ctx context.Context, subject string) (bool, error) {
	var registered bool
	err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM mail_accounts WHERE subject=?)", subject).Scan(&registered)
	return registered, err
}

func (s *Store) requireRegistration(ctx context.Context, subject string) (map[string]any, error) {
	registered, err := s.Registered(ctx, subject)
	if err != nil {
		return nil, err
	}
	if !registered {
		return result("registration_required"), nil
	}
	return nil, nil
}

func (s *Store) Register(ctx context.Context, subject, handle string) (map[string]any, error) {
	handle = canonical(handle)
	if subject == "" || handle == "" {
		return result("invalid_identity"), nil
	}
	if handle != "handle" {
		if _, err := s.db.ExecContext(ctx, "INSERT INTO mail_accounts(subject,handle) VALUES(?,?) ON CONFLICT DO NOTHING", subject, handle); err != nil {
			return nil, err
		}
	}
	var saved string
	err := s.db.QueryRowContext(ctx, "SELECT handle FROM mail_accounts WHERE subject=?", subject).Scan(&saved)
	if errors.Is(err, sql.ErrNoRows) {
		return result("handle_unavailable"), nil
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"status": "ready", "handle": display(saved)}, nil
}

func (s *Store) Contacts(ctx context.Context, subject string) (map[string]any, error) {
	if stop, err := s.requireRegistration(ctx, subject); stop != nil || err != nil {
		return stop, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT a.handle,c.note FROM mail_contacts c
		JOIN mail_accounts a ON a.subject=c.peer WHERE c.owner=? ORDER BY a.handle`, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	contacts := []map[string]any{}
	for rows.Next() {
		var handle, note string
		if err := rows.Scan(&handle, &note); err != nil {
			return nil, err
		}
		contacts = append(contacts, map[string]any{"handle": display(handle), "note": note})
	}
	return map[string]any{"status": "ready", "contacts": contacts}, rows.Err()
}

func (s *Store) SaveContact(ctx context.Context, subject, handle, note string) (map[string]any, error) {
	if stop, err := s.requireRegistration(ctx, subject); stop != nil || err != nil {
		return stop, err
	}
	if len(note) > maxNoteBytes {
		return map[string]any{"status": "note_too_large", "max_bytes": maxNoteBytes}, nil
	}
	handle = canonical(handle)
	r, err := s.db.ExecContext(ctx, `INSERT INTO mail_contacts(owner,peer,note)
		SELECT ?,subject,? FROM mail_accounts WHERE handle=?
		ON CONFLICT(owner,peer) DO UPDATE SET note=excluded.note`, subject, note, handle)
	if err != nil {
		return nil, err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return result("unknown_handle"), nil
	}
	return map[string]any{"status": "saved", "handle": display(handle), "note": note}, nil
}

func timestamp(ns int64) string {
	return time.Unix(0, ns).UTC().Format(time.RFC3339Nano)
}

func (s *Store) Send(ctx context.Context, subject, to, body, requestID string) (map[string]any, error) {
	if stop, err := s.requireRegistration(ctx, subject); stop != nil || err != nil {
		return stop, err
	}
	to = canonical(to)
	var invalid map[string]any
	switch {
	case len(requestID) > maxRequestIDBytes:
		invalid = map[string]any{"status": "request_id_too_long", "max_bytes": maxRequestIDBytes}
	case len(body) > maxMessageBytes:
		invalid = map[string]any{"status": "message_too_large", "max_bytes": maxMessageBytes}
	case strings.TrimSpace(requestID) == "" || strings.TrimSpace(body) == "":
		invalid = result("invalid_message")
	case to == "handle":
		invalid = map[string]any{"status": "reserved_handle", "next": "Replace @handle with the recipient's actual Ping handle."}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var id string
	if invalid == nil {
		id = rand.Text()
		now := time.Now()
		// The covering (sender, sent_ns) index visits at most 60 entries.
		// Checking in the INSERT keeps concurrent sends inside the same limit.
		_, err = tx.ExecContext(ctx, `INSERT INTO mail_messages(id,sender,recipient,request_id,body,body_folded,sent_ns)
			SELECT ?,?,subject,?,?,?,? FROM mail_accounts WHERE handle=? AND NOT EXISTS (
				SELECT 1 FROM mail_messages WHERE sender=? AND sent_ns>?
				ORDER BY sent_ns DESC LIMIT 1 OFFSET ?
			) ON CONFLICT(sender,request_id) DO NOTHING`, id, subject, requestID, body, strings.ToLower(body),
			now.UnixNano(), to, subject, now.Add(-time.Minute).UnixNano(), sendsPerMinute-1)
		if err != nil {
			return nil, err
		}
	}
	var savedID, recipient, recipientHandle, senderHandle, savedBody string
	var ns int64
	err = tx.QueryRowContext(ctx, `SELECT m.id,m.recipient,r.handle,s.handle,m.body,m.sent_ns FROM mail_messages m
		JOIN mail_accounts r ON r.subject=m.recipient JOIN mail_accounts s ON s.subject=m.sender
		WHERE m.sender=? AND m.request_id=?`, subject, requestID).
		Scan(&savedID, &recipient, &recipientHandle, &senderHandle, &savedBody, &ns)
	if errors.Is(err, sql.ErrNoRows) {
		if invalid != nil {
			return invalid, nil
		}
		var known bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM mail_accounts WHERE handle=?)", to).Scan(&known); err != nil {
			return nil, err
		}
		if !known {
			return result("unknown_handle"), nil
		}
		return map[string]any{"status": "rate_limited", "retry_after_seconds": 60}, nil
	}
	if err != nil {
		return nil, err
	}
	// Return the original receipt even if new writes of this size or from this
	// sender are currently restricted. Reusing a key never changes its payload.
	if savedBody != body || recipientHandle != to {
		return result("request_conflict"), nil
	}
	if savedID == id {
		if err := s.enqueue(ctx, tx, recipient, id, display(senderHandle)); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return map[string]any{"status": "sent", "message_id": savedID, "sender": display(senderHandle), "recipient": display(recipientHandle), "sent_at": timestamp(ns)}, nil
}
