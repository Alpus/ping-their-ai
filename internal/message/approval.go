package message

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

const approvalLifetime = 15 * time.Minute

// WidgetProof is sent only in a trusted host's component-only result metadata.
// The browser link uses a separate session and CSRF protection. Knowing that
// link or its request ID does not authorize a model to make the decision.
func (s *Store) WidgetProof(subject, grant, message, request string) string {
	mac := hmac.New(sha256.New, s.widgetKey)
	encoded, _ := json.Marshal([4]string{subject, grant, message, request})
	mac.Write(encoded)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Store) DecideWidget(ctx context.Context, subject, grant, message, request, proof, decision string) (map[string]any, error) {
	if !hmac.Equal([]byte(proof), []byte(s.WidgetProof(subject, grant, message, request))) {
		return result("unavailable"), nil
	}
	return s.decide(ctx, subject, request, decision, false)
}

func (s *Store) Read(ctx context.Context, subject, grant, client, id, request string) (map[string]any, error) {
	if stop, err := s.requireRegistration(ctx, subject); stop != nil || err != nil {
		return stop, err
	}
	if grant == "" {
		return result("invalid_connection"), nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now()
	// This conditional write obtains the SQLite write lock before the remaining
	// permission checks and consumes a live legacy one-time grant, if supplied.
	consumed, err := tx.ExecContext(ctx, `DELETE FROM mail_approvals WHERE id=? AND message=? AND grant_id=?
		AND state='once' AND expires_ns>? AND EXISTS (
			SELECT 1 FROM mail_messages m WHERE m.id=mail_approvals.message AND m.recipient=?
		)`, request, id, grant, now.UnixNano(), subject)
	if err != nil {
		return nil, err
	}
	n, err := consumed.RowsAffected()
	if err != nil {
		return nil, err
	}
	var m messageInfo
	err = m.scan(tx.QueryRowContext(ctx, "SELECT "+messageColumns+messageFrom+" WHERE m.id=? AND (m.recipient=? OR m.sender=?)", id, subject, subject))
	if errors.Is(err, sql.ErrNoRows) {
		return result("not_found"), nil
	}
	if err != nil {
		return nil, err
	}
	allowed := m.sender == subject || m.approved.Valid || n == 1
	if !allowed {
		err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM mail_trust WHERE owner=? AND sender=?)", subject, m.sender).Scan(&allowed)
		if err != nil {
			return nil, err
		}
	}
	if !allowed {
		key := request
		if key != "" {
			var exists bool
			err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mail_approvals WHERE id=? AND message=? AND grant_id=? AND state='pending' AND expires_ns>?)`, key, id, grant, now.UnixNano()).Scan(&exists)
			if err != nil {
				return nil, err
			}
			if !exists {
				return map[string]any{"status": "request_unavailable", "message_id": id, "next": "Open this message ID again without a request_id to ask for fresh permission."}, nil
			}
		} else {
			if _, err = tx.ExecContext(ctx, "DELETE FROM mail_approvals WHERE expires_ns<=?", now.UnixNano()); err != nil {
				return nil, err
			}
			key = rand.Text()
			inserted, err := tx.ExecContext(ctx, `INSERT INTO mail_approvals(id,message,grant_id,client,state,expires_ns)
       SELECT ?,?,?,?,'pending',? WHERE NOT EXISTS(SELECT 1 FROM mail_approvals WHERE grant_id=? LIMIT 1 OFFSET 127)`, key, id, grant, client, now.Add(approvalLifetime).UnixNano(), grant)
			if err != nil {
				return nil, err
			}
			count, err := inserted.RowsAffected()
			if err != nil {
				return nil, err
			}
			if count == 0 {
				return result("too_many_pending_requests"), nil
			}
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		out := m.metadata(subject)
		out["status"], out["approval_key"] = "approval_required", key
		return out, nil
	}
	if m.recipient == subject && !m.read.Valid {
		m.read = sql.NullInt64{Int64: now.UnixNano(), Valid: true}
		if _, err := tx.ExecContext(ctx, "UPDATE mail_messages SET read_ns=? WHERE id=?", m.read.Int64, id); err != nil {
			return nil, err
		}
	}
	var body string
	if err := tx.QueryRowContext(ctx, "SELECT body FROM mail_messages WHERE id=?", id).Scan(&body); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	out := m.metadata(subject)
	out["status"], out["body"] = "read", body
	return out, nil
}

func (s *Store) Approval(ctx context.Context, subject, key string) (map[string]any, error) {
	var id, sender, recipient, client, body string
	err := s.db.QueryRowContext(ctx, `SELECT m.id,a.handle,b.handle,p.client,m.body`+messageFrom+`
		JOIN mail_approvals p ON p.message=m.id
		WHERE p.id=? AND m.recipient=? AND p.state='pending' AND p.expires_ns>?`, key, subject, time.Now().UnixNano()).
		Scan(&id, &sender, &recipient, &client, &body)
	if errors.Is(err, sql.ErrNoRows) {
		return result("unavailable"), nil
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"status": "pending", "message_id": id, "sender": display(sender), "recipient": display(recipient), "client": client, "body": body}, nil
}

// A browser preview is scoped to the recipient. Only an authorized AI read
// records a receipt. Legacy one-time approvals remain bound to their request.
const inboxWideAccess = `(m.approved_ns IS NOT NULL OR EXISTS (
	SELECT 1 FROM mail_trust t WHERE t.owner=m.recipient AND t.sender=m.sender
))`

const trustRevision = `COALESCE((SELECT revision FROM mail_trust_revisions
	WHERE owner=m.recipient AND sender=m.sender),'')`

func (s *Store) PreviewMessage(ctx context.Context, subject, id string) (map[string]any, error) {
	var sender, body, revision string
	var allowed bool
	err := s.db.QueryRowContext(ctx, `SELECT a.handle,m.body,`+inboxWideAccess+","+trustRevision+messageFrom+
		` WHERE m.id=? AND m.recipient=?`, id, subject).Scan(&sender, &body, &allowed, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return result("unavailable"), nil
	}
	if err != nil {
		return nil, err
	}
	status := "pending"
	if allowed {
		status = "readable"
	}
	return map[string]any{"status": status, "sender": display(sender), "body": body, "revision": revision}, nil
}

// DecideMessage handles the recipient's choice on the stable message page.
// The page can precede any AI request. Resolve all existing matching requests
// with their original grants if the owner chooses to allow access.
func (s *Store) DecideMessage(ctx context.Context, subject, id, decision, revision string) (map[string]any, error) {
	var status string
	switch decision {
	case "allow_message":
		status = "message_allowed"
	case "always":
		status = "trusted"
	case "later":
		status = "later"
	default:
		return result("invalid_decision"), nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var approved, trusted bool
	var currentRevision string
	err = tx.QueryRowContext(ctx, `SELECT m.approved_ns IS NOT NULL,
		EXISTS(SELECT 1 FROM mail_trust WHERE owner=m.recipient AND sender=m.sender),`+trustRevision+`
		FROM mail_messages m WHERE m.id=? AND m.recipient=?`, id, subject).Scan(&approved, &trusted, &currentRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return result("unavailable"), nil
	}
	if err != nil {
		return nil, err
	}
	if revision != currentRevision {
		return result("permissions_changed"), nil
	}
	if trusted {
		return result("trusted"), nil
	}
	if approved {
		if decision == "always" {
			return result("only_message_allowed"), nil
		}
		return result("message_allowed"), nil
	}
	if decision != "later" {
		if err := s.grantInboxAccess(ctx, tx, subject, id, decision, time.Now()); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return map[string]any{"status": status, "message_id": id}, nil
}

// PreviewWidget authenticates a component request without granting access or recording a read.
func (s *Store) PreviewWidget(ctx context.Context, subject, grant, message, request, proof string) (map[string]any, error) {
	if !hmac.Equal([]byte(proof), []byte(s.WidgetProof(subject, grant, message, request))) {
		return result("unavailable"), nil
	}
	return s.Approval(ctx, subject, request)
}

func (s *Store) Decide(ctx context.Context, subject, key, decision string) (map[string]any, error) {
	return s.decide(ctx, subject, key, decision, true)
}

func (s *Store) decide(ctx context.Context, subject, key, decision string, fromBrowser bool) (map[string]any, error) {
	now := time.Now()
	// Exactly one POST can transition a live recipient-owned approval away
	// from pending. A preview, retry, expired key, or different account cannot.
	const where = ` WHERE id=? AND state='pending' AND expires_ns>? AND EXISTS (
		SELECT 1 FROM mail_messages m WHERE m.id=mail_approvals.message AND m.recipient=?
	) RETURNING message,grant_id`
	var query, status string
	args := []any{key, now.UnixNano(), subject}
	switch decision {
	case "allow_message":
		query, status = "DELETE FROM mail_approvals"+where, "message_allowed"
	case "once":
		query, status = "UPDATE mail_approvals SET state='once',expires_ns=?"+where, "approved_once"
		args = append([]any{now.Add(approvalLifetime).UnixNano()}, args...)
	case "always":
		query, status = "DELETE FROM mail_approvals"+where, "trusted"
	case "later":
		query, status = "DELETE FROM mail_approvals"+where, "later"
	default:
		return result("invalid_decision"), nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var messageID, grant string
	err = tx.QueryRowContext(ctx, query, args...).Scan(&messageID, &grant)
	if errors.Is(err, sql.ErrNoRows) {
		return result("unavailable"), nil
	}
	if err != nil {
		return nil, err
	}
	if decision == "allow_message" || decision == "always" {
		if err := s.grantInboxAccess(ctx, tx, subject, messageID, decision, now); err != nil {
			return nil, err
		}
	}
	if fromBrowser && decision != "later" {
		if err := s.readable(ctx, tx, subject, grant, key, messageID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return map[string]any{"status": status, "message_id": messageID}, nil
}

func (s *Store) grantInboxAccess(ctx context.Context, tx *sql.Tx, subject, id, decision string, now time.Time) error {
	var err error
	if decision == "always" {
		_, err = tx.ExecContext(ctx, `INSERT INTO mail_trust(owner,sender)
			SELECT recipient,sender FROM mail_messages WHERE id=? ON CONFLICT DO NOTHING`, id)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE mail_messages SET approved_ns=? WHERE id=? AND approved_ns IS NULL`, now.UnixNano(), id)
	}
	if err != nil {
		return err
	}
	return s.finishRelatedRequests(ctx, tx, subject, id, decision == "always", now)
}

// The deciding request has already been consumed. Other chats that requested
// access resume through their own grant and request, including late subscribers.
func (s *Store) finishRelatedRequests(ctx context.Context, tx *sql.Tx, owner, messageID string, trustSender bool, now time.Time) error {
	scope := "message=? AND state='pending'"
	args := []any{messageID}
	if trustSender {
		// As before, sender trust supersedes every outstanding decision for
		// this sender and recipient. Only live pending requests need a wake.
		scope = `message IN (SELECT id FROM mail_messages
			WHERE recipient=? AND sender=(SELECT sender FROM mail_messages WHERE id=?))`
		args = []any{owner, messageID}
	}
	rows, err := tx.QueryContext(ctx, "DELETE FROM mail_approvals WHERE "+scope+" RETURNING id,grant_id,message,state,expires_ns", args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var request, grant, message, state string
		var expires int64
		if err := rows.Scan(&request, &grant, &message, &state, &expires); err != nil {
			return err
		}
		if state == "pending" && expires > now.UnixNano() {
			if err := s.readable(ctx, tx, owner, grant, request, message); err != nil {
				return err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return s.approved(ctx, tx, owner, messageID, trustSender)
}

func (s *Store) Trusts(ctx context.Context, subject string) (map[string]any, error) {
	if stop, err := s.requireRegistration(ctx, subject); stop != nil || err != nil {
		return stop, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT a.handle FROM mail_trust t JOIN mail_accounts a ON a.subject=t.sender
		WHERE t.owner=? ORDER BY a.handle`, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	trusts := []map[string]any{}
	for rows.Next() {
		var handle string
		if err := rows.Scan(&handle); err != nil {
			return nil, err
		}
		trusts = append(trusts, map[string]any{"handle": display(handle)})
	}
	return map[string]any{"status": "ready", "trusts": trusts}, rows.Err()
}

func (s *Store) Revoke(ctx context.Context, subject, peer string) (map[string]any, error) {
	if stop, err := s.requireRegistration(ctx, subject); stop != nil || err != nil {
		return stop, err
	}
	handle := canonical(peer)
	if handle == "" {
		return result("unknown_handle"), nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM mail_trust WHERE owner=?
		AND sender=(SELECT subject FROM mail_accounts WHERE handle=?)`, subject, handle)
	if err != nil {
		return nil, err
	}
	return map[string]any{"status": "revoked", "handle": display(handle)}, nil
}
