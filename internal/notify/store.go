package notify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

const schema = `
CREATE TABLE IF NOT EXISTS notify_subscriptions (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, grant_id TEXT NOT NULL, callback TEXT NOT NULL,
 signing_key BLOB NOT NULL, previous_key BLOB, previous_until INTEGER NOT NULL DEFAULT 0,
 verified_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS notify_owner ON notify_subscriptions(owner,expires_at);
CREATE INDEX IF NOT EXISTS notify_expiry ON notify_subscriptions(expires_at);
CREATE TABLE IF NOT EXISTS notify_include_next (
 subscription_id TEXT PRIMARY KEY REFERENCES notify_subscriptions(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS notify_received (
 subscription_id TEXT PRIMARY KEY REFERENCES notify_subscriptions(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS notify_received_pending (
 subscription_id TEXT NOT NULL REFERENCES notify_received(subscription_id) ON DELETE CASCADE,
 message_id TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(subscription_id,message_id)
);
CREATE TABLE IF NOT EXISTS notify_read_waits (
 subscription_id TEXT PRIMARY KEY REFERENCES notify_subscriptions(id) ON DELETE CASCADE, request TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS notify_read_request ON notify_read_waits(request);
CREATE TABLE IF NOT EXISTS notify_read_ready (
 request TEXT PRIMARY KEY, owner TEXT NOT NULL, grant_id TEXT NOT NULL, message TEXT NOT NULL, occurred_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS notify_read_expiry ON notify_read_ready(occurred_at);
CREATE TABLE IF NOT EXISTS notify_jobs (
 subscription_id TEXT NOT NULL REFERENCES notify_subscriptions(id) ON DELETE CASCADE,
 message_id TEXT NOT NULL, sender TEXT NOT NULL, occurred_at INTEGER NOT NULL,
 ready_at INTEGER NOT NULL, attempt INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(subscription_id,message_id)
);
CREATE INDEX IF NOT EXISTS notify_ready ON notify_jobs(ready_at);
CREATE INDEX IF NOT EXISTS notify_subscription_ready ON notify_jobs(subscription_id,ready_at);
CREATE TABLE IF NOT EXISTS notify_dispatch (
 subscription_id TEXT PRIMARY KEY REFERENCES notify_subscriptions(id) ON DELETE CASCADE,
 owner TEXT NOT NULL, message_id TEXT NOT NULL, lease TEXT NOT NULL, lease_until INTEGER NOT NULL,
 last_claim INTEGER NOT NULL, retry_after INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS notify_dispatch_owner ON notify_dispatch(lease_until,owner);
CREATE TABLE IF NOT EXISTS notify_verifications (
 bucket TEXT PRIMARY KEY, window INTEGER NOT NULL, used INTEGER NOT NULL
);`

const verificationCache = time.Hour
const rotationWindow = 5 * time.Minute

func limited(limit string) error {
	data, _ := json.Marshal(map[string]string{"limit": limit})
	return &jsonrpc.Error{Code: -32025, Message: "Event subscription limit reached, retry later", Data: data}
}

// Reserve bounded challenge capacity before sending any request. The two counters
// share a transaction so exhausting a destination budget does not spend the owner's.
func (s *Service) reserveVerification(ctx context.Context, owner, callback string) error {
	u, err := url.Parse(callback)
	if err != nil {
		return err
	}
	hostHash := sha256.Sum256([]byte(strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	minute := s.now().Unix() / 60
	for _, budget := range []struct {
		bucket string
		limit  int
	}{{"account:" + owner, 12}, {"host:" + hex.EncodeToString(hostHash[:]), 240}} {
		r, err := tx.ExecContext(ctx, `INSERT INTO notify_verifications(bucket,window,used) VALUES(?,?,1)
			ON CONFLICT(bucket) DO UPDATE SET window=excluded.window,used=CASE WHEN window=excluded.window THEN used+1 ELSE 1 END
			WHERE window<>excluded.window OR used<?`, budget.bucket, minute, budget.limit)
		if err != nil {
			return err
		}
		n, err := r.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return limited("callback_verifications")
		}
	}
	return tx.Commit()
}

func (s *Service) saveVerified(ctx context.Context, id string, p Principal, callback string, key []byte, ttl time.Duration, request string, includeNext, receiveBodies bool) (time.Time, error) {
	var previous []byte
	var verified, expires int64
	err := s.db.QueryRowContext(ctx, "SELECT signing_key,verified_at,expires_at FROM notify_subscriptions WHERE id=?", id).Scan(&previous, &verified, &expires)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, err
	}
	now := s.now()
	if expires <= now.UnixMilli() || !bytes.Equal(previous, key) || verified <= now.Add(-verificationCache).UnixMilli() {
		select {
		case s.verifications <- struct{}{}:
			defer func() { <-s.verifications }()
		default:
			return time.Time{}, limited("callback_verifications")
		}
		if err := s.reserveVerification(ctx, p.Subject, callback); err != nil {
			return time.Time{}, err
		}
		if err := s.verify(ctx, endpoint{url: callback, key: key}, id); err != nil {
			return time.Time{}, err
		}
		verified = s.now().UnixMilli()
	}
	active, err := s.active(ctx, p.Subject, p.Grant)
	if err != nil {
		return time.Time{}, err
	}
	if !active {
		return time.Time{}, &jsonrpc.Error{Code: -32024, Message: "The account connection is no longer active"}
	}
	now = s.now()
	end := time.UnixMilli(now.Add(ttl).UnixMilli())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback()
	// Re-subscribing after expiry begins a fresh delivery window. Old jobs
	// disappear with their subscription, while the ordinary inbox persists.
	if _, err = tx.ExecContext(ctx, "DELETE FROM notify_subscriptions WHERE id=? AND expires_at<=?", id, now.UnixMilli()); err != nil {
		return time.Time{}, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM notify_subscriptions WHERE owner=? AND expires_at>? AND id<>?", p.Subject, now.UnixMilli(), id).Scan(&count); err != nil {
		return time.Time{}, err
	}
	if count >= 64 {
		return time.Time{}, limited("subscriptions")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO notify_subscriptions(id,owner,grant_id,callback,signing_key,verified_at,expires_at)
		VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
		previous_key=CASE WHEN signing_key<>excluded.signing_key THEN signing_key ELSE previous_key END,
		previous_until=CASE WHEN signing_key<>excluded.signing_key THEN ? ELSE previous_until END,
		signing_key=excluded.signing_key,verified_at=excluded.verified_at,expires_at=excluded.expires_at`,
		id, p.Subject, p.Grant, callback, key, verified, end.UnixMilli(), now.Add(rotationWindow).UnixMilli())
	if err != nil {
		return time.Time{}, err
	}
	if receiveBodies {
		if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO notify_received(subscription_id) VALUES(?)", id); err != nil {
			return time.Time{}, err
		}
	}
	// Existing subscriptions have no row and retain their original event format.
	if includeNext {
		_, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO notify_include_next(subscription_id) VALUES(?)", id)
	} else {
		_, err = tx.ExecContext(ctx, "DELETE FROM notify_include_next WHERE subscription_id=?", id)
	}
	if err != nil {
		return time.Time{}, err
	}
	if request != "" {
		added, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO notify_read_waits(subscription_id,request) VALUES(?,?)", id, request)
		if err != nil {
			return time.Time{}, err
		}
		fresh, err := added.RowsAffected()
		if err != nil {
			return time.Time{}, err
		}
		// Access may already have been granted when the host subscribes.
		if fresh == 1 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO notify_jobs(subscription_id,message_id,sender,occurred_at,ready_at)
    SELECT ?,message,'',occurred_at,? FROM notify_read_ready WHERE request=? AND owner=? AND grant_id=? AND occurred_at>?`,
				id, now.UnixMilli(), request, p.Subject, p.Grant, now.Add(-readWindow).UnixMilli()); err != nil {
				return time.Time{}, err
			}
		}
	}
	// An expired subscription was deleted above. Renewing the same active
	// subscription must not replay envelopes it may have already delivered.
	if request == "" && expires <= now.UnixMilli() {
		_, err := tx.ExecContext(ctx, `INSERT INTO notify_jobs(subscription_id,message_id,sender,occurred_at,ready_at)
			SELECT ?, m.id, '@' || a.handle, m.sent_ns / 1000000, ?
			FROM mail_messages m JOIN mail_accounts a ON a.subject=m.sender
			WHERE m.recipient=? AND m.read_ns IS NULL ORDER BY m.seq`, id, now.UnixMilli(), p.Subject)
		if err != nil {
			return time.Time{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return time.Time{}, err
	}
	s.signal()
	return end, nil
}

// Enqueue joins the transaction that writes the message. No network call or
// separate database connection runs while that transaction is open.
func (s *Service) Enqueue(ctx context.Context, tx *sql.Tx, recipient, messageID, senderHandle string) error {
	now := s.now().UnixMilli()
	_, err := tx.ExecContext(ctx, `INSERT INTO notify_jobs(subscription_id,message_id,sender,occurred_at,ready_at)
		SELECT id,?,?,?,? FROM notify_subscriptions WHERE owner=? AND expires_at>?
  AND NOT EXISTS(SELECT 1 FROM notify_read_waits w WHERE w.subscription_id=notify_subscriptions.id)
  ON CONFLICT(subscription_id,message_id) DO NOTHING`, messageID, senderHandle, now, now, recipient, now)
	if err == nil {
		s.signal()
	}
	return err
}

// Readable schedules only subscriptions for this approval request and OAuth grant.
// Keep the decision briefly so an immediately following registration can catch up.
func (s *Service) Readable(ctx context.Context, tx *sql.Tx, owner, grant, request, message string) error {
	now := s.now().UnixMilli()
	if _, err := tx.ExecContext(ctx, `INSERT INTO notify_read_ready(request,owner,grant_id,message,occurred_at) VALUES(?,?,?,?,?)`, request, owner, grant, message, now); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO notify_jobs(subscription_id,message_id,sender,occurred_at,ready_at)
 SELECT s.id,?,'',?,? FROM notify_subscriptions s JOIN notify_read_waits w ON w.subscription_id=s.id
 WHERE s.owner=? AND s.grant_id=? AND w.request=? AND s.expires_at>?
 ON CONFLICT(subscription_id,message_id) DO NOTHING`, message, now, now, owner, grant, request, now)
	if err == nil {
		s.signal()
	}
	return err
}

// Approved joins the owner's decision transaction. Only subscribers that were
// waiting for these messages are woken. In-flight or not-yet-delivered jobs
// recheck permission before posting; renewing never replays completed bodies.
func (s *Service) Approved(ctx context.Context, tx *sql.Tx, owner, messageID string, allFromSender bool) error {
	scope := "m.id=?"
	if allFromSender {
		scope = "m.sender=(SELECT sender FROM mail_messages WHERE recipient=s.owner AND id=?)"
	}
	from := ` FROM notify_received_pending p JOIN notify_subscriptions s ON s.id=p.subscription_id
  JOIN mail_messages m ON m.id=p.message_id AND m.recipient=s.owner
  JOIN mail_accounts a ON a.subject=m.sender
  WHERE s.owner=? AND s.expires_at>? AND ` + scope
	now := s.now().UnixMilli()
	// The revision prevents a notification acknowledgement from erasing a body
	// job that approval scheduled while the notification was in flight.
	if _, err := tx.ExecContext(ctx, `UPDATE notify_received_pending SET revision=revision+1
  WHERE (subscription_id,message_id) IN (SELECT p.subscription_id,m.id`+from+")", owner, now, messageID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO notify_jobs(subscription_id,message_id,sender,occurred_at,ready_at)
  SELECT p.subscription_id,m.id,'@'||a.handle,m.sent_ns/1000000,?`+from+`
  ON CONFLICT(subscription_id,message_id) DO UPDATE SET ready_at=excluded.ready_at,attempt=0`,
		now, owner, now, messageID)
	if err == nil {
		s.signal()
	}
	return err
}

func (s *Service) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
