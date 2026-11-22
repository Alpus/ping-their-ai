package notify

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type job struct {
	subID, message, sender, lease string
	occurred                      int64
	attempt                       int
	received                      bool
	revision                      int64
	receiptOwner                  string
}

const maxAttempts = 5

// Run processes the durable outbox with a bounded number of concurrent HTTPS deliveries.
func (s *Service) Run(ctx context.Context) {
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for ctx.Err() == nil {
				didWork, err := s.processNext(ctx)
				if didWork && err == nil {
					continue
				}
				select {
				case <-ctx.Done():
					return
				case <-s.wake:
				case <-ticker.C:
				}
			}
		})
	}
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			workers.Wait()
			s.client.CloseIdleConnections()
			return
		case <-ticker.C:
			now := s.now()
			s.db.ExecContext(ctx, "DELETE FROM notify_read_ready WHERE occurred_at<=?", now.Add(-readWindow).UnixMilli())
			s.db.ExecContext(ctx, "DELETE FROM notify_subscriptions WHERE expires_at<=?", now.UnixMilli())
			s.db.ExecContext(ctx, "UPDATE notify_subscriptions SET previous_key=NULL,previous_until=0 WHERE previous_key IS NOT NULL AND previous_until<=?", now.UnixMilli())
			s.db.ExecContext(ctx, "DELETE FROM notify_verifications WHERE window<?", now.Unix()/60-1)
		}
	}
}

// Lease one job per owner. Look up only the head of each eligible subscription's
// queue, even when a slow callback has accumulated many thousands of events.
func (s *Service) claim(ctx context.Context) (job, error) {
	now := s.now()
	j := job{lease: rand.Text()}
	err := s.db.QueryRowContext(ctx, `INSERT INTO notify_dispatch(subscription_id,owner,message_id,lease,lease_until,last_claim)
		SELECT s.id,s.owner,j.message_id,?1,?2,?3
		FROM (SELECT 1 FROM notify_jobs WHERE ready_at<=?3 LIMIT 1) AS due
		CROSS JOIN notify_subscriptions s
		LEFT JOIN notify_dispatch d ON d.subscription_id=s.id
		CROSS JOIN notify_jobs j ON j.rowid=(
		    SELECT rowid FROM notify_jobs WHERE subscription_id=s.id AND ready_at<=?3
		    ORDER BY ready_at,rowid LIMIT 1)
		WHERE s.owner NOT IN (SELECT owner FROM notify_dispatch WHERE lease_until>?3)
		  AND COALESCE(d.retry_after,0)<=?3
		ORDER BY COALESCE(d.last_claim,0),j.ready_at,j.rowid LIMIT 1
		ON CONFLICT(subscription_id) DO UPDATE SET message_id=excluded.message_id,
		    lease=excluded.lease,lease_until=excluded.lease_until,last_claim=excluded.last_claim,retry_after=0
		RETURNING subscription_id,message_id`,
		j.lease, now.Add(time.Minute).UnixMilli(), now.UnixMilli(),
	).Scan(&j.subID, &j.message)
	return j, err
}

func (s *Service) processNext(ctx context.Context) (bool, error) {
	j, err := s.claim(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	s.signal()
	unlock := s.lockSubscription(j.subID)
	defer unlock()
	// Re-read after acquiring the lock: a concurrent unsubscribe, refresh or
	// revocation may already have changed this row and its endpoint.
	var dest endpoint
	var p Principal
	var expires int64
	var request sql.NullString
	var includeNext, receiveBodies bool
	now := s.now()
	err = s.db.QueryRowContext(ctx, `SELECT s.callback,s.signing_key,CASE WHEN s.previous_until>? THEN s.previous_key END,
		s.owner,s.grant_id,s.expires_at,j.sender,j.occurred_at,j.attempt,w.request,
		EXISTS(SELECT 1 FROM notify_include_next n WHERE n.subscription_id=s.id),
  EXISTS(SELECT 1 FROM notify_received v WHERE v.subscription_id=s.id)
		FROM notify_subscriptions s LEFT JOIN notify_read_waits w ON s.id=w.subscription_id
		JOIN notify_jobs j ON j.subscription_id=s.id
		JOIN notify_dispatch d ON d.subscription_id=s.id AND d.message_id=j.message_id
		WHERE s.id=? AND d.lease=? AND d.lease_until>?`,
		now.UnixMilli(), j.subID, j.lease, now.UnixMilli()).Scan(&dest.url, &dest.key, &dest.oldKey, &p.Subject, &p.Grant, &expires, &j.sender, &j.occurred, &j.attempt, &request, &includeNext, &receiveBodies)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return true, err
	}
	active := false
	if expires > now.UnixMilli() {
		active, err = s.active(ctx, p.Subject, p.Grant)
		if err != nil {
			// No delivery was attempted. Retry the lookup without discarding the
			// subscription or spending any of this event's delivery attempts.
			retry := now.Add(5 * time.Second)
			return true, errors.Join(err, s.settle(ctx, j, retry, retry))
		}
	}
	if !active {
		_, err = s.db.ExecContext(ctx, `DELETE FROM notify_subscriptions WHERE id=? AND
		    EXISTS (SELECT 1 FROM notify_dispatch WHERE subscription_id=? AND lease=?)`, j.subID, j.subID, j.lease)
		return true, err
	}
	name := eventName
	instruction := ""
	data := map[string]string{"message_id": j.message, "sender_handle": j.sender}
	eventKey := j.message
	var sendingBody bool
	if receiveBodies {
		// Track the message BEFORE checking access: an approval concurrent with the
		// check either makes the body immediately available or advances the revision.
		err := s.db.QueryRowContext(ctx, `INSERT INTO notify_received_pending(subscription_id,message_id) VALUES(?,?)
   ON CONFLICT(subscription_id,message_id) DO UPDATE SET message_id=excluded.message_id RETURNING revision`, j.subID, j.message).Scan(&j.revision)
		if err != nil {
			return true, err
		}
		j.received = true
		name = receivedEvent
		var sentNS int64
		if err = s.db.QueryRowContext(ctx, "SELECT sent_ns FROM mail_messages WHERE recipient=? AND id=?", p.Subject, j.message).Scan(&sentNS); err != nil {
			return true, err
		}
		data["sent_at"] = time.Unix(0, sentNS).UTC().Format(time.RFC3339Nano)
		data["message_url"] = s.delivery.MessageURL(j.message)
		text, err := s.delivery.Body(ctx, p.Subject, j.message)
		if err != nil {
			retry := now.Add(5 * time.Second)
			return true, errors.Join(err, s.settle(ctx, j, retry, retry))
		}
		data["status"] = "approval_required"
		if text != nil {
			data["status"] = "readable"
			data["body"] = *text
			sendingBody = true
		} else if includeNext {
			data["review_action"] = fmt.Sprintf("[Review message from %s](<%s>)", j.sender, data["message_url"])
		}
		eventKey = name + "\x00" + j.subID + "\x00" + j.message + "\x00" + data["status"]
	} else if request.Valid {
		name = readableEvent
		instruction = readableNext
		data = map[string]string{"message_id": j.message, "request_id": request.String}
		eventKey = name + "\x00" + request.String
	}
	if includeNext && !receiveBodies {
		if !request.Valid {
			instruction = fmt.Sprintf(createdNext, s.delivery.MessageURL(j.message))
		}
		data["next"] = instruction
	}
	hash := sha256.Sum256([]byte(eventKey))
	eventID := "evt_" + base64.RawURLEncoding.EncodeToString(hash[:])
	body, err := json.Marshal(struct {
		ID        string            `json:"eventId"`
		Name      string            `json:"name"`
		Timestamp time.Time         `json:"timestamp"`
		Data      map[string]string `json:"data"`
		Cursor    *string           `json:"cursor"`
	}{eventID, name, time.UnixMilli(j.occurred).UTC(), data, nil})
	if err != nil {
		return true, err
	}
	status := 0
	var retryHeader string
	resp, err := s.post(ctx, dest, j.subID, eventID, body)
	if err == nil {
		status = resp.StatusCode
		retryHeader = resp.Header.Get("Retry-After")
		// Drain only a small response so standard acknowledgements reuse TLS.
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
	}
	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	if sendingBody && status >= 200 && status < 300 {
		j.receiptOwner = p.Subject
	}
	transient := status == 0 || status == 408 || status == 425 || status == 429 || status >= 500
	var next, pause time.Time
	if transient {
		now = s.now()
		// A receiver can defer this subscription only through its current term.
		// Renewing keeps that deadline, even if the original header was longer.
		expiry := time.UnixMilli(expires)
		pause = retryAfter(now, retryHeader)
		if pause.After(expiry) {
			pause = expiry
		}
		// Old versions charged the lease itself. Even an interrupted last lease
		// gets a delivery here. New rows count only completed transport failures.
		j.attempt++
		if j.attempt < maxAttempts {
			next = now.Add(5 * time.Second << (j.attempt - 1))
			if pause.After(next) {
				next = pause
			}
			if next.After(expiry) {
				next = expiry
			}
		}
	}
	return true, s.settle(ctx, j, next, pause)
}

func retryAfter(now time.Time, value string) time.Time {
	seconds, err := strconv.ParseUint(value, 10, 64)
	if err == nil || errors.Is(err, strconv.ErrRange) {
		return now.Add(time.Duration(min(seconds, math.MaxInt64/uint64(time.Second))) * time.Second)
	}
	date, err := http.ParseTime(value)
	if err == nil && date.After(now) {
		return date
	}
	return time.Time{}
}

// A worker resuming after a long interruption can no longer change a job
// claimed by its successor. Release the owner and settle the event atomically.
func (s *Service) settle(ctx context.Context, j job, next, pause time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	released, err := tx.ExecContext(ctx, `UPDATE notify_dispatch SET lease='',lease_until=0,retry_after=?
		WHERE subscription_id=? AND lease=?`, pause.UnixMilli(), j.subID, j.lease)
	if err != nil {
		return err
	}
	n, err := released.RowsAffected()
	if err != nil || n == 0 {
		return err
	}
	if j.receiptOwner != "" {
		if err := s.delivery.Acknowledge(ctx, tx, j.receiptOwner, j.message); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM notify_received_pending WHERE subscription_id=? AND message_id=?", j.subID, j.message); err != nil {
			return err
		}
	} else if j.received {
		var superseded bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM notify_received_pending
   WHERE subscription_id=? AND message_id=? AND revision<>?)`, j.subID, j.message, j.revision).Scan(&superseded); err != nil {
			return err
		}
		if superseded {
			return tx.Commit()
		}
	}
	if next.IsZero() {
		_, err = tx.ExecContext(ctx, "DELETE FROM notify_jobs WHERE subscription_id=? AND message_id=?", j.subID, j.message)
	} else {
		_, err = tx.ExecContext(ctx, "UPDATE notify_jobs SET ready_at=?,attempt=? WHERE subscription_id=? AND message_id=?", next.UnixMilli(), j.attempt, j.subID, j.message)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}
