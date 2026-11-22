package message

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

type Filter struct {
	ID, Peer, Query, Direction, After, Before string
	Cursor                                    int64
	Limit                                     int
}

type messageInfo struct {
	seq                           int64
	id, sender, recipient         string
	senderHandle, recipientHandle string
	sent                          int64
	read, approved                sql.NullInt64
}

const messageColumns = `m.seq,m.id,m.sender,m.recipient,a.handle,b.handle,m.sent_ns,m.read_ns,m.approved_ns`
const messageFrom = ` FROM mail_messages m
	JOIN mail_accounts a ON a.subject=m.sender JOIN mail_accounts b ON b.subject=m.recipient `

func (m *messageInfo) scan(row interface{ Scan(...any) error }) error {
	return row.Scan(&m.seq, &m.id, &m.sender, &m.recipient, &m.senderHandle, &m.recipientHandle, &m.sent, &m.read, &m.approved)
}

func (m messageInfo) metadata(subject string) map[string]any {
	peer, direction := m.senderHandle, "incoming"
	if m.sender == subject {
		peer, direction = m.recipientHandle, "outgoing"
	}
	out := map[string]any{
		"message_id": m.id, "sender": display(m.senderHandle), "recipient": display(m.recipientHandle),
		"direction": direction, "peer": display(peer), "sent_at": timestamp(m.sent),
	}
	if m.read.Valid {
		out["read_at"] = timestamp(m.read.Int64)
	}
	return out
}

// Messages returns metadata only. Text filters cover outgoing messages and
// incoming messages approved individually or through current sender trust.
func (s *Store) Messages(ctx context.Context, subject string, f Filter) (map[string]any, error) {
	if stop, err := s.requireRegistration(ctx, subject); stop != nil || err != nil {
		return stop, err
	}
	if f.Limit == 0 {
		f.Limit = 30
	}
	if f.Limit < 1 || f.Limit > 100 || f.Cursor < 0 {
		return result("invalid_filter"), nil
	}
	where := []string{}
	args := []any{}
	switch f.Direction {
	case "", "all":
		where = append(where, "(m.sender=? OR m.recipient=?)")
		args = append(args, subject, subject)
	case "incoming":
		where = append(where, "m.recipient=?")
		args = append(args, subject)
	case "outgoing":
		where = append(where, "m.sender=?")
		args = append(args, subject)
	default:
		return result("invalid_filter"), nil
	}
	if f.ID != "" {
		where = append(where, "m.id=?")
		args = append(args, f.ID)
	}
	if f.Peer != "" {
		handle := canonical(f.Peer)
		if handle == "" {
			return result("invalid_filter"), nil
		}
		where = append(where, `CASE WHEN m.sender=? THEN b.handle ELSE a.handle END=?`)
		args = append(args, subject, handle)
	}
	// Intervals include their start and exclude their end, so adjacent
	// date windows can be combined without losing or repeating a message.
	for i, raw := range []string{f.After, f.Before} {
		if raw == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil || !time.Unix(0, t.UnixNano()).Equal(t) {
			return result("invalid_filter"), nil
		}
		where = append(where, []string{"m.sent_ns>=?", "m.sent_ns<?"}[i])
		args = append(args, t.UnixNano())
	}
	if q := strings.ToLower(strings.TrimSpace(f.Query)); q != "" {
		where = append(where, `CASE WHEN m.sender=? OR m.approved_ns IS NOT NULL OR EXISTS(
			SELECT 1 FROM mail_trust t WHERE t.owner=? AND t.sender=m.sender
		) THEN instr(m.body_folded,?) ELSE 0 END > 0`)
		args = append(args, subject, subject, q)
	}
	if f.Cursor != 0 {
		where = append(where, "m.seq<?")
		args = append(args, f.Cursor)
	}
	query := "SELECT " + messageColumns + messageFrom + " WHERE " + strings.Join(where, " AND ") + " ORDER BY m.seq DESC LIMIT ?"
	rows, err := s.db.QueryContext(ctx, query, append(args, f.Limit+1)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	out := result("ready")
	var lastSeq int64
	for rows.Next() {
		if len(items) == f.Limit {
			out["next_cursor"] = lastSeq
			break
		}
		var m messageInfo
		if err := m.scan(rows); err != nil {
			return nil, err
		}
		items = append(items, m.metadata(subject))
		lastSeq = m.seq
	}
	out["messages"] = items
	return out, rows.Err()
}
