package message

import (
	"context"
	"database/sql"
	"time"
)

// DeliveryBody returns text only under current inbox-wide permission. A browser
// preview, a previous read, or a legacy grant-specific approval is insufficient.
func (s *Store) DeliveryBody(ctx context.Context, owner, id string) (*string, error) {
	var body *string
	err := s.db.QueryRowContext(ctx, "SELECT CASE WHEN "+inboxWideAccess+" THEN m.body END FROM mail_messages m WHERE m.id=? AND m.recipient=?", id, owner).Scan(&body)
	return body, err
}

// AcknowledgeDelivery shares the transaction that settles a successful body delivery.
func (s *Store) AcknowledgeDelivery(ctx context.Context, tx *sql.Tx, owner, id string) error {
	_, err := tx.ExecContext(ctx, "UPDATE mail_messages SET read_ns=? WHERE id=? AND recipient=? AND read_ns IS NULL", time.Now().UnixNano(), id, owner)
	return err
}
