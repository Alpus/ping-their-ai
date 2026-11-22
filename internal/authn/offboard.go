package authn

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

var errOffboarded = errors.New("account disabled")

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Credentials issued before the first offboarding keep their original subject.
func accountCredential(ctx context.Context, q rowQuerier, subject string) (string, error) {
	var generation string
	var disabled bool
	err := q.QueryRowContext(ctx, "SELECT generation,disabled FROM auth_offboarded WHERE subject=?", subject).Scan(&generation, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return subject, nil
	}
	if err != nil {
		return "", err
	}
	if disabled {
		return "", errOffboarded
	}
	return subject + "/" + generation, nil
}

// SetAccountAccess can run from a second process while the server owns the OAuth
// database. The account block and invalidation of its browser sessions are atomic.
func SetAccountAccess(ctx context.Context, db *sql.DB, handle string, enabled bool) error {
	handle = strings.TrimPrefix(strings.ToLower(handle), "@")
	if !handlePattern.MatchString(handle) {
		return errors.New("invalid handle")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var subject string
	err = tx.QueryRowContext(ctx, "SELECT subject FROM auth_accounts WHERE handle=?", handle).Scan(&subject)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("unknown handle")
	}
	if err != nil {
		return err
	}
	if enabled {
		if _, err = tx.ExecContext(ctx, "UPDATE auth_offboarded SET disabled=0 WHERE subject=?", subject); err != nil {
			return err
		}
		return tx.Commit()
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO auth_offboarded(subject,generation,disabled) VALUES(?,?,1)
		ON CONFLICT(subject) DO UPDATE SET generation=excluded.generation,disabled=1 WHERE disabled=0`, subject, opaque()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM auth_flows WHERE token IN (SELECT flow FROM auth_oidc WHERE subject=?)", subject); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM auth_sessions WHERE subject=?", subject); err != nil {
		return err
	}
	return tx.Commit()
}
