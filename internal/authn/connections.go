package authn

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/ajent-social/go/mcpoauth"
	"github.com/ajent-social/go/mcpoauth/boltstore"
	bolt "go.etcd.io/bbolt"
)

// The OAuth store owns all credentials. Keep an owner-to-grant index for the
// profile because the store's public interface only supports lookup by ID.
type connectionsStore struct {
	*boltstore.Store
	db     *sql.DB
	prefix string
}

// Rebuild the derived index from the v1 grant records on each start. This
// includes grants issued by older binaries or restored separately from SQLite.
func initializeConnections(ctx context.Context, db *sql.DB, path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		_, err = db.ExecContext(ctx, "DELETE FROM auth_connections")
		return err
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0 {
		return errors.New("OAuth database must be a private regular file")
	}
	old, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		return err
	}
	defer old.Close()
	// Take the SQLite write lock only after obtaining the OAuth file lock.
	dest, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer dest.Rollback()
	if _, err = dest.ExecContext(ctx, "DELETE FROM auth_connections"); err != nil {
		return err
	}
	now := time.Now()
	err = old.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("amsl-mcpoauth-grants-v1"))
		if bucket == nil {
			return errors.New("unrecognized OAuth grant database")
		}
		return bucket.ForEach(func(k, v []byte) error {
			var g mcpoauth.GrantRecord
			if err := json.Unmarshal(v, &g); err != nil {
				return err
			}
			if !bytes.Equal(k, []byte(g.ID)) || g.Subject == "" {
				return errors.New("invalid OAuth grant record")
			}
			if !g.RevokedAt.IsZero() || !now.Before(g.ExpiresAt) {
				return nil
			}
			_, err := dest.ExecContext(ctx, "INSERT INTO auth_connections(id,subject,expires) VALUES(?,?,?)", g.ID, g.Subject, g.ExpiresAt.Unix())
			return err
		})
	})
	if err != nil {
		return err
	}
	return dest.Commit()
}

func (s *connectionsStore) CreateGrant(ctx context.Context, issue mcpoauth.GrantIssue) error {
	g := issue.Grant
	if err := s.checkOwner(ctx, g.Subject); err != nil {
		if errors.Is(err, mcpoauth.ErrNotFound) {
			return mcpoauth.ErrDenied
		}
		return err
	}
	// Write the index first. A crash can leave an unused index entry, but
	// cannot issue a credential that its owner cannot find and disconnect.
	_, err := s.db.ExecContext(ctx, "INSERT INTO auth_connections(id,subject,expires) VALUES(?,?,?)", g.ID, g.Subject, g.ExpiresAt.Unix())
	if err != nil {
		return err
	}
	return s.Store.CreateGrant(ctx, issue)
}

func (s *connectionsStore) Grant(ctx context.Context, id string) (mcpoauth.GrantRecord, error) {
	g, err := s.Store.Grant(ctx, id)
	if err != nil {
		return g, err
	}
	return g, s.checkOwner(ctx, g.Subject)
}

func (s *connectionsStore) checkOwner(ctx context.Context, qualified string) error {
	credential, current := strings.CutPrefix(qualified, s.prefix)
	if !current {
		return nil // Old domain policies are rejected by the resource server.
	}
	subject, _, _ := strings.Cut(credential, "/")
	expected, err := accountCredential(ctx, s.db, subject)
	if errors.Is(err, errOffboarded) || (err == nil && expected != credential) {
		return mcpoauth.ErrNotFound
	}
	return err
}

type Connection struct {
	ID, Client string
	Created    time.Time
}

func (s *Service) Connections(ctx context.Context, subject string) ([]Connection, error) {
	now := time.Now()
	credential, err := accountCredential(ctx, s.db, subject)
	if err != nil {
		return nil, err
	}
	owner := s.credentialPrefix + credential
	rows, err := s.db.QueryContext(ctx, "SELECT id FROM auth_connections WHERE subject=? AND expires>=?", owner, now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var connections []Connection
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		g, err := s.store.Grant(ctx, id)
		if errors.Is(err, mcpoauth.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if g.Subject == owner && g.Resource == s.resource && g.RevokedAt.IsZero() && now.Before(g.ExpiresAt) {
			connections = append(connections, Connection{g.ID, g.Binding, g.CreatedAt.UTC()})
		}
	}
	slices.SortFunc(connections, func(a, b Connection) int {
		if cmp := b.Created.Compare(a.Created); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.ID, b.ID)
	})
	return connections, rows.Err()
}

func (s *Service) Disconnect(ctx context.Context, subject, id string) error {
	g, err := s.store.Grant(ctx, id)
	if errors.Is(err, mcpoauth.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	owner, err := accountCredential(ctx, s.db, subject)
	if err != nil {
		return err
	}
	if g.Subject != s.credentialPrefix+owner || g.Resource != s.resource {
		return nil
	}
	return s.store.RevokeGrant(ctx, id, time.Now())
}
