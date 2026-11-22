package main

import (
	"database/sql"
	"errors"
	"testing"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

func TestServerAndOperatorReserveWriteAccessBeforeReading(t *testing.T) {
	dir := t.TempDir()
	open := func(mode string) *sql.DB {
		t.Helper()
		db, err := openMailDB(dir, mode)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		// Report contention immediately so this check needs no sleep or goroutines.
		if _, err := db.Exec("PRAGMA busy_timeout=0"); err != nil {
			t.Fatal(err)
		}
		return db
	}
	server := open("rwc")
	if _, err := server.Exec("CREATE TABLE ledger(value INTEGER)"); err != nil {
		t.Fatal(err)
	}
	operator := open("rw")
	for _, pair := range [][2]*sql.DB{{server, operator}, {operator, server}} {
		tx, err := pair[0].Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		var n int
		if err := tx.QueryRow("SELECT COUNT(*) FROM ledger").Scan(&n); err != nil {
			t.Fatal(err)
		}
		_, err = pair[1].Exec("INSERT INTO ledger VALUES(1)")
		var contention *sqlite.Error
		if !errors.As(err, &contention) || contention.Code() != sqlite3.SQLITE_BUSY {
			t.Fatalf("another process could write after the transaction's initial read: %v", err)
		}
		if _, err = tx.Exec("INSERT INTO ledger VALUES(2)"); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if _, err = pair[1].Exec("INSERT INTO ledger VALUES(3)"); err != nil {
			t.Fatal(err)
		}
	}
}
