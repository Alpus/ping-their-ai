package main

import (
	"context"
	"database/sql"
	"testing"

	"github.com/Alpus/ping-their-ai/internal/message"
)

func TestFindMessageLinkWithoutReadingText(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx := t.Context()
	inbox, err := message.New(ctx, db,
		func(context.Context, *sql.Tx, string, string, string) error { return nil },
		func(context.Context, *sql.Tx, string, string, string, string) error { return nil },
		func(context.Context, *sql.Tx, string, string, bool) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, handle := range []string{"alice", "bob", "eve"} {
		if out, err := inbox.Register(ctx, handle, handle); err != nil || out["status"] != "ready" {
			t.Fatal(out, err)
		}
	}
	const body = "private message content"
	sent, err := inbox.Send(ctx, "alice", "bob", body, "first")
	if err != nil {
		t.Fatal(err)
	}
	id := sent["message_id"].(string)
	if _, err := inbox.Send(ctx, "alice", "bob", "more recent message", "second"); err != nil {
		t.Fatal(err)
	}
	const base = "https://example.test/team/ping"
	lookup := func(owner string) []map[string]any {
		t.Helper()
		out, err := findMessages(ctx, inbox, owner, base, historyArgs{ID: id})
		if err != nil || out["status"] != "ready" {
			t.Fatal(out, err)
		}
		return out["messages"].([]map[string]any)
	}
	link := base + "/messages/" + id
	checkRecipient := func(readAt any) {
		t.Helper()
		rows := lookup("bob")
		if len(rows) != 1 || rows[0]["message_id"] != id || rows[0]["message_url"] != link ||
			rows[0]["read_at"] != readAt || rows[0]["body"] != nil {
			t.Fatalf("wrong recipient link or metadata: %v", rows)
		}
	}
	checkRecipient(nil)
	if out, err := inbox.DecideMessage(ctx, "bob", id, "allow_message", ""); err != nil || out["status"] != "message_allowed" {
		t.Fatal(out, err)
	}
	checkRecipient(nil)
	read, err := inbox.Read(ctx, "bob", "test-grant", "chat", id, "")
	if err != nil || read["body"] != body || read["read_at"] == nil {
		t.Fatal(read, err)
	}
	checkRecipient(read["read_at"])
	if rows := lookup("alice"); len(rows) != 1 || rows[0]["message_url"] != nil || rows[0]["body"] != nil {
		t.Fatal("unexpected outgoing link or body", rows)
	}
	if rows := lookup("eve"); len(rows) != 0 {
		t.Fatal("another inbox can look up the message", rows)
	}
}
