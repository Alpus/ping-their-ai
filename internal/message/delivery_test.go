package message

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func TestDeliveryRequiresCurrentInboxWidePermission(t *testing.T) {
	f := openFixture(t, filepath.Join(t.TempDir(), "messages.db"))
	f.activate()
	const recipient, sender, stranger = "bob-subject", "alice-subject", "eve-subject"
	const body = "approved for delivery"
	id := f.ok(f.Send(f.ctx, sender, "bob", body, "delivery"))["message_id"].(string)
	assertWithheld := func() {
		t.Helper()
		got, err := f.DeliveryBody(f.ctx, recipient, id)
		if err != nil || got != nil {
			t.Fatalf("withheld body = %v, err = %v", got, err)
		}
	}

	key := f.ok(f.Read(f.ctx, recipient, "legacy", "old client", id, ""))["approval_key"].(string)
	expect(t, f.ok(f.Decide(f.ctx, recipient, key, "once")), "approved_once")
	assertWithheld()
	expect(t, f.ok(f.Read(f.ctx, recipient, "legacy", "old client", id, key)), "read")
	assertWithheld()
	expect(t, f.ok(f.DecideMessage(f.ctx, recipient, id, "always", "")), "trusted")
	if got, err := f.DeliveryBody(f.ctx, recipient, id); err != nil || got == nil || *got != body {
		t.Fatal("trusted sender's body unavailable", err)
	}
	for _, other := range []string{stranger, sender} {
		if got, err := f.DeliveryBody(f.ctx, other, id); !errors.Is(err, sql.ErrNoRows) || got != nil {
			t.Fatal("delivery lookup exposed another inbox's message", got, err)
		}
	}
	expect(t, f.ok(f.Revoke(f.ctx, recipient, "alice")), "revoked")
	assertWithheld()
}

func TestDeliveryReceiptFollowsItsTransaction(t *testing.T) {
	f := openFixture(t, filepath.Join(t.TempDir(), "messages.db"))
	f.activate()
	const recipient = "bob-subject"
	id := f.ok(f.Send(f.ctx, "alice-subject", "bob", "acknowledge me", "ack"))["message_id"].(string)
	expect(t, f.ok(f.DecideMessage(f.ctx, recipient, id, "allow_message", "")), "message_allowed")

	ack := func(owner string, commit bool) {
		t.Helper()
		tx, err := f.db.BeginTx(f.ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err := f.AcknowledgeDelivery(f.ctx, tx, owner, id); err != nil {
			t.Fatal(err)
		}
		if commit {
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}
	}
	receipt := func() any {
		t.Helper()
		rows := f.ok(f.Messages(f.ctx, "alice-subject", Filter{ID: id}))["messages"].([]map[string]any)
		return rows[0]["read_at"]
	}
	ack("eve-subject", true)
	ack(recipient, false)
	if got := receipt(); got != nil {
		t.Fatal("wrong inbox or rolled-back acknowledgement recorded a read", got)
	}
	ack(recipient, true)
	first := receipt()
	ack(recipient, true)
	if first == nil || receipt() != first {
		t.Fatal("retry changed the first successful read receipt", first)
	}
}
