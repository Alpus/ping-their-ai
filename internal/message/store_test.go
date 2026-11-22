package message

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

type fixture struct {
	t *testing.T
	*Store
	ctx context.Context
}

func openFixture(t *testing.T, path string) fixture {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA foreign_keys=ON;
		CREATE TABLE IF NOT EXISTS test_outbox(recipient TEXT, id TEXT UNIQUE, sender_handle TEXT)`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	s, err := New(ctx, db, func(ctx context.Context, tx *sql.Tx, recipient, id, sender string) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO test_outbox VALUES(?,?,?)", recipient, id, sender)
		return err
	}, func(context.Context, *sql.Tx, string, string, string, string) error { return nil },
		func(context.Context, *sql.Tx, string, string, bool) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return fixture{t, s, ctx}
}

func (f fixture) ok(v map[string]any, err error) map[string]any {
	f.t.Helper()
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}

func expect(t *testing.T, v map[string]any, want string) {
	t.Helper()
	if v["status"] != want {
		t.Fatalf("status: got %v, want %s", v, want)
	}
}

func (f fixture) activate() {
	f.t.Helper()
	for _, handle := range []string{"alice", "bob", "eve"} {
		expect(f.t, f.ok(f.Register(f.ctx, handle+"-subject", handle)), "ready")
	}
}

func TestExampleHandleCannotRegisterOrReceive(t *testing.T) {
	f := openFixture(t, filepath.Join(t.TempDir(), "store.db"))
	f.activate()
	expect(t, f.ok(f.Register(f.ctx, "new-user", " @HaNdLe ")), "handle_unavailable")
	// A database from an older release can already contain the example address.
	if _, err := f.db.Exec("INSERT INTO mail_accounts(subject,handle) VALUES('existing-user','handle')"); err != nil {
		t.Fatal(err)
	}
	expect(t, f.ok(f.Register(f.ctx, "existing-user", "handle")), "ready")
	expect(t, f.ok(f.Send(f.ctx, "alice-subject", "@HANDLE", "draft is ready", "example")), "reserved_handle")
	var count int
	if err := f.db.QueryRow("SELECT count(*) FROM mail_messages").Scan(&count); err != nil || count != 0 {
		t.Fatal(count, err)
	}
	expect(t, f.ok(f.Register(f.ctx, "new-user", "@handle2")), "ready")
}

func TestActivationContactsAndDurableIdempotentSend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	f := openFixture(t, path)
	ctx := f.ctx
	const a, b = "alice-subject", "bob-subject"

	expect(t, f.ok(f.Contacts(ctx, a)), "registration_required")
	expect(t, f.ok(f.SaveContact(ctx, a, "@bob", "private")), "registration_required")
	expect(t, f.ok(f.Read(ctx, a, "grant", "client", "unused", "")), "registration_required")
	expect(t, f.ok(f.Messages(ctx, a, Filter{})), "registration_required")
	expect(t, f.ok(f.Send(ctx, a, "@bob", "hello", "key")), "registration_required")

	f.activate()
	if got := f.ok(f.Register(ctx, a, "@ALICE"))["handle"]; got != "@alice" {
		t.Fatal(got)
	}
	expect(t, f.ok(f.Register(ctx, "fourth", "alice")), "handle_unavailable")
	expect(t, f.ok(f.Send(ctx, a, "@missing", "hello", "key")), "unknown_handle")
	expect(t, f.ok(f.SaveContact(ctx, a, "@missing", "private")), "unknown_handle")
	sent := f.ok(f.Send(ctx, a, "@BOB", "hello", "key"))
	expect(t, sent, "sent")
	if got := f.ok(f.Send(ctx, a, "bob", "hello", "key")); !reflect.DeepEqual(got, sent) {
		t.Fatalf("receipt changed: %v", got)
	}
	expect(t, f.ok(f.Send(ctx, a, "@bob", "changed", "key")), "request_conflict")
	expect(t, f.ok(f.Send(ctx, a, "eve", "hello", "key")), "request_conflict")
	expect(t, f.ok(f.Send(ctx, a, "missing", "hello", "key")), "request_conflict")
	var n int
	var recipient, id, handle string
	if err := f.db.QueryRow(`SELECT COUNT(*),recipient,id,sender_handle FROM test_outbox`).Scan(&n, &recipient, &id, &handle); err != nil || n != 1 || recipient != b || handle != "@alice" || id != sent["message_id"] {
		t.Fatal(n, recipient, id, handle, err)
	}

	expect(t, f.ok(f.SaveContact(ctx, a, "@bob", "first")), "saved")
	expect(t, f.ok(f.SaveContact(ctx, a, "Bob", "private")), "saved")
	if got := f.ok(f.Contacts(ctx, a))["contacts"].([]map[string]any); len(got) != 1 || got[0]["note"] != "private" {
		t.Fatal(got)
	}
	if got := f.ok(f.Contacts(ctx, b))["contacts"].([]map[string]any); len(got) != 0 {
		t.Fatal(got)
	}
	f.enqueue = func(context.Context, *sql.Tx, string, string, string) error { return errors.New("outbox unavailable") }
	if receipt, err := f.Send(ctx, a, "bob", "lost", "retry"); err == nil || receipt != nil {
		t.Fatal(receipt, err)
	}
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM mail_messages`).Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	f = openFixture(t, path)
	if got := f.ok(f.Send(f.ctx, a, "bob", "hello", "key")); !reflect.DeepEqual(got, sent) {
		t.Fatal(got)
	}
	expect(t, f.ok(f.Send(f.ctx, a, "bob", "lost", "retry")), "sent")
}

func TestReadOnceIsHumanOwnedGrantBoundAndAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	f := openFixture(t, path)
	f.activate()
	ctx := f.ctx
	const a, b, e = "alice-subject", "bob-subject", "eve-subject"
	id := f.ok(f.Send(ctx, a, "bob", "секрет", "1"))["message_id"].(string)
	expect(t, f.ok(f.Read(ctx, e, "g3", "eve client", id, "")), "not_found")
	out := f.ok(f.Read(ctx, a, "g-a", "sender client", id, ""))
	if out["body"] != "секрет" || out["read_at"] != nil {
		t.Fatal(out)
	}
	lock := f.ok(f.Read(ctx, b, "g1", "client one", id, ""))
	expect(t, lock, "approval_required")
	key := lock["approval_key"].(string)
	if lock["body"] != nil {
		t.Fatal(lock)
	}
	if key != f.ok(f.Read(ctx, b, "g1", "client one", id, key))["approval_key"] {
		t.Fatal("repeated read changed pending link")
	}
	if preview := f.ok(f.Approval(ctx, b, key)); preview["client"] != "client one" || preview["sender"] != "@alice" || preview["recipient"] != "@bob" || preview["body"] != "секрет" {
		t.Fatal(preview)
	}
	expect(t, f.ok(f.Approval(ctx, a, key)), "unavailable")
	expect(t, f.ok(f.Decide(ctx, e, key, "always")), "unavailable")
	other := f.ok(f.Read(ctx, b, "g2", "client two", id, ""))
	expect(t, other, "approval_required")
	if other["approval_key"] == key {
		t.Fatal("grant collision")
	}
	expect(t, f.ok(f.Decide(ctx, b, key, "once")), "approved_once")
	expect(t, f.ok(f.Decide(ctx, b, key, "always")), "unavailable")
	expect(t, f.ok(f.Read(ctx, b, "g2", "client two", id, "")), "approval_required")
	var wg sync.WaitGroup
	type response struct {
		v   map[string]any
		err error
	}
	ch := make(chan response, 2)
	for i := 0; i < 2; i++ {
		wg.Go(func() { v, err := f.Read(ctx, b, "g1", "client one", id, key); ch <- response{v, err} })
	}
	wg.Wait()
	close(ch)
	var read, blocked int
	var readAt any
	for r := range ch {
		if r.err != nil {
			t.Fatal(r.err)
		}
		switch r.v["status"] {
		case "read":
			read++
			readAt = r.v["read_at"]
			if r.v["body"] != "секрет" || readAt == nil {
				t.Fatal(r.v)
			}
		case "request_unavailable":
			blocked++
			if r.v["body"] != nil {
				t.Fatal(r.v)
			}
		default:
			t.Fatal(r.v)
		}
	}
	if read != 1 || blocked != 1 {
		t.Fatal(read, blocked)
	}
	expect(t, f.ok(f.Decide(ctx, b, other["approval_key"].(string), "later")), "later")
	expect(t, f.ok(f.Approval(ctx, b, other["approval_key"].(string))), "unavailable")
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	f = openFixture(t, path)
	history := f.ok(f.Messages(f.ctx, a, Filter{}))["messages"].([]map[string]any)
	if len(history) != 1 || history[0]["read_at"] != readAt || history[0]["body"] != nil {
		t.Fatal(history)
	}
	if got := f.ok(f.Messages(f.ctx, b, Filter{Query: "секрет"}))["messages"].([]map[string]any); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestTrustedSearchPaginationAndRevocation(t *testing.T) {
	f := openFixture(t, filepath.Join(t.TempDir(), "store.db"))
	f.activate()
	ctx := f.ctx
	const a, b, e = "alice-subject", "bob-subject", "eve-subject"
	first := f.ok(f.Send(ctx, a, "bob", "Проверка макета", "1"))
	f.ok(f.Send(ctx, e, "bob", "МАКЕТ private", "1"))
	second := f.ok(f.Send(ctx, a, "bob", "МАКЕТ второй", "2"))
	own := f.ok(f.Send(ctx, b, "alice", "Наш макет", "1"))
	q := Filter{Query: "МаКеТ"}
	entries := func(out map[string]any) []map[string]any { return out["messages"].([]map[string]any) }
	if got := entries(f.ok(f.Messages(ctx, b, q))); len(got) != 1 || got[0]["message_id"] != own["message_id"] {
		t.Fatal(got)
	}
	key := f.ok(f.Read(ctx, b, "web", "browser", first["message_id"].(string), ""))["approval_key"].(string)
	oldKey := f.ok(f.Read(ctx, b, "phone", "phone", second["message_id"].(string), ""))["approval_key"].(string)
	expect(t, f.ok(f.Decide(ctx, b, key, "always")), "trusted")
	expect(t, f.ok(f.Decide(ctx, b, oldKey, "once")), "unavailable")
	trusts := f.ok(f.Trusts(ctx, b))["trusts"].([]map[string]any)
	if len(trusts) != 1 || trusts[0]["handle"] != "@alice" {
		t.Fatal(trusts)
	}
	q.Limit = 2
	page := f.ok(f.Messages(ctx, b, q))
	if rows := entries(page); len(rows) != 2 || rows[1]["message_id"] != second["message_id"] || rows[1]["read_at"] != nil || rows[1]["body"] != nil {
		t.Fatal(rows)
	}
	f.ok(f.Send(ctx, a, "bob", "новый макет", "3"))
	q.Cursor = page["next_cursor"].(int64)
	page = f.ok(f.Messages(ctx, b, q))
	if rows := entries(page); len(rows) != 1 || rows[0]["message_id"] != first["message_id"] || page["next_cursor"] != nil {
		t.Fatal(rows, page)
	}
	selected := Filter{Peer: "@ALICE", Direction: "incoming", After: first["sent_at"].(string), Before: second["sent_at"].(string)}
	if rows := entries(f.ok(f.Messages(ctx, b, selected))); len(rows) != 1 || rows[0]["message_id"] != first["message_id"] {
		t.Fatal(rows)
	}
	out := f.ok(f.Read(ctx, b, "phone", "phone", second["message_id"].(string), ""))
	if out["body"] != "МАКЕТ второй" {
		t.Fatal(out)
	}
	expect(t, f.ok(f.Revoke(ctx, b, "ALICE")), "revoked")
	if rows := entries(f.ok(f.Messages(ctx, b, Filter{Query: "макет", Direction: "incoming"}))); len(rows) != 0 {
		t.Fatal(rows)
	}
	expect(t, f.ok(f.Read(ctx, b, "phone", "phone", second["message_id"].(string), "")), "approval_required")
	expect(t, f.ok(f.Messages(ctx, b, Filter{Direction: "bad"})), "invalid_filter")
}

func TestAllowMessageAcrossConnectionsAndSenderRevocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "message-access.sqlite")
	f := openFixture(t, path)
	f.activate()
	const owner, sender, observer = "bob-subject", "alice-subject", "eve-subject"
	id := f.ok(f.Send(f.ctx, sender, "bob", "shared note", "1"))["message_id"].(string)
	otherID := f.ok(f.Send(f.ctx, sender, "bob", "another note", "2"))["message_id"].(string)
	request := func(id, grant string) string {
		return f.ok(f.Read(f.ctx, owner, grant, "client", id, ""))["approval_key"].(string)
	}
	key := request(id, "first")
	otherRequest := request(id, "second")
	expect(t, f.ok(f.Decide(f.ctx, observer, key, "allow_message")), "unavailable")
	expect(t, f.ok(f.Approval(f.ctx, owner, key)), "pending")

	f.readable = func(context.Context, *sql.Tx, string, string, string, string) error {
		return errors.New("wake failed")
	}
	if _, err := f.Decide(f.ctx, owner, key, "allow_message"); err == nil {
		t.Fatal("decision committed without its wake")
	}
	expect(t, f.ok(f.Read(f.ctx, owner, "second", "client", id, otherRequest)), "approval_required")
	wakes := map[string][]string{}
	f.readable = func(_ context.Context, _ *sql.Tx, recipient, grant, requestID, messageID string) error {
		if recipient != owner || messageID != id {
			t.Fatal(recipient, messageID)
		}
		wakes[grant] = append(wakes[grant], requestID)
		return nil
	}
	decision := f.ok(f.Decide(f.ctx, owner, key, "allow_message"))
	expect(t, decision, "message_allowed")
	if decision["message_id"] != id {
		t.Fatal(decision)
	}
	expect(t, f.ok(f.Decide(f.ctx, owner, key, "allow_message")), "unavailable")
	expect(t, f.ok(f.Decide(f.ctx, owner, otherRequest, "later")), "unavailable")
	if want := map[string][]string{"first": {key}, "second": {otherRequest}}; !reflect.DeepEqual(wakes, want) {
		t.Fatalf("wakes: got %v, want %v", wakes, want)
	}
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	f = openFixture(t, path)
	q := Filter{Query: "note", Direction: "incoming"}
	search := func(subject string) []map[string]any {
		return f.ok(f.Messages(f.ctx, subject, q))["messages"].([]map[string]any)
	}
	if rows := search(owner); len(rows) != 1 || rows[0]["message_id"] != id || rows[0]["read_at"] != nil || rows[0]["body"] != nil {
		t.Fatal(rows)
	}
	expect(t, f.ok(f.Read(f.ctx, observer, "observer", "client", id, "")), "not_found")
	if rows := search(observer); len(rows) != 0 {
		t.Fatal(rows)
	}
	var readers sync.WaitGroup
	var reads [2]map[string]any
	var readErrors [2]error
	for i, grant := range []string{"second", "third"} {
		readers.Go(func() { reads[i], readErrors[i] = f.Read(f.ctx, owner, grant, "client", id, "") })
	}
	readers.Wait()
	readAt := reads[0]["read_at"]
	for i, read := range reads {
		if readErrors[i] != nil || readAt == nil || read["body"] != "shared note" || read["read_at"] != readAt {
			t.Fatal(read, readErrors[i])
		}
	}
	neighbor := request(otherID, "first")
	expect(t, f.ok(f.Decide(f.ctx, owner, neighbor, "always")), "trusted")
	if rows := search(owner); len(rows) != 2 {
		t.Fatal(rows)
	}
	expect(t, f.ok(f.Revoke(f.ctx, owner, "alice")), "revoked")
	if rows := search(owner); len(rows) != 1 || rows[0]["message_id"] != id || rows[0]["read_at"] != readAt {
		t.Fatal(rows)
	}
	expect(t, f.ok(f.Read(f.ctx, owner, "second", "client", otherID, "")), "approval_required")
	for _, grant := range []string{"first", "third", "second"} {
		read := f.ok(f.Read(f.ctx, owner, grant, "client", id, ""))
		if read["body"] != "shared note" || read["read_at"] != readAt {
			t.Fatal(read)
		}
	}
}

func TestUpgradeKeepsLegacyReceiptsAndOneTimeAccessSeparateFromConsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite")
	f := openFixture(t, path)
	f.activate()
	const owner = "bob-subject"
	id := f.ok(f.Send(f.ctx, "alice-subject", "bob", "legacy", "1"))["message_id"].(string)
	request := func() string {
		return f.ok(f.Read(f.ctx, owner, "first", "client", id, ""))["approval_key"].(string)
	}
	readKey := request()
	expect(t, f.ok(f.Decide(f.ctx, owner, readKey, "once")), "approved_once")
	readAt := f.ok(f.Read(f.ctx, owner, "first", "client", id, readKey))["read_at"]
	onceKey := request()
	expect(t, f.ok(f.Decide(f.ctx, owner, onceKey, "once")), "approved_once")
	pendingKey := request()
	if _, err := f.db.Exec("ALTER TABLE mail_messages DROP COLUMN approved_ns"); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	f = openFixture(t, path)
	if rows := f.ok(f.Messages(f.ctx, owner, Filter{Query: "legacy"}))["messages"].([]map[string]any); len(rows) != 0 {
		t.Fatal(rows)
	}
	expect(t, f.ok(f.Read(f.ctx, owner, "second", "client", id, onceKey)), "request_unavailable")
	oldRead := f.ok(f.Read(f.ctx, owner, "first", "client", id, onceKey))
	if readAt == nil || oldRead["read_at"] != readAt || oldRead["body"] != "legacy" {
		t.Fatal(oldRead)
	}
	expect(t, f.ok(f.Read(f.ctx, owner, "first", "client", id, onceKey)), "request_unavailable")
	expect(t, f.ok(f.Decide(f.ctx, owner, pendingKey, "once")), "approved_once")
	expect(t, f.ok(f.Read(f.ctx, owner, "first", "client", id, pendingKey)), "read")
	expect(t, f.ok(f.Read(f.ctx, owner, "first", "client", id, "")), "approval_required")
}

func TestExpiredApprovalCanBeRequestedAgain(t *testing.T) {
	f := openFixture(t, filepath.Join(t.TempDir(), "store.db"))
	f.activate()
	ctx := f.ctx
	id := f.ok(f.Send(ctx, "alice-subject", "bob", strings.Repeat("x", 20), "1"))["message_id"].(string)
	req := func() string { return f.ok(f.Read(ctx, "bob-subject", "g", "app", id, ""))["approval_key"].(string) }
	expire := func(key string) {
		t.Helper()
		if _, err := f.db.Exec("UPDATE mail_approvals SET expires_ns=0 WHERE id=?", key); err != nil {
			t.Fatal(err)
		}
	}
	key := req()
	expire(key)
	expect(t, f.ok(f.Approval(ctx, "bob-subject", key)), "unavailable")
	expect(t, f.ok(f.Decide(ctx, "bob-subject", key, "always")), "unavailable")
	replacement := req()
	if replacement == key {
		t.Fatal("expired key reused")
	}
	expect(t, f.ok(f.Decide(ctx, "bob-subject", replacement, "once")), "approved_once")
	expire(replacement)
	if req() == replacement {
		t.Fatal("expired grant returned")
	}
}

func TestStoredTextByteLimitsAndLegacyRetry(t *testing.T) {
	f := openFixture(t, filepath.Join(t.TempDir(), "store.db"))
	f.activate()
	ctx := f.ctx
	const a = "alice-subject"
	body := strings.Repeat("м", maxMessageBytes/2)
	key := strings.Repeat("а", maxRequestIDBytes/2)
	note := strings.Repeat("я", maxNoteBytes/2)
	expect(t, f.ok(f.Send(ctx, a, "bob", body, key)), "sent")
	expect(t, f.ok(f.Send(ctx, a, "bob", body+"x", "too-large")), "message_too_large")
	expect(t, f.ok(f.Send(ctx, a, "bob", "valid", key+"x")), "request_id_too_long")
	expect(t, f.ok(f.SaveContact(ctx, a, "bob", note)), "saved")
	expect(t, f.ok(f.SaveContact(ctx, a, "bob", note+"x")), "note_too_large")
	contacts := f.ok(f.Contacts(ctx, a))["contacts"].([]map[string]any)
	if len(contacts) != 1 || contacts[0]["note"] != note {
		t.Fatal("oversized edit changed the saved contact")
	}
	var n int
	if err := f.db.QueryRow("SELECT COUNT(*) FROM mail_messages").Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	// A database created before these limits may already contain larger messages.
	const legacyID = "older-message"
	legacyKey, legacyBody := key+"long", body+"large"
	_, err := f.db.Exec(`INSERT INTO mail_messages(id,sender,recipient,request_id,body,body_folded,sent_ns)
		VALUES(?,?,'bob-subject',?,?,?,?)`, legacyID, a, legacyKey, legacyBody, legacyBody, time.Now().UnixNano())
	if err != nil {
		t.Fatal(err)
	}
	retry := f.ok(f.Send(ctx, a, "bob", legacyBody, legacyKey))
	expect(t, retry, "sent")
	if retry["message_id"] != legacyID {
		t.Fatal(retry)
	}
}

func TestBurstCountsOnlyNewMessagesForOneSender(t *testing.T) {
	f := openFixture(t, filepath.Join(t.TempDir(), "store.db"))
	f.activate()
	ctx := f.ctx
	const a = "alice-subject"
	first := f.ok(f.Send(ctx, a, "bob", "first", "first"))
	expect(t, first, "sent")
	for i := 1; i < sendsPerMinute-1; i++ {
		expect(t, f.ok(f.Send(ctx, a, "eve", "other", strconv.Itoa(i))), "sent")
	}
	type outcome struct {
		out map[string]any
		err error
	}
	ch := make(chan outcome, 2)
	start := make(chan struct{})
	for _, recipient := range []string{"bob", "eve"} {
		go func() {
			<-start
			out, err := f.Send(ctx, a, recipient, "final slot", "last-"+recipient)
			ch <- outcome{out, err}
		}()
	}
	close(start)
	counts := map[string]int{}
	for range 2 {
		v := <-ch
		if v.err != nil {
			t.Fatal(v.err)
		}
		counts[v.out["status"].(string)]++
	}
	if counts["sent"] != 1 || counts["rate_limited"] != 1 {
		t.Fatal(counts)
	}
	limited := f.ok(f.Send(ctx, a, "bob", "next", "next"))
	expect(t, limited, "rate_limited")
	if limited["retry_after_seconds"] != 60 {
		t.Fatal(limited)
	}
	if got := f.ok(f.Send(ctx, a, "bob", "first", "first")); !reflect.DeepEqual(first, got) {
		t.Fatal(got)
	}
	expect(t, f.ok(f.Send(ctx, a, "eve", "changed", "first")), "request_conflict")
	expect(t, f.ok(f.Send(ctx, a, "missing", "hi", "bad-to")), "unknown_handle")
	expect(t, f.ok(f.Send(ctx, "bob-subject", "alice", "reply", "other sender")), "sent")
	var n int
	if err := f.db.QueryRow("SELECT COUNT(*) FROM test_outbox WHERE sender_handle='@alice'").Scan(&n); err != nil || n != sendsPerMinute {
		t.Fatal(n, err)
	}
	if _, err := f.db.Exec("UPDATE mail_messages SET sent_ns=? WHERE sender=? AND request_id='first'", time.Now().Add(-2*time.Minute).UnixNano(), a); err != nil {
		t.Fatal(err)
	}
	expect(t, f.ok(f.Send(ctx, a, "bob", "next", "next")), "sent")
}

func TestWidgetChoiceIsScopedAndBrowserWakeIsAtomic(t *testing.T) {
	f := openFixture(t, filepath.Join(t.TempDir(), "widget.sqlite"))
	f.activate()
	const sender = "alice-subject"
	const owner = "bob-subject"
	const grant = "g1"
	id := f.ok(f.Send(f.ctx, sender, "bob", "one message", "req"))["message_id"].(string)
	getKey := func() string { return f.ok(f.Read(f.ctx, owner, grant, "ChatGPT", id, ""))["approval_key"].(string) }
	key := getKey()
	proof := f.WidgetProof(owner, grant, id, key)
	for _, a := range [][5]string{
		{sender, grant, id, key, proof}, {owner, "another-grant", id, key, proof}, {owner, grant, id + "x", key, proof}, {owner, grant, id, key + "x", proof}, {owner, grant, id, key, key},
	} {
		expect(t, f.ok(f.DecideWidget(f.ctx, a[0], a[1], a[2], a[3], a[4], "once")), "unavailable")
		expect(t, f.ok(f.PreviewWidget(f.ctx, a[0], a[1], a[2], a[3], a[4])), "unavailable")
	}
	if got := f.ok(f.PreviewWidget(f.ctx, owner, grant, id, key, proof)); got["message_id"] != id || got["body"] != "one message" {
		t.Fatal(got)
	}
	wakes := 0
	f.readable = func(ctx context.Context, tx *sql.Tx, who, connection, request, message string) error {
		if who != owner || connection != grant || request != key || message != id {
			t.Fatal("incorrect wake scope")
		}
		wakes++
		return nil
	}
	if got := f.ok(f.DecideWidget(f.ctx, owner, grant, id, key, proof, "once")); got["message_id"] != id || got["status"] != "approved_once" {
		t.Fatal(got)
	}
	expect(t, f.ok(f.DecideWidget(f.ctx, owner, grant, id, key, proof, "always")), "unavailable")
	expect(t, f.ok(f.Read(f.ctx, owner, grant, "ChatGPT", id, key)), "read")
	if wakes != 0 {
		t.Fatal("the widget has its own follow-up")
	}
	key = getKey()
	f.readable = func(context.Context, *sql.Tx, string, string, string, string) error { return errors.New("offline") }
	if _, err := f.Decide(f.ctx, owner, key, "always"); err == nil {
		t.Fatal("browser decision committed without resume record")
	}
	expect(t, f.ok(f.Approval(f.ctx, owner, key)), "pending")
}

func TestSeparateChatsOnOneGrant(t *testing.T) {
	f := openFixture(t, filepath.Join(t.TempDir(), "conversations.sqlite"))
	f.activate()
	const owner, grant = "bob-subject", "same-client-grant"
	id := f.ok(f.Send(f.ctx, "alice-subject", "bob", "one chat only", "example"))["message_id"].(string)
	open := func(req string) map[string]any { return f.ok(f.Read(f.ctx, owner, grant, "client", id, req)) }
	first := open("")["approval_key"].(string)
	second := open("")["approval_key"].(string)
	if first == second {
		t.Fatal("different conversations shared a request")
	}
	f.ok(f.Decide(f.ctx, owner, first, "once"))
	expect(t, open(second), "approval_required")
	expect(t, open(""), "approval_required")
	if out := open(first); out["body"] != "one chat only" {
		t.Fatal(out)
	}
	expect(t, open(first), "request_unavailable")
	if out := open(second); out["approval_key"] != second {
		t.Fatal(out)
	}
}

func TestUpgradeRetainsPendingReadRequest(t *testing.T) {
	f := openFixture(t, filepath.Join(t.TempDir(), "upgrade.sqlite"))
	f.activate()
	id := f.ok(f.Send(f.ctx, "alice-subject", "bob", "retained", "upgrade"))["message_id"].(string)
	const old = "prior-approval"
	_, err := f.db.Exec(`DROP TABLE mail_approvals;
	CREATE TABLE mail_approvals (id TEXT PRIMARY KEY NOT NULL, message TEXT NOT NULL REFERENCES mail_messages(id),
	 grant_id TEXT NOT NULL,client TEXT NOT NULL,state TEXT NOT NULL,expires_ns INTEGER NOT NULL, UNIQUE(message,grant_id));
	INSERT INTO mail_approvals(id,message,grant_id,client,state,expires_ns) VALUES (?,?,?,'client','pending',?)`, old, id, "grant", time.Now().Add(time.Minute).UnixNano())
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareApprovals(f.ctx, f.db); err != nil {
		t.Fatal(err)
	}
	expect(t, f.ok(f.Approval(f.ctx, "bob-subject", old)), "pending")
	f.ok(f.Decide(f.ctx, "bob-subject", old, "once"))
	expect(t, f.ok(f.Read(f.ctx, "bob-subject", "grant", "client", id, old)), "read")
}

func TestStableMessagePagePreviewsAndDecidesForRecipient(t *testing.T) {
	f := openFixture(t, filepath.Join(t.TempDir(), "store.db"))
	f.activate()
	const sender, owner, other = "alice-subject", "bob-subject", "eve-subject"
	const body = "browser-only preview"
	id := f.ok(f.Send(f.ctx, sender, "bob", body, "stable-link"))["message_id"].(string)

	for _, wrong := range []string{"", sender, other} {
		preview := f.ok(f.PreviewMessage(f.ctx, wrong, id))
		expect(t, preview, "unavailable")
		if preview["body"] != nil {
			t.Fatal("preview exposed content to another account")
		}
		expect(t, f.ok(f.DecideMessage(f.ctx, wrong, id, "always", "")), "unavailable")
	}
	view := f.ok(f.PreviewMessage(f.ctx, owner, id))
	expect(t, view, "pending")
	if view["body"] != body || view["sender"] != "@alice" {
		t.Fatal("preview missing text or sender")
	}
	expect(t, f.ok(f.DecideMessage(f.ctx, owner, id, "later", "")), "later")
	expect(t, f.ok(f.DecideMessage(f.ctx, owner, id, "once", "")), "invalid_decision")
	var clean bool
	if err := f.db.QueryRow(`SELECT read_ns IS NULL AND approved_ns IS NULL AND
		NOT EXISTS(SELECT 1 FROM mail_approvals) AND NOT EXISTS(SELECT 1 FROM mail_trust)
		FROM mail_messages WHERE id=?`, id).Scan(&clean); err != nil || !clean {
		t.Fatal("preview or dismissal changed access or recorded a read", err)
	}

	legacy := f.ok(f.Read(f.ctx, owner, "legacy", "old chat", id, ""))["approval_key"].(string)
	expect(t, f.ok(f.Decide(f.ctx, owner, legacy, "once")), "approved_once")
	expect(t, f.ok(f.PreviewMessage(f.ctx, owner, id)), "pending")
	var exists bool
	if err := f.db.QueryRow("SELECT EXISTS(SELECT 1 FROM mail_approvals WHERE id=? AND state='once')", legacy).Scan(&exists); err != nil || !exists {
		t.Fatal("browser preview consumed a legacy approval", err)
	}

	request := f.ok(f.Read(f.ctx, owner, "dot", "Dot", id, ""))["approval_key"]
	wakes := 0
	f.readable = func(_ context.Context, _ *sql.Tx, recipient, grant, key, messageID string) error {
		if recipient != owner || grant != "dot" || key != request || messageID != id {
			t.Fatal("wrong waiting chat")
		}
		wakes++
		return nil
	}
	for range 2 {
		expect(t, f.ok(f.DecideMessage(f.ctx, owner, id, "allow_message", "")), "message_allowed")
		expect(t, f.ok(f.PreviewMessage(f.ctx, owner, id)), "readable")
	}
	if wakes != 1 {
		t.Fatal("expected one continuation, got", wakes)
	}
	if err := f.db.QueryRow("SELECT read_ns IS NULL FROM mail_messages WHERE id=?", id).Scan(&clean); err != nil || !clean {
		t.Fatal("preview or approval marked as read", err)
	}
	expect(t, f.ok(f.Read(f.ctx, owner, "another", "AI", id, "")), "read")
	id2 := f.ok(f.Send(f.ctx, sender, "bob", "second message", "second"))["message_id"].(string)
	expect(t, f.ok(f.PreviewMessage(f.ctx, owner, id2)), "pending")
	expect(t, f.ok(f.DecideMessage(f.ctx, owner, id2, "always", "")), "trusted")
	expect(t, f.ok(f.PreviewMessage(f.ctx, owner, id2)), "readable")
	expect(t, f.ok(f.Revoke(f.ctx, owner, "alice")), "revoked")
	expect(t, f.ok(f.PreviewMessage(f.ctx, owner, id2)), "pending")
}

func TestStaleBrowserDecisionsPreserveLaterRevocations(t *testing.T) {
	f := openFixture(t, filepath.Join(t.TempDir(), "store.db"))
	f.activate()
	const owner = "bob-subject"
	id := f.ok(f.Send(f.ctx, "alice-subject", "bob", "older tab", "first"))["message_id"].(string)
	another := f.ok(f.Send(f.ctx, "alice-subject", "bob", "another tab", "second"))["message_id"].(string)
	unrelated := f.ok(f.Send(f.ctx, "eve-subject", "bob", "other sender", "third"))["message_id"].(string)
	revision := func(messageID string) string {
		t.Helper()
		return f.ok(f.PreviewMessage(f.ctx, owner, messageID))["revision"].(string)
	}
	old := revision(id)
	expect(t, f.ok(f.DecideMessage(f.ctx, owner, id, "allow_message", old)), "message_allowed")
	expect(t, f.ok(f.DecideMessage(f.ctx, owner, id, "always", old)), "only_message_allowed")
	expect(t, f.ok(f.PreviewMessage(f.ctx, owner, another)), "pending")

	expect(t, f.ok(f.DecideMessage(f.ctx, owner, another, "always", old)), "trusted")
	expect(t, f.ok(f.Revoke(f.ctx, owner, "alice")), "revoked")
	for _, decision := range []string{"allow_message", "always"} {
		expect(t, f.ok(f.DecideMessage(f.ctx, owner, another, decision, old)), "permissions_changed")
	}
	expect(t, f.ok(f.PreviewMessage(f.ctx, owner, another)), "pending")
	if revision(unrelated) != old {
		t.Fatal("revocation invalidated an unrelated sender's form")
	}
	newRevision := revision(another)
	if newRevision == old {
		t.Fatal("fresh form kept the revoked revision")
	}
	expect(t, f.ok(f.DecideMessage(f.ctx, owner, another, "always", newRevision)), "trusted")
	expect(t, f.ok(f.Revoke(f.ctx, owner, "alice")), "revoked")
	expect(t, f.ok(f.DecideMessage(f.ctx, owner, another, "always", newRevision)), "permissions_changed")
}
