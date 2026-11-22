package notify

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
)

func receivedFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	for _, handle := range []string{"alice", "bob", "eve"} {
		if _, err := f.inbox.Register(t.Context(), handle, handle); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f *fixture) subscribeReceived(path string) map[string]any {
	f.t.Helper()
	p := subArgs(testKey('k'))
	p["name"] = receivedEvent
	p["delivery"].(map[string]string)["url"] = callback + path
	r := f.call("events/subscribe", "2025-11-25", "alice", "g1", p)
	if r.Error != nil {
		f.t.Fatalf("subscribe: %+v", r.Error)
	}
	return p
}

func (f *fixture) sendSample(sender, key string) string {
	f.t.Helper()
	r, err := f.inbox.Send(f.t.Context(), sender, "alice", "body "+key, key)
	if err != nil || r["status"] != "sent" {
		f.t.Fatal(r, err)
	}
	return r["message_id"].(string)
}

func (f *fixture) choose(id, decision string) {
	f.t.Helper()
	ctx := f.t.Context()
	r, err := f.inbox.Read(ctx, "alice", "g1", "client", id, "")
	if err != nil || r["status"] != "approval_required" {
		f.t.Fatal(r, err)
	}
	if out, err := f.inbox.Decide(ctx, "alice", r["approval_key"].(string), decision); err != nil || out["message_id"] != id {
		f.t.Fatal(out, err)
	}
}

func (f *fixture) assertRead(id string, want bool) {
	f.t.Helper()
	var read bool
	if err := f.db.QueryRow("SELECT read_ns IS NOT NULL FROM mail_messages WHERE id=?", id).Scan(&read); err != nil || read != want {
		f.t.Fatalf("read = %t, want %t, err %v", read, want, err)
	}
}

type incomingEvent struct {
	ID   string         `json:"eventId"`
	Name string         `json:"name"`
	Data map[string]any `json:"data"`
}

func (f *fixture) deliveryEvent(worker *Service) incomingEvent {
	f.t.Helper()
	before := len(f.hooks)
	f.next(worker, true)
	if len(f.hooks) != before+1 {
		f.t.Fatal("no single HTTP delivery")
	}
	last := f.hooks[before]
	var e incomingEvent
	if err := json.Unmarshal(last.body, &e); err != nil {
		f.t.Fatal(err)
	}
	if e.ID != last.header.Get("webhook-id") || e.Name != receivedEvent {
		f.t.Fatal(e)
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(received.PayloadSchema, &schema); err != nil {
		f.t.Fatal(err)
	}
	valid, err := schema.Resolve(nil)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := valid.Validate(e.Data); err != nil {
		f.t.Fatal(e, err)
	}
	id := e.Data["message_id"].(string)
	if e.Data["message_url"] != f.s.delivery.MessageURL(id) {
		f.t.Fatal("wrong message link")
	}
	var ns int64
	if err := f.db.QueryRow("SELECT sent_ns FROM mail_messages WHERE id=?", id).Scan(&ns); err != nil || e.Data["sent_at"] != time.Unix(0, ns).UTC().Format(time.RFC3339Nano) {
		f.t.Fatal("wrong send time", e, err)
	}
	return e
}

func TestReceivedApprovalDuringDeliveryAndRetry(t *testing.T) {
	f := receivedFixture(t)
	id := f.sendSample("bob", "before")
	f.subscribeReceived("/one")
	// Approve the message while its initial notification is in flight. A stale
	// acknowledgement must leave the newly queued body ready after restart.
	inner := f.s.client.Transport
	f.s.client.Transport = roundTrip(func(req *http.Request) (*http.Response, error) {
		f.choose(id, "allow_message")
		return inner.RoundTrip(req)
	})
	notice := f.deliveryEvent(f.s)
	f.s.client.Transport = inner
	if notice.Data["status"] != "approval_required" || notice.Data["sender_handle"] != "@bob" || notice.Data["body"] != nil {
		t.Fatal(notice)
	}
	f.assertRead(id, false)
	resumed := f.service()
	f.status = 503
	failed := f.deliveryEvent(resumed)
	if failed.ID == notice.ID || failed.Data["status"] != "readable" || failed.Data["body"] != "body before" {
		t.Fatal(failed)
	}
	f.assertRead(id, false)
	f.status = 202
	f.now = f.now.Add(6 * time.Second)
	accepted := f.deliveryEvent(resumed)
	if accepted.ID != failed.ID {
		t.Fatal("retry changed the body event ID")
	}
	f.assertRead(id, true)
	f.next(resumed, false)
	f.subscribeReceived("/new")
	f.next(resumed, false)
}

func TestReceivedAlwaysAllowCoversOnlyCurrentWaiters(t *testing.T) {
	f := receivedFixture(t)
	f.subscribeReceived("/one")
	f.subscribeReceived("/two")
	first := f.sendSample("bob", "one")
	second := f.sendSample("bob", "two")
	other := f.sendSample("eve", "other")
	for range 6 {
		e := f.deliveryEvent(f.s)
		if e.Data["status"] != "approval_required" {
			t.Fatal(e)
		}
	}
	f.choose(first, "later")
	f.next(f.s, false)
	f.choose(first, "once")
	f.next(f.s, false)
	f.choose(first, "always")
	counts := map[string]int{}
	deliveries := map[string]bool{}
	for range 4 {
		e := f.deliveryEvent(f.s)
		if e.Data["status"] != "readable" || e.Data["sender_handle"] != "@bob" {
			t.Fatal(e)
		}
		if deliveries[e.ID] {
			t.Fatal("different subscribed chats received the same event ID", e.ID)
		}
		deliveries[e.ID] = true
		counts[e.Data["message_id"].(string)]++
	}
	if counts[first] != 2 || counts[second] != 2 {
		t.Fatal(counts)
	}
	f.next(f.s, false)
	f.assertRead(other, false)
	trusted := f.sendSample("bob", "trusted")
	for range 2 {
		e := f.deliveryEvent(f.s)
		if e.Data["message_id"] != trusted || e.Data["body"] != "body trusted" {
			t.Fatal(e)
		}
	}
	f.next(f.s, false)
}

func TestReceivedRechecksTrustOnRetryAndUnsubscribe(t *testing.T) {
	f := receivedFixture(t)
	sub := f.subscribeReceived("/one")
	trusted := f.sendSample("bob", "trust")
	f.choose(trusted, "always")
	f.deliveryEvent(f.s)
	id := f.sendSample("bob", "retry")
	f.status = 503
	if f.deliveryEvent(f.s).Data["body"] != "body retry" {
		t.Fatal("expected authorized body")
	}
	f.assertRead(id, false)
	if r, err := f.inbox.Revoke(t.Context(), "alice", "bob"); err != nil || r["status"] != "revoked" {
		t.Fatal(r, err)
	}
	f.now = f.now.Add(6 * time.Second)
	f.status = 200
	if e := f.deliveryEvent(f.s); e.Data["body"] != nil || e.Data["status"] != "approval_required" {
		t.Fatal("revoked text delivered", e)
	}
	f.assertRead(id, false)
	if r := f.call("events/unsubscribe", "2025-11-25", "alice", "g1", sub); r.Error != nil {
		t.Fatal(r.Error)
	}
	f.choose(id, "allow_message")
	f.next(f.s, false)
	f.assertRead(id, false)
}

func TestReceivedReviewActionNeedsOptInForPendingMessages(t *testing.T) {
	f := receivedFixture(t)
	sub := f.subscribeReceived("/one")
	first := f.sendSample("bob", "before-format-change")
	if e := f.deliveryEvent(f.s); e.Data["review_action"] != nil {
		t.Fatal("cached schema received a new field", e)
	}
	sub["arguments"] = map[string]any{"include_review_action": true}
	if r := f.call("events/subscribe", "2025-11-25", "alice", "g1", sub); r.Error != nil {
		t.Fatal(r.Error)
	}
	f.next(f.s, false)
	second := f.sendSample("bob", "formatted")
	e := f.deliveryEvent(f.s)
	if e.Data["review_action"] != "[Review message from @bob](<"+f.s.delivery.MessageURL(second)+">)" || e.Data["body"] != nil {
		t.Fatal(e)
	}
	f.choose(second, "allow_message")
	if e := f.deliveryEvent(f.s); e.Data["status"] != "readable" || e.Data["review_action"] != nil {
		t.Fatal(e)
	}
	sub["arguments"] = map[string]any{}
	if r := f.call("events/subscribe", "2025-11-25", "alice", "g1", sub); r.Error != nil {
		t.Fatal(r.Error)
	}
	f.sendSample("bob", "format-disabled")
	if e := f.deliveryEvent(f.s); e.Data["review_action"] != nil {
		t.Fatal(e)
	}
	f.next(f.s, false)
	f.assertRead(first, false)
}
