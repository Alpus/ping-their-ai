package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Alpus/ping-their-ai/internal/message"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	_ "modernc.org/sqlite"
)

type principalKey struct{}
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type hook struct {
	header http.Header
	body   []byte
}
type fixture struct {
	t       *testing.T
	s       *Service
	inbox   *message.Store
	db      *sql.DB
	now     time.Time
	active  bool
	server  *httptest.Server
	hooks   []hook
	status  int
	badEcho bool
}

const callback = "https://receiver.example/events/one"

func testKey(char byte) string {
	return "whsec_" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{char}, 32))
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "events.db")+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	f := &fixture{t: t, db: db, now: time.Date(2026, 11, 1, 12, 30, 0, 0, time.UTC), active: true, status: 202}
	f.s = f.service()
	f.inbox, err = message.New(t.Context(), db, f.s.Enqueue, f.s.Readable, f.s.Approved)
	if err != nil {
		t.Fatal(err)
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, &mcp.ServerOptions{Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}}})
	if err := f.s.Install(server); err != nil {
		t.Fatal(err)
	}
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := Principal{r.Header.Get("Test-Subject"), r.Header.Get("Test-Grant")}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fixture) service() *Service {
	f.t.Helper()
	s, err := New(context.Background(), f.db, func(ctx context.Context) (Principal, bool) {
		p, ok := ctx.Value(principalKey{}).(Principal)
		return p, ok
	},
		func(ctx context.Context, subject string) (bool, error) { return subject != "pending", nil },
		func(ctx context.Context, subject, grant string) (bool, error) { return f.active, nil }, Delivery{
			MessageURL: func(id string) string { return "https://ping.example/messages/" + id },
			Body: func(ctx context.Context, subject, id string) (*string, error) {
				return f.inbox.DeliveryBody(ctx, subject, id)
			},
			Acknowledge: func(ctx context.Context, tx *sql.Tx, subject, id string) error {
				return f.inbox.AcknowledgeDelivery(ctx, tx, subject, id)
			},
		})
	if err != nil {
		f.t.Fatal(err)
	}
	s.now = func() time.Time { return f.now }
	s.client = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		f.hooks = append(f.hooks, hook{r.Header.Clone(), payload})
		var verify struct {
			Challenge string `json:"challenge"`
		}
		json.Unmarshal(payload, &verify)
		status := f.status
		responseBody := ""
		if verify.Challenge != "" {
			status = 200
			if f.badEcho {
				verify.Challenge = "different"
			}
			b, _ := json.Marshal(verify)
			responseBody = string(b)
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(responseBody)), Header: make(http.Header)}, nil
	})}
	return s
}

type wire struct {
	Result map[string]any `json:"result"`
	Error  *struct {
		Code int
		Data map[string]string
	} `json:"error"`
}

func (f *fixture) call(method, version, owner, grant string, params map[string]any) wire {
	f.t.Helper()
	if version == "2026-07-28" {
		params["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": version, "io.modelcontextprotocol/clientInfo": map[string]string{"name": "test", "version": "1"}, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequest("POST", f.server.URL, bytes.NewReader(b))
	if err != nil {
		f.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Method", method)
	req.Header.Set("MCP-Protocol-Version", version)
	req.Header.Set("Test-Subject", owner)
	req.Header.Set("Test-Grant", grant)
	res, err := f.server.Client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer res.Body.Close()
	var w wire
	raw, _ := io.ReadAll(res.Body)
	if err := json.Unmarshal(raw, &w); err != nil {
		f.t.Fatalf("%s returned HTTP %d: %s", method, res.StatusCode, raw)
	}
	return w
}
func subArgs(key string) map[string]any {
	delivery := map[string]string{"mode": "webhook", "url": callback}
	if key != "" {
		delivery["secret"] = key
	}
	return map[string]any{"name": eventName, "arguments": map[string]any{}, "delivery": delivery, "cursor": nil}
}

func (f *fixture) sub(key string) map[string]any {
	f.t.Helper()
	r := f.call("events/subscribe", "2025-11-25", "alice", "g1", subArgs(key))
	if r.Error != nil || r.Result["id"] == nil {
		f.t.Fatalf("subscribe failed: %+v", r.Error)
	}
	return r.Result
}

func (f *fixture) enqueue(owner, id string, commit bool) {
	f.t.Helper()
	ctx := context.Background()
	tx, err := f.db.Begin()
	if err != nil {
		f.t.Fatal(err)
	}
	if err := f.s.Enqueue(ctx, tx, owner, id, "bob"); err != nil {
		f.t.Fatal(err)
	}
	if commit {
		err = tx.Commit()
	} else {
		err = tx.Rollback()
	}
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) next(service *Service, want bool) {
	f.t.Helper()
	got, err := service.processNext(context.Background())
	if err != nil || got != want {
		f.t.Fatalf("processNext = %t, %v; want %t", got, err, want)
	}
}

// Verify the HTTP bytes as an independent receiver, using the Standard Webhooks input.
func verifySignature(t *testing.T, h hook, id, key string) {
	t.Helper()
	decoded, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(key, "whsec_"))
	mac := hmac.New(sha256.New, decoded)
	mac.Write([]byte(h.header.Get("webhook-id") + "." + h.header.Get("webhook-timestamp") + "."))
	mac.Write(h.body)
	want := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	found := false
	for _, sig := range strings.Fields(h.header.Get("webhook-signature")) {
		found = found || hmac.Equal([]byte(want), []byte(sig))
	}
	if !found || h.header.Get("Content-Type") != "application/json" || h.header.Get("X-MCP-Subscription-Id") != id {
		t.Fatal("invalid webhook signature or headers")
	}
}

func TestProtocolOnBothSDKWires(t *testing.T) {
	f := newFixture(t)
	init := f.call("initialize", "2025-11-25", "alice", "g1", map[string]any{"protocolVersion": "2025-11-25", "clientInfo": map[string]string{"name": "test", "version": "1"}, "capabilities": map[string]any{}})
	discover := f.call("server/discover", "2026-07-28", "alice", "g1", map[string]any{})
	if discover.Result["resultType"] != "complete" || discover.Result["supportedVersions"] == nil {
		t.Fatalf("MCP 2 discovery: %+v, error %+v", discover.Result, discover.Error)
	}
	for _, r := range []wire{init, discover} {
		caps, ok := r.Result["capabilities"].(map[string]any)
		if !ok || caps["events"] == nil || caps["tools"] == nil {
			t.Fatalf("missing capabilities: %+v, error %+v", r.Result, r.Error)
		}
	}
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		r := f.call("events/list", version, "alice", "g1", map[string]any{})
		list, ok := r.Result["events"].([]any)
		if !ok || len(list) != 3 || list[0].(map[string]any)["name"] != receivedEvent || list[2].(map[string]any)["name"] != readableEvent {
			t.Fatalf("events/list on %s: %+v %+v", version, r.Result, r.Error)
		}
		d := list[1].(map[string]any)
		if d["name"] != eventName || !reflect.DeepEqual(d["delivery"], []any{"webhook"}) {
			t.Fatalf("unexpected event: %+v", d)
		}
		if f.call("events/list", version, "pending", "g2", map[string]any{}).Error != nil {
			t.Fatal("authenticated client could not discover the static event before activation")
		}
		if f.call("events/subscribe", version, "pending", "g2", subArgs(testKey('w'))).Error == nil {
			t.Fatal("inactive inbox subscribed")
		}
		if created := f.call("events/subscribe", version, "alice", "g1", subArgs(testKey('w'))); created.Error != nil || created.Result["id"] == nil {
			t.Fatalf("subscribe on %s: %+v", version, created.Error)
		}
		stopped := f.call("events/unsubscribe", version, "alice", "g1", subArgs(""))
		if stopped.Error != nil {
			t.Fatalf("unsubscribe on %s: %+v", version, stopped)
		}
		if version == "2026-07-28" {
			if r.Result["resultType"] != "complete" || stopped.Result["resultType"] != "complete" || stopped.Result["_meta"] == nil {
				t.Fatalf("missing MCP 2.0 envelopes: list=%+v unsubscribe=%+v", r.Result, stopped.Result)
			}
			delete(stopped.Result, "_meta")
			delete(stopped.Result, "resultType")
		}
		if len(stopped.Result) != 0 {
			t.Fatalf("unexpected unsubscribe payload: %+v", stopped.Result)
		}
	}
}

func TestVerifiedDeliveryRetryRotationAndUnsubscribe(t *testing.T) {
	f := newFixture(t)
	old, newKey := testKey('a'), testKey('b')
	sub := f.sub(old)
	id := sub["id"].(string)
	if sub["cursor"] != nil || sub["truncated"] != false || len(f.hooks) != 1 {
		t.Fatalf("initial subscription: %+v", sub)
	}
	first := f.hooks[0]
	verifySignature(t, first, id, old)
	var verification map[string]any
	json.Unmarshal(first.body, &verification)
	if len(verification) != 2 || verification["type"] != "verification" || verification["challenge"] == "" {
		t.Fatal("unexpected verification payload")
	}
	if f.sub(old)["id"] != id || len(f.hooks) != 1 {
		t.Fatal("verification not cached")
	}
	if f.sub(newKey)["id"] != id || len(f.hooks) != 2 {
		t.Fatal("rotation did not reverify the new key")
	}
	verifySignature(t, f.hooks[1], id, newKey)
	f.enqueue("other", "not-for-this-inbox", true)
	f.enqueue("alice", "rollback", false)
	f.next(f.s, false)
	f.enqueue("alice", "message1", true)
	f.enqueue("alice", "message1", true)
	// Durable state is read by a new service, with no in-memory subscription.
	restarted := f.service()
	f.status = 503
	f.next(restarted, true)
	sent := f.hooks[len(f.hooks)-1]
	verifySignature(t, sent, id, old)
	verifySignature(t, sent, id, newKey)
	var event map[string]any
	json.Unmarshal(sent.body, &event)
	if len(event) != 5 || event["eventId"] != sent.header.Get("webhook-id") || event["name"] != eventName || event["cursor"] != nil || event["timestamp"] != f.now.Format(time.RFC3339) || !reflect.DeepEqual(event["data"], map[string]any{"message_id": "message1", "sender_handle": "bob"}) {
		t.Fatalf("delivery leaked or omitted data: %+v", event)
	}
	f.next(restarted, false)
	f.now = f.now.Add(6 * time.Second)
	f.status = 202
	f.next(restarted, true)
	retry := f.hooks[len(f.hooks)-1]
	if !bytes.Equal(retry.body, sent.body) || retry.header.Get("webhook-timestamp") == sent.header.Get("webhook-timestamp") {
		t.Fatal("retry changed the event or reused the signing time")
	}
	verifySignature(t, retry, id, newKey)
	f.next(restarted, false)
	// Another grant cannot cancel this subscription.
	if f.call("events/unsubscribe", "2025-11-25", "alice", "other-grant", subArgs("")).Error != nil {
		t.Fatal("unsubscribe should be idempotent")
	}
	f.enqueue("alice", "message2", true)
	f.next(f.s, true)
	f.enqueue("alice", "message3", true)
	for range 2 {
		r := f.call("events/unsubscribe", "2025-11-25", "alice", "g1", subArgs(""))
		if r.Error != nil || len(r.Result) != 0 {
			t.Fatalf("unsubscribe: %+v", r)
		}
	}
	f.next(f.s, false)
	f.enqueue("alice", "after-unsubscribe", true)
	f.next(f.s, false)
}

func TestFailedChallengeExpiryAndRevocation(t *testing.T) {
	f := newFixture(t)
	key := testKey('k')
	f.badEcho = true
	reply := f.call("events/subscribe", "2025-11-25", "alice", "g1", subArgs(key))
	if reply.Error == nil || reply.Error.Code != -32015 || reply.Error.Data["reason"] != "challenge_failed" {
		t.Fatalf("wrong verification error: %+v", reply.Error)
	}
	f.enqueue("alice", "before", true)
	f.next(f.s, false)
	f.badEcho = false
	args := subArgs(key)
	args["ttlMs"] = int64(1000)
	r := f.call("events/subscribe", "2025-11-25", "alice", "g1", args)
	if r.Result["refreshBefore"] != f.now.Add(time.Second).Format(time.RFC3339) {
		t.Fatalf("lifetime: %+v", r.Result)
	}
	f.enqueue("alice", "before-expiry", true)
	f.now = f.now.Add(2 * time.Second)
	f.enqueue("alice", "after-expiry", true)
	before := len(f.hooks)
	f.next(f.s, true)
	f.next(f.s, false)
	if len(f.hooks) != before {
		t.Fatal("sent after expiry")
	}
	f.sub(key)
	f.enqueue("alice", "after-revoke", true)
	f.active = false
	before = len(f.hooks)
	f.next(f.s, true)
	if len(f.hooks) != before {
		t.Fatal("sent to revoked connection")
	}
	f.enqueue("alice", "also-after-revoke", true)
	f.next(f.s, false)
}

func TestBoundedPublicHTTPS(t *testing.T) {
	c := publicClient()
	tr := c.Transport.(*http.Transport)
	if tr.Proxy != nil || c.Timeout <= 0 || tr.MaxResponseHeaderBytes == 0 || c.CheckRedirect(&http.Request{}, nil) != http.ErrUseLastResponse {
		t.Fatal("webhook client missing network bounds")
	}
	for _, s := range []string{"http://example.com/events", "https://127.0.0.1/events", "https://10.0.0.1/events", "https://[::1]/events", "https://user@example.org/events", "https://example.org/events#frag"} {
		if err := validateURL(s); err == nil {
			t.Fatalf("unexpected callback acceptance: %s", s)
		}
	}
	if err := validateURL(callback); err != nil {
		t.Fatal(err)
	}
	_, err := tr.DialContext(context.Background(), "tcp", "127.0.0.1:443")
	if err == nil {
		t.Fatal("private connection allowed")
	}
}

func TestRetryLimitsAndTerminalResponses(t *testing.T) {
	for _, tc := range []struct {
		name             string
		status, attempts int
		active           bool
	}{
		{"too large drops only this event", 413, 1, true},
		{"stale event drops only this delivery", 410, 1, true},
		{"temporary failures stop after five attempts", 503, maxAttempts, true},
		{"permanent response drops this event", 403, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.sub(testKey('t'))
			f.enqueue("alice", "persistent", true)
			f.status = tc.status
			for range tc.attempts {
				f.next(f.s, true)
				f.now = f.now.Add(3 * time.Minute)
			}
			f.next(f.s, false)
			if got := len(f.hooks) - 1; got != tc.attempts {
				t.Fatalf("got %d attempts; want %d", got, tc.attempts)
			}
			f.status = 200
			f.enqueue("alice", "next", true)
			f.next(f.s, tc.active)
		})
	}
}

func TestRunDeliversCommittedEventAndStops(t *testing.T) {
	f := newFixture(t)
	f.sub(testKey('s'))
	f.enqueue("alice", "run-test", true)
	delivered := make(chan struct{}, 1)
	base := f.s.client.Transport
	f.s.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		resp, err := base.RoundTrip(r)
		if err == nil {
			delivered <- struct{}{}
		}
		return resp, err
	})
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan struct{})
	go func() { f.s.Run(ctx); close(done) }()
	select {
	case <-delivered:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not dispatch")
	}
	// Wait for the successful HTTP acknowledgement to be committed before
	// interrupting Run, as on an orderly shutdown after delivery.
	deadline := time.Now().Add(3 * time.Second)
	var n int
	for {
		if err := f.db.QueryRow("SELECT COUNT(*) FROM notify_jobs").Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("acknowledged job was retained")
		}
		time.Sleep(time.Millisecond)
	}
	stop()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker failed to stop")
	}
}

func (f *fixture) follow(owner, grant, id, suffix string) string {
	f.t.Helper()
	args := subArgs(testKey('a'))
	args["name"] = readableEvent
	args["arguments"] = map[string]any{"request_id": id}
	args["delivery"].(map[string]string)["url"] = callback + suffix
	res := f.call("events/subscribe", "2025-11-25", owner, grant, args)
	if res.Error != nil {
		f.t.Fatal(res.Error)
	}
	return res.Result["id"].(string)
}

func TestReadableOnlyWakesOriginalRequestAndGrant(t *testing.T) {
	f := newFixture(t)
	key := strings.Repeat("a", 26)
	finish := func(req string) {
		tx, err := f.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err = f.s.Readable(t.Context(), tx, "alice", "g1", req, "m1"); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}

	normal := f.sub(testKey('n'))["id"].(string)
	correct := f.follow("alice", "g1", key, "/target")
	f.follow("alice", "g2", key, "/other-app")
	f.follow("bob", "g1", key, "/other-owner")
	f.follow("alice", "g1", key+"b", "/other-request")
	f.enqueue("alice", "ordinary", true)
	f.next(f.s, true)
	if f.hooks[len(f.hooks)-1].header.Get("X-MCP-Subscription-Id") != normal {
		t.Fatal("inbox event sent to a read waiter")
	}
	f.next(f.s, false)
	finish(key)
	f.next(f.s, true)
	f.next(f.s, false)
	sent := f.hooks[len(f.hooks)-1]
	var event map[string]any
	if err := json.Unmarshal(sent.body, &event); err != nil {
		t.Fatal(err)
	}
	if sent.header.Get("X-MCP-Subscription-Id") != correct || event["name"] != readableEvent || !reflect.DeepEqual(event["data"], map[string]any{"message_id": "m1", "request_id": key}) {
		t.Fatal("resume did not match")
	}
	// A browser click preceding the host's registration is replayed to the
	// original grant. Refreshing an already-delivered subscription stays quiet.
	late := key + "c"
	finish(late)
	id := f.follow("alice", "g1", late, "/late")
	f.next(f.s, true)
	f.next(f.s, false)
	if f.hooks[len(f.hooks)-1].header.Get("X-MCP-Subscription-Id") != id {
		t.Fatal("missed the fast browser decision")
	}
	f.follow("alice", "g1", late, "/late")
	f.next(f.s, false)
}

func TestSharedConsentWakesOnlyRelatedPendingRequests(t *testing.T) {
	for _, decision := range []string{"allow_message", "always", "once"} {
		t.Run(decision, func(t *testing.T) {
			f := newFixture(t)
			ctx := t.Context()
			for _, owner := range []string{"alice", "bob", "eve"} {
				if _, err := f.inbox.Register(ctx, owner, owner); err != nil {
					t.Fatal(err)
				}
			}
			send := func(sender, owner, key string) string {
				t.Helper()
				out, err := f.inbox.Send(ctx, sender, owner, "private text", key)
				if err != nil || out["status"] != "sent" {
					t.Fatal(out, err)
				}
				return out["message_id"].(string)
			}
			request := func(owner, grant, message string) string {
				t.Helper()
				out, err := f.inbox.Read(ctx, owner, grant, "client", message, "")
				if err != nil || out["status"] != "approval_required" {
					t.Fatal(out, err)
				}
				return out["approval_key"].(string)
			}
			message := send("bob", "alice", "first")
			sameSender := send("bob", "alice", "second")
			card := request("alice", "card", message)
			otherChat := request("alice", "dots", message)
			late := request("alice", "card", message) // another chat on the card's grant
			anotherMessage := request("alice", "dots", sameSender)
			dismissed := request("alice", "dots", message)
			expired := request("alice", "dots", message)
			if out, err := f.inbox.Decide(ctx, "alice", dismissed, "later"); err != nil || out["status"] != "later" {
				t.Fatal(out, err)
			}
			f.follow("alice", "card", card, "/card")
			firstSub := f.follow("alice", "dots", otherChat, "/dots")
			secondSub := f.follow("alice", "dots", anotherMessage, "/sender")
			f.follow("alice", "dots", dismissed, "/dismissed")
			f.follow("alice", "dots", expired, "/expired")
			f.follow("alice", "dots", request("alice", "dots", send("eve", "alice", "other")), "/other-sender")
			f.follow("eve", "dots", request("eve", "dots", send("bob", "eve", "other")), "/other-owner")

			if _, err := f.db.Exec("UPDATE mail_approvals SET expires_ns=0 WHERE id=?", expired); err != nil {
				t.Fatal(err)
			}

			proof := f.inbox.WidgetProof("alice", "card", message, card)
			if out, err := f.inbox.DecideWidget(ctx, "alice", "card", message, card, proof, decision); err != nil || out["message_id"] != message {
				t.Fatal(out, err)
			}
			// A host can finish subscribing after the owner clicked elsewhere.
			lateSub := f.follow("alice", "card", late, "/late")
			want := map[string]map[string]any{}
			if decision != "once" {
				want[firstSub] = map[string]any{"message_id": message, "request_id": otherChat}
				want[lateSub] = map[string]any{"message_id": message, "request_id": late}
			}
			if decision == "always" {
				want[secondSub] = map[string]any{"message_id": sameSender, "request_id": anotherMessage}
			}
			for len(want) > 0 {
				f.next(f.s, true)
				sent := f.hooks[len(f.hooks)-1]
				sub := sent.header.Get("X-MCP-Subscription-Id")
				var event map[string]any
				if err := json.Unmarshal(sent.body, &event); err != nil {
					t.Fatal(err)
				}
				if event["name"] != readableEvent || !reflect.DeepEqual(want[sub], event["data"]) {
					t.Fatalf("unexpected delivery for %s: %v", sub, event)
				}
				verifySignature(t, sent, sub, testKey('a'))
				delete(want, sub)
			}
			f.next(f.s, false)
		})
	}
}

func TestSubscribeDeliversUnreadMessagesAlreadyInTheInbox(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	for _, h := range []string{"alice", "bob", "eve"} {
		if _, err := f.inbox.Register(ctx, h, h); err != nil {
			t.Fatal(err)
		}
	}
	send := func(recipient, key string) string {
		t.Helper()
		out, err := f.inbox.Send(ctx, "bob", recipient, "private text", key)
		if err != nil || out["status"] != "sent" {
			t.Fatalf("send: %v %v", out, err)
		}
		return out["message_id"].(string)
	}
	send("eve", "other-inbox")
	read := send("alice", "already-read")
	out, err := f.inbox.Read(ctx, "alice", "g1", "chat", read, "")
	if err != nil || out["status"] != "approval_required" {
		t.Fatal(out, err)
	}
	request := out["approval_key"].(string)
	if _, err = f.inbox.Decide(ctx, "alice", request, "once"); err != nil {
		t.Fatal(err)
	}
	if out, err = f.inbox.Read(ctx, "alice", "g1", "chat", read, request); err != nil || out["status"] != "read" {
		t.Fatal(out, err)
	}
	first := send("alice", "first")
	// The second message arrives while the server is verifying the callback.
	var second string
	verifyTransport := f.s.client.Transport
	f.s.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if second == "" {
			second = send("alice", "during-challenge")
		}
		return verifyTransport.RoundTrip(r)
	})
	key := testKey('a')
	sub := f.sub(key)["id"].(string)
	f.s.client.Transport = verifyTransport
	f.sub(key)
	for _, id := range []string{first, second} {
		f.next(f.s, true)
		delivery := f.hooks[len(f.hooks)-1]
		verifySignature(t, delivery, sub, key)
		var event struct {
			Name string
			Data map[string]string
		}
		if err := json.Unmarshal(delivery.body, &event); err != nil || event.Name != eventName || !reflect.DeepEqual(event.Data, map[string]string{"message_id": id, "sender_handle": "@bob"}) {
			t.Fatalf("unexpected event: %s", delivery.body)
		}
	}
	f.sub(key)
	f.next(f.s, false)
	if out, err = f.inbox.Read(ctx, "alice", "g1", "chat", first, ""); err != nil || out["status"] != "approval_required" {
		t.Fatal(out, err)
	}
	// A newly subscribed chat can still receive both unread envelopes.
	args := subArgs(key)
	args["delivery"].(map[string]string)["url"] = callback + "/second-chat"
	if reply := f.call("events/subscribe", "2025-11-25", "alice", "g2", args); reply.Error != nil {
		t.Fatal(reply.Error)
	}
	f.next(f.s, true)
	f.next(f.s, true)
	f.next(f.s, false)
}

func TestEventInstructionsOptIn(t *testing.T) {
	const requestID = "abcdefghjkmnpqrstuvwxy2345"
	for _, event := range []string{eventName, readableEvent} {
		for _, tc := range []struct {
			name    string
			initial bool
			renew   bool
			choice  any
			want    bool
		}{
			{name: "legacy subscription"},
			{name: "opt in on creation", initial: true, want: true},
			{name: "opt in on renewal", renew: true, choice: true, want: true},
			{name: "renew with false", initial: true, renew: true, choice: false},
			{name: "renew with old arguments", initial: true, renew: true},
		} {
			t.Run(event+"/"+tc.name, func(t *testing.T) {
				f := newFixture(t)
				params := subArgs(testKey('a'))
				params["name"] = event
				arguments := params["arguments"].(map[string]any)
				if event == readableEvent {
					arguments["request_id"] = requestID
				}
				if tc.initial {
					arguments["include_next"] = true
				}
				subscribe := func() string {
					t.Helper()
					res := f.call("events/subscribe", "2025-11-25", "alice", "g1", params)
					if res.Error != nil {
						t.Fatal(res.Error)
					}
					return res.Result["id"].(string)
				}
				id := subscribe()
				// On upgrade, pre-existing subscriptions are still present while the
				// new preferences table has never existed.
				if !tc.initial {
					if _, err := f.db.Exec("DROP TABLE notify_include_next"); err != nil {
						t.Fatal(err)
					}
					f.service()
				}
				if tc.renew {
					delete(arguments, "include_next")
					if tc.choice != nil {
						arguments["include_next"] = tc.choice
					}
					if subscribe() != id {
						t.Fatal("renewal changed subscription ID")
					}
				}
				worker := f.service()
				wantData := map[string]string{"message_id": "m1"}
				if event == readableEvent {
					tx, err := f.db.Begin()
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback()
					if err := worker.Readable(t.Context(), tx, "alice", "g1", requestID, "m1"); err != nil {
						t.Fatal(err)
					}
					if err := tx.Commit(); err != nil {
						t.Fatal(err)
					}
					wantData["request_id"] = requestID
					if tc.want {
						wantData["next"] = readableNext
					}
				} else {
					f.enqueue("alice", "m1", true)
					wantData["sender_handle"] = "bob"
					if tc.want {
						wantData["next"] = fmt.Sprintf(createdNext, worker.delivery.MessageURL("m1"))
					}
				}
				f.next(worker, true)
				f.next(worker, false)
				delivery := f.hooks[len(f.hooks)-1]
				var received struct {
					Name string
					Data map[string]string
				}
				if err := json.Unmarshal(delivery.body, &received); err != nil {
					t.Fatal(err)
				}
				if delivery.header.Get("X-MCP-Subscription-Id") != id || received.Name != event || !reflect.DeepEqual(received.Data, wantData) {
					t.Fatalf("unexpected delivery: %s", delivery.body)
				}
			})
		}
	}
}

func TestDiscoveredSubscriptionSchemasRequireIncludeNext(t *testing.T) {
	for _, event := range []eventDefinition{inboxEvent, readEvent} {
		t.Run(event.Name, func(t *testing.T) {
			var schema jsonschema.Schema
			if err := json.Unmarshal(event.InputSchema, &schema); err != nil {
				t.Fatal(err)
			}
			resolved, err := schema.Resolve(nil)
			if err != nil {
				t.Fatal(err)
			}
			args := map[string]any{}
			if event.Name == readableEvent {
				args["request_id"] = "abcdefghjkmnpqrstuvwxy2345"
			}
			if resolved.Validate(args) == nil {
				t.Fatal("newly discovered schema accepted missing include_next")
			}
			args["include_next"] = true
			if err := resolved.Validate(args); err != nil {
				t.Fatal(err)
			}
			if got := string(schema.Properties["include_next"].Default); got != "true" {
				t.Fatalf("include_next default = %s", got)
			}
		})
	}
}

func TestIncludeNextRejectsInvalidArguments(t *testing.T) {
	f := newFixture(t)
	for _, arguments := range []map[string]any{{"include_next": nil}, {"include_next": "true"}, {"include_next": true, "extra": false}} {
		params := subArgs(testKey('a'))
		params["arguments"] = arguments
		res := f.call("events/subscribe", "2025-11-25", "alice", "g1", params)
		if res.Error == nil || res.Error.Code != -32602 {
			t.Fatalf("accepted invalid arguments: %v", arguments)
		}
	}
}
