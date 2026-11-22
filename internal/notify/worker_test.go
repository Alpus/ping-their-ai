package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSlowOwnerCannotBlockOtherRecipients(t *testing.T) {
	f := newFixture(t)
	for i := range 4 {
		args := subArgs(testKey('s'))
		args["delivery"].(map[string]string)["url"] = fmt.Sprintf("%s/slow/%d", callback, i)
		if res := f.call("events/subscribe", "2025-11-25", "alice", "g1", args); res.Error != nil {
			t.Fatal(res.Error)
		}
	}
	args := subArgs(testKey('b'))
	args["delivery"].(map[string]string)["url"] = callback + "/fast"
	if res := f.call("events/subscribe", "2025-11-25", "bob", "g2", args); res.Error != nil {
		t.Fatal(res.Error)
	}
	for i := range 4 {
		f.enqueue("alice", fmt.Sprint(i), true)
	}

	requests := make(chan string, 16)
	f.s.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		requests <- r.URL.Path
		if strings.Contains(r.URL.Path, "/slow/") {
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { f.s.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	receive := func() string {
		t.Helper()
		select {
		case path := <-requests:
			return path
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for a delivery")
			return ""
		}
	}
	if path := receive(); !strings.Contains(path, "/slow/") {
		t.Fatalf("first delivery: %s", path)
	}
	f.enqueue("bob", "first", true)
	if path := receive(); !strings.HasSuffix(path, "/fast") {
		t.Fatalf("slow owner occupied another worker: %s", path)
	}
}

func TestInterruptedLeaseDoesNotSpendFinalAttempt(t *testing.T) {
	f := newFixture(t)
	f.sub(testKey('a'))
	f.enqueue("alice", "last", true)
	if _, err := f.db.Exec("UPDATE notify_jobs SET attempt=?", maxAttempts-1); err != nil {
		t.Fatal(err)
	}
	abandoned, err := f.s.claim(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	restarted := f.service()
	f.next(restarted, false)
	f.now = f.now.Add(time.Minute)
	successor, err := restarted.claim(t.Context())
	if err != nil || successor.lease == abandoned.lease {
		t.Fatalf("replacement lease: %v", err)
	}
	if err := f.s.settle(t.Context(), abandoned, time.Time{}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	var attempts int
	if err := f.db.QueryRow("SELECT attempt FROM notify_jobs WHERE message_id='last'").Scan(&attempts); err != nil || attempts != maxAttempts-1 {
		t.Fatalf("after interrupted leases: attempts=%d err=%v", attempts, err)
	}
	f.now = f.now.Add(time.Minute)
	f.next(restarted, true)
	f.next(restarted, false)
	if len(f.hooks) != 2 {
		t.Fatalf("got %d hooks including verification", len(f.hooks))
	}
}

func TestUpgradeRetriesLegacyFinalLease(t *testing.T) {
	f := newFixture(t)
	f.sub(testKey('a'))
	f.enqueue("alice", "legacy", true)
	due := f.now.Add(time.Minute)
	if _, err := f.db.Exec("DROP TABLE notify_dispatch"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec("UPDATE notify_jobs SET ready_at=?,attempt=?", due.UnixMilli(), maxAttempts); err != nil {
		t.Fatal(err)
	}
	upgraded := f.service()
	f.next(upgraded, false)
	f.now = due
	f.next(upgraded, true)
	f.next(upgraded, false)
	if len(f.hooks) != 2 {
		t.Fatal("last delivery was dropped on upgrade")
	}
}

func TestGrantLookupFailureRetainsSubscriptionAndQueue(t *testing.T) {
	f := newFixture(t)
	f.sub(testKey('a'))
	f.enqueue("alice", "queued", true)
	active := f.s.active
	failure := errors.New("grant store unavailable")
	f.s.active = func(context.Context, string, string) (bool, error) { return false, failure }
	did, err := f.s.processNext(t.Context())
	if !did || !errors.Is(err, failure) {
		t.Fatalf("lookup result: %t %v", did, err)
	}
	var attempts int
	if err := f.db.QueryRow("SELECT attempt FROM notify_jobs WHERE message_id='queued'").Scan(&attempts); err != nil || attempts != 0 || len(f.hooks) != 1 {
		t.Fatalf("temporary failure: attempts=%d hooks=%d err=%v", attempts, len(f.hooks), err)
	}
	f.enqueue("alice", "new-arrival", true)
	f.s.active = active
	f.next(f.s, false)
	f.now = f.now.Add(5 * time.Second)
	f.next(f.s, true)
	f.next(f.s, true)
	f.next(f.s, false)
	if len(f.hooks) != 3 {
		t.Fatal("queued notifications did not recover")
	}
}

func TestRetryAfterAppliesToOnlyAffectedSubscription(t *testing.T) {
	for _, format := range []string{"seconds", "date"} {
		t.Run(format, func(t *testing.T) {
			f := newFixture(t)
			slow := f.sub(testKey('a'))["id"].(string)
			f.enqueue("alice", "queued", true)
			until := f.now.Add(2 * time.Hour)
			transport := f.s.client.Transport
			f.s.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
				resp, err := transport.RoundTrip(r)
				if err != nil {
					return nil, err
				}
				resp.StatusCode = http.StatusTooManyRequests
				header := "7200"
				if format == "date" {
					header = until.Format(http.TimeFormat)
				}
				resp.Header.Set("Retry-After", header)
				return resp, nil
			})
			f.next(f.s, true)
			f.s.client.Transport = transport
			args := subArgs(testKey('b'))
			args["delivery"].(map[string]string)["url"] = callback + "/another"
			other := f.call("events/subscribe", "2025-11-25", "alice", "g2", args)
			if other.Error != nil {
				t.Fatal(other.Error)
			}
			f.enqueue("alice", "new-arrival", true)
			worker := f.service()
			f.now = until.Add(-time.Millisecond)
			f.next(worker, true)
			if got := f.hooks[len(f.hooks)-1].header.Get("X-MCP-Subscription-Id"); got != other.Result["id"] {
				t.Fatalf("unexpected early callback %s", got)
			}
			f.next(worker, false)
			f.now = until
			for range 2 {
				f.next(worker, true)
				if f.hooks[len(f.hooks)-1].header.Get("X-MCP-Subscription-Id") != slow {
					t.Fatal("retried wrong callback")
				}
			}
			f.next(worker, false)
		})
	}
}

func TestRetryAfterCannotOutliveOriginalSubscriptionTerm(t *testing.T) {
	f := newFixture(t)
	args := subArgs(testKey('a'))
	args["ttlMs"] = time.Minute.Milliseconds()
	subscribe := func() {
		t.Helper()
		if res := f.call("events/subscribe", "2025-11-25", "alice", "g1", args); res.Error != nil {
			t.Fatal(res.Error)
		}
	}
	subscribe()
	end := f.now.Add(time.Minute)
	f.enqueue("alice", "original", true)
	transport := f.s.client.Transport
	f.s.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		resp, err := transport.RoundTrip(r)
		if err == nil {
			resp.StatusCode = http.StatusServiceUnavailable
			resp.Header.Set("Retry-After", "99999999999999999999")
		}
		return resp, err
	})
	f.next(f.s, true)
	f.s.client.Transport = transport

	args["ttlMs"] = time.Hour.Milliseconds()
	f.now = end.Add(-30 * time.Second)
	subscribe()
	f.enqueue("alice", "after-renewal", true)
	f.now = end.Add(-time.Millisecond)
	subscribe()
	restarted := f.service()
	f.next(restarted, false)
	f.now = end
	f.next(restarted, true)
	f.next(restarted, true)
	f.next(restarted, false)
	if len(f.hooks) != 4 {
		t.Fatalf("got %d callbacks including verification, initial attempt and both deliveries", len(f.hooks))
	}
}
