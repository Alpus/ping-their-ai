package authn

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestBrowserSignInBudgetPrecedesStorage(t *testing.T) {
	f := newFixture(t)
	f.svc.limits = limits{until: time.Now().Add(time.Minute), counts: map[string]int{"browser-signin:192.0.2.1": 89}}
	want(t, f.req(nil, "GET", prefix+"/connections", "", "", nil), http.StatusSeeOther)
	for _, path := range []string{"/connections", "/approve/message"} {
		res := f.req(nil, "GET", prefix+path, "", "", nil)
		want(t, res, http.StatusTooManyRequests)
		if res.Header().Get("Set-Cookie") != "" || res.Header().Get("Retry-After") == "" {
			t.Fatal("limited request should only receive retry instructions")
		}
	}
	for _, table := range []string{"auth_sessions", "auth_flows", "auth_oidc"} {
		var n int
		if err := f.db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil || n != 1 {
			t.Fatalf("%s has %d rows: %v", table, n, err)
		}
	}
}

func TestOwnerDisconnectsLegacyConnection(t *testing.T) {
	f := newFixture(t)
	b := new(browser)
	client := f.register(t)
	v, _ := f.oauthForm(t, b, client)
	first := f.connect(t, b, client, "handle", v)
	who := f.principal(t, first.Access)
	v, _ = f.oauthForm(t, b, client)
	second := f.connect(t, b, client, "connect", v)
	// Simulate the old release: real tokens and browser sessions were stored
	// normally in bbolt and SQLite; no owner-to-grant index existed.
	if err := f.svc.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec("DROP TABLE auth_connections"); err != nil {
		t.Fatal(err)
	}
	f.open(t)
	ctx := t.Context()
	want(t, f.req(b, "GET", prefix+"/connections", "", "", nil), http.StatusOK)
	got, err := f.svc.Connections(ctx, who.Subject)
	if err != nil || len(got) != 2 || got[0].Client != who.Client || got[0].Created.IsZero() {
		t.Fatalf("prior connections not available: %v %v", got, err)
	}
	// An older server can issue grants after the index exists; separately
	// restored SQLite data can also contain stale or misassigned rows.
	if err := f.svc.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec("DELETE FROM auth_connections WHERE id=?", who.Grant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec("UPDATE auth_connections SET subject='wrong-owner'"); err != nil {
		t.Fatal(err)
	}
	f.open(t)
	got, err = f.svc.Connections(ctx, who.Subject)
	if err != nil || len(got) != 2 {
		t.Fatalf("existing index was not reconciled: %v %v", got, err)
	}
	other, err := f.svc.Connections(ctx, "other-owner")
	if err != nil || len(other) != 0 {
		t.Fatalf("incorrect owner filter: %v %v", other, err)
	}
	if err := f.svc.Disconnect(ctx, "other-owner", who.Grant); err != nil {
		t.Fatal(err)
	}
	f.principal(t, first.Access)
	if err := f.svc.Disconnect(ctx, who.Subject, who.Grant); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Disconnect(ctx, who.Subject, who.Grant); err != nil {
		t.Fatal("disconnect must be idempotent", err)
	}
	want(t, f.req(nil, "GET", prefix+"/mcp", "", "", http.Header{"Authorization": {"Bearer " + first.Access}}), 401)
	want(t, f.post(nil, prefix+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {first.Refresh}}), 400)
	remaining := f.principal(t, second.Access)
	got, err = f.svc.Connections(ctx, who.Subject)
	if err != nil || len(got) != 1 || got[0].ID != remaining.Grant {
		t.Fatalf("remaining connection: %v %v", got, err)
	}
}

func TestOffboardTerminatesLocalAccess(t *testing.T) {
	f := newFixture(t)
	b := new(browser)
	client := f.register(t)
	v, _ := f.oauthForm(t, b, client)
	first := f.connect(t, b, client, "handle", v)
	who := f.principal(t, first.Access)

	// Hold an unredeemed code across offboarding and reinstatement.
	v, _ = f.oauthForm(t, b, client)
	v.Set("mode", "connect")
	approval := f.post(b, prefix+"/login", v)
	want(t, approval, 303)
	approved, err := url.Parse(approval.Header().Get("Location"))
	if err != nil || approved.Query().Get("code") == "" {
		t.Fatal("missing pending code", err)
	}

	// A second account uses the same OAuth client.
	other := new(browser)
	entry := f.startClient(t, other, client)
	back := f.provider.callback(t, entry.Header().Get("Location"), "other-person", nil)
	location := f.req(other, "GET", back, "", "", nil).Header().Get("Location")
	fields := form(t, f.req(other, "GET", location, "", "", nil))
	fields.Set("mode", "handle")
	fields.Set("handle", "other")
	res := f.post(other, prefix+"/login", fields)
	want(t, res, 303)
	fields = form(t, f.req(other, "GET", res.Header().Get("Location"), "", "", nil))
	otherTokens := f.connect(t, other, client, "connect", fields)

	for range 2 {
		if err := SetAccountAccess(t.Context(), f.db, "@KATYA", false); err != nil {
			t.Fatal(err)
		}
	}
	f.principal(t, otherTokens.Access)
	want(t, f.req(other, "GET", prefix+"/connections", "", "", nil), 200)
	want(t, f.req(nil, "GET", prefix+"/mcp", "", "", http.Header{"Authorization": {"Bearer " + first.Access}}), 401)
	want(t, f.post(nil, prefix+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {first.Refresh}}), 400)
	if active, err := f.svc.GrantActive(t.Context(), who.Subject, who.Grant); err != nil || active {
		t.Fatalf("disabled account can still receive notifications: %v %v", active, err)
	}
	res = f.req(b, "GET", prefix+"/connections", "", "", nil)
	want(t, res, 303)
	back = f.provider.callback(t, res.Header().Get("Location"), "katya-account", nil)
	want(t, f.req(b, "GET", back, "", "", nil), 403)
	if err := SetAccountAccess(t.Context(), f.db, "@katya", true); err != nil {
		t.Fatal(err)
	}
	staleCode := f.post(nil, prefix+"/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "redirect_uri": {callback}, "code": {approved.Query().Get("code")}, "code_verifier": {verifier}})
	want(t, staleCode, http.StatusBadRequest)
	var rejection struct{ Error string }
	if err := json.Unmarshal(staleCode.Body.Bytes(), &rejection); err != nil || rejection.Error != "invalid_grant" {
		t.Fatalf("unexpected OAuth rejection for an offboarded code: %q %v", rejection.Error, err)
	}
	want(t, f.req(nil, "GET", prefix+"/mcp", "", "", http.Header{"Authorization": {"Bearer " + first.Access}}), 401)
	want(t, f.post(nil, prefix+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {first.Refresh}}), 400)
	if active, err := f.svc.GrantActive(t.Context(), who.Subject, who.Grant); err != nil || active {
		t.Fatalf("reinstatement restored old notifications: %v %v", active, err)
	}
	v, _ = f.oauthForm(t, b, client)
	fresh := f.connect(t, b, client, "connect", v)
	person := f.principal(t, fresh.Access)
	if person.Subject != who.Subject {
		t.Fatal("reinstated account lost its inbox")
	}
	available, err := f.svc.Connections(t.Context(), who.Subject)
	if err != nil || len(available) != 1 || available[0].ID != person.Grant {
		t.Fatalf("expected only a fresh connection: %v %v", available, err)
	}
}
