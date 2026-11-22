package authn

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockCode struct {
	challenge string
	claims    map[string]any
}
type mockIDP struct {
	server *httptest.Server
	issuer string
	mu     sync.Mutex
	codes  map[string]mockCode
}

func newMockIDP(t *testing.T) *mockIDP {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &mockIDP{codes: map[string]mockCode{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		u := p.server.URL
		writeJSON(w, map[string]any{"issuer": p.issuer, "authorization_endpoint": u + "/authorize", "token_endpoint": u + "/token", "jwks_uri": u + "/keys", "id_token_signing_alg_values_supported": []string{"EdDSA"}})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"keys": []map[string]string{{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": "pilot", "x": base64.RawURLEncoding.EncodeToString(pub)}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		c, ok := p.codes[r.FormValue("code")]
		delete(p.codes, r.FormValue("code"))
		p.mu.Unlock()
		if !ok || r.FormValue("client_id") != "ping-test" || digest(r.FormValue("code_verifier")) != c.challenge || r.FormValue("redirect_uri") != testOrigin+prefix+"/auth/callback" {
			http.Error(w, "invalid code", 400)
			return
		}
		h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"pilot"}`))
		payload, _ := json.Marshal(c.claims)
		body := h + "." + base64.RawURLEncoding.EncodeToString(payload)
		signature := ed25519.Sign(private, []byte(body))
		if c.claims["bad_test_signature"] == true {
			signature[0] ^= 1
		}
		token := body + "." + base64.RawURLEncoding.EncodeToString(signature)
		writeJSON(w, map[string]any{"token_type": "Bearer", "access_token": "mock-identity-access", "id_token": token})
	})
	p.server = httptest.NewServer(mux)
	p.issuer = p.server.URL
	t.Cleanup(p.server.Close)
	t.Setenv("OIDC_ISSUER", p.server.URL)
	t.Setenv("OIDC_CLIENT_ID", "ping-test")
	t.Setenv("OIDC_CLIENT_SECRET", "")
	return p
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func (p *mockIDP) callback(t *testing.T, destination, subject string, override map[string]any) string {
	t.Helper()
	u, err := url.Parse(destination)
	if err != nil || u.Scheme+"://"+u.Host+u.Path != p.server.URL+"/authorize" {
		t.Fatalf("wrong upstream URL %v", u)
	}
	q := u.Query()
	wantScope := "openid"
	if os.Getenv("GOOGLE_ALLOWED_DOMAIN") != "" {
		wantScope = "openid email"
	}
	if q.Get("scope") != wantScope || q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("redirect_uri") != testOrigin+prefix+"/auth/callback" {
		t.Fatal("invalid provider request")
	}
	c := opaque()
	claims := map[string]any{"iss": p.issuer, "aud": "ping-test", "sub": subject, "nonce": q.Get("nonce"), "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
	for k, v := range override {
		claims[k] = v
	}
	p.mu.Lock()
	p.codes[c] = mockCode{q.Get("code_challenge"), claims}
	p.mu.Unlock()
	return prefix + "/auth/callback?" + url.Values{"state": {q.Get("state")}, "code": {c}}.Encode()
}

func TestUpstreamVerificationAndBrowserBinding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		claims map[string]any
	}{
		{"nonce", map[string]any{"nonce": "another"}},
		{"signature", map[string]any{"bad_test_signature": true}},
		{"issuer", map[string]any{"iss": "https://other.example"}},
		{"audience", map[string]any{"aud": "different"}},
		{"authorized party", map[string]any{"aud": []string{"ping-test", "other"}, "azp": "other"}},
		{"expiration", map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}},
		{"subject", map[string]any{"sub": ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			b := new(browser)
			first := f.req(b, "GET", prefix+"/approve/message-1", "", "", nil)
			back := f.provider.callback(t, first.Header().Get("Location"), "identity", tc.claims)
			want(t, f.req(new(browser), "GET", back, "", "", nil), 410)
			want(t, f.req(b, "GET", back, "", "", nil), 401)
			want(t, f.req(b, "GET", back, "", "", nil), 410)
		})
	}
}

func TestHistoricAccountCannotBeClaimedByHandle(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "legacy.sqlite")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE auth_accounts(subject TEXT PRIMARY KEY,handle TEXT UNIQUE NOT NULL,password_hash BLOB NOT NULL);
		INSERT INTO auth_accounts VALUES('old-subject','katya',x'1234')`)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{db: db, dir: dir, provider: newMockIDP(t)}
	f.open(t)
	defer f.svc.Close()
	stale := opaque()
	_, err = f.db.Exec("INSERT INTO auth_sessions(token,subject,csrf,expires) VALUES(?,'old-subject','previous',?)", digest(stale), time.Now().Add(time.Minute).Unix())
	if err != nil {
		t.Fatal(err)
	}
	b := &browser{cookie: &http.Cookie{Name: sessionCookie, Value: stale}}
	client := f.register(t)
	v, _ := f.oauthForm(t, b, client)
	v.Set("mode", "handle")
	v.Set("handle", "katya")
	res := f.post(b, prefix+"/login", v)
	want(t, res, 409)
	v.Set("handle", "fresh")
	res = f.post(b, prefix+"/login", v)
	want(t, res, 303)
	page := f.req(b, "GET", res.Header().Get("Location"), "", "", nil)
	v = form(t, page)
	if !strings.Contains(page.Body.String(), "Connect as @fresh") {
		t.Fatal("fresh handle was not established before consent")
	}
	v.Set("mode", "connect")
	res = f.post(b, prefix+"/login", v)
	if !strings.HasPrefix(res.Header().Get("Location"), callback+"?") {
		t.Fatal("no new authorization code")
	}
}

type localGoogleDiscovery struct {
	http.RoundTripper
	origin *url.URL
}

func (d localGoogleDiscovery) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host == "accounts.google.com" {
		r = r.Clone(r.Context())
		r.URL.Host, r.URL.Scheme = d.origin.Host, d.origin.Scheme
	}
	return d.RoundTripper.RoundTrip(r)
}

func newGoogleFixture(t *testing.T) *fixture {
	t.Helper()
	p := newMockIDP(t)
	p.issuer = googleIssuer
	origin, err := url.Parse(p.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	original := http.DefaultTransport
	http.DefaultTransport = localGoogleDiscovery{original, origin}
	t.Cleanup(func() { http.DefaultTransport = original })
	t.Setenv("OIDC_ISSUER", "")
	t.Setenv("GOOGLE_CLIENT_ID", "ping-test")
	t.Setenv("GOOGLE_CLIENT_SECRET", "local-only")
	return fixtureWithProvider(t, p)
}

func TestGoogleDomainAdmission(t *testing.T) {
	for _, tc := range []struct {
		name, domain, email, hosted string
		verified                    any
		want                        int
	}{
		{"exact", "example.com", "person@example.com", "example.com", true, 303},
		{"case", "EXAMPLE.com", "Person@Example.Com", "Example.Com", "true", 303},
		{"external address", "example.com", "person@example.com", "", true, 403},
		{"unverified address", "example.com", "person@example.com", "example.com", false, 403},
		{"missing email", "example.com", "", "example.com", true, 403},
		{"subdomain", "example.com", "person@sub.example.com", "sub.example.com", true, 403},
		{"wrong organization", "example.com", "person@example.com", "other.test", true, 403},
		{"wrong address", "example.com", "person@other.test", "example.com", true, 403},
		{"Gmail", "gmail.com", "person@gmail.com", "", true, 303},
		{"Gmail restriction", "gmail.com", "person@other.test", "", true, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GOOGLE_ALLOWED_DOMAIN", tc.domain)
			f := newGoogleFixture(t)
			b := new(browser)
			login := f.req(b, "GET", prefix+"/connections", "", "", nil).Header().Get("Location")
			u, err := url.Parse(login)
			if err != nil {
				t.Fatal(err)
			}
			hint := strings.ToLower(tc.domain)
			if hint == "gmail.com" {
				hint = ""
			}
			if u.Query().Get("prompt") != "select_account" || u.Query().Get("scope") != "openid email" || u.Query().Get("hd") != hint {
				t.Fatal("wrong account chooser settings")
			}
			claims := map[string]any{"email": tc.email, "email_verified": tc.verified}
			if tc.hosted != "" {
				claims["hd"] = tc.hosted
			}
			page := f.req(b, "GET", f.provider.callback(t, login, "new-user", claims), "", "", nil)
			want(t, page, tc.want)
			if tc.want == 403 && !strings.Contains(page.Body.String(), "@"+strings.ToLower(tc.domain)+" account") {
				t.Fatal("missing sign-in recovery")
			}
		})
	}
}

func TestChangingGoogleDomainKeepsInboxAndExpiresCredentials(t *testing.T) {
	t.Setenv("GOOGLE_ALLOWED_DOMAIN", "")
	f := newGoogleFixture(t)
	restart := func(domain string) {
		t.Helper()
		if err := f.svc.Close(); err != nil {
			t.Fatal(err)
		}
		t.Setenv("GOOGLE_ALLOWED_DOMAIN", domain)
		f.open(t)
	}
	b := new(browser)
	client := f.register(t)
	v, _ := f.oauthForm(t, b, client)
	original := f.connect(t, b, client, "handle", v)
	person := f.principal(t, original.Access)
	if !f.grantActive(t, person.Subject, person.Grant) {
		t.Fatal("original grant unavailable")
	}
	oldBrowser := *b
	otherClient := f.register(t)
	pending := new(browser)
	before := f.startClient(t, pending, otherClient)
	back := f.provider.callback(t, before.Header().Get("Location"), "another-user", nil)
	verifiedForm := f.req(pending, "GET", back, "", "", nil).Header().Get("Location")

	restart("example.com")
	want(t, f.req(b, "GET", prefix+"/connections", "", "", nil), 303)
	want(t, f.req(pending, "GET", verifiedForm, "", "", nil), 410)
	denied := func(token string) {
		t.Helper()
		want(t, f.req(nil, "GET", prefix+"/mcp", "", "", http.Header{"Authorization": {"Bearer " + token}}), 401)
	}
	denied(original.Access)
	oldRefresh := f.token(t, url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {original.Refresh}})
	denied(oldRefresh.Access)
	if f.grantActive(t, person.Subject, person.Grant) {
		t.Fatal("old event grant active")
	}

	// Following the normal client entry point must return the same inbox after domain verification.
	entry := f.startClient(t, b, client).Header().Get("Location")
	back = f.provider.callback(t, entry, "katya-account", map[string]any{"email": "katya@example.com", "email_verified": true, "hd": "example.com"})
	page := f.req(b, "GET", back, "", "", nil)
	want(t, page, 303)
	v = form(t, f.req(b, "GET", page.Header().Get("Location"), "", "", nil))
	allowed := f.connect(t, b, client, "connect", v)
	current := f.principal(t, allowed.Access)
	if person.Subject != current.Subject || person.Handle != current.Handle || person.Grant == current.Grant {
		t.Fatal("lost account identity or reused previous grant")
	}

	restart("EXAMPLE.COM")
	want(t, f.req(b, "GET", prefix+"/connections", "", "", nil), 200)
	f.principal(t, allowed.Access)
	if !f.grantActive(t, current.Subject, current.Grant) {
		t.Fatal("unchanged policy lost its grant")
	}
	restart("other.test")
	denied(allowed.Access)
	if f.grantActive(t, current.Subject, current.Grant) {
		t.Fatal("changed policy retained events")
	}
	restart("")
	denied(original.Access)
	want(t, f.req(&oldBrowser, "GET", prefix+"/connections", "", "", nil), 303)
	restart("example.com")
	denied(allowed.Access)
}

func TestInvalidGoogleDomainConfiguration(t *testing.T) {
	t.Setenv("GOOGLE_CLIENT_ID", "local")
	t.Setenv("GOOGLE_CLIENT_SECRET", "local")
	for _, invalid := range []string{"*.example.com", "@example.com", "https://example.com", "foo,bar", "127.0.0.1", "example..com"} {
		t.Setenv("GOOGLE_ALLOWED_DOMAIN", invalid)
		if _, err := openProvider(t.Context(), testOrigin); err == nil || !strings.Contains(err.Error(), "GOOGLE_ALLOWED_DOMAIN") {
			t.Fatalf("invalid domain accepted %q", invalid)
		}
	}
	t.Setenv("GOOGLE_ALLOWED_DOMAIN", "example.com")
	t.Setenv("OIDC_ISSUER", "https://other.test")
	t.Setenv("OIDC_CLIENT_ID", "local")
	if _, err := openProvider(t.Context(), testOrigin); err == nil || !strings.Contains(err.Error(), "direct Google") {
		t.Fatal("unrelated OIDC issuer accepted")
	}
}
