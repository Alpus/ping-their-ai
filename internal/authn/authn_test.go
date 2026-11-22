package authn

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

type fixture struct {
	svc      *Service
	mux      *http.ServeMux
	db       *sql.DB
	dir      string
	provider *mockIDP
}

const testOrigin = "https://example.test"
const prefix = "/ping"
const verifier = "test-verifier-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const callback = "http://localhost:49111/callback"

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return fixtureWithProvider(t, newMockIDP(t))
}
func fixtureWithProvider(t *testing.T, provider *mockIDP) *fixture {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "test.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	f := &fixture{dir: dir, db: db, provider: provider}
	f.open(t)
	t.Cleanup(func() { f.svc.Close(); db.Close() })
	return f
}
func (f *fixture) grantActive(t *testing.T, subject, grant string) bool {
	t.Helper()
	active, err := f.svc.GrantActive(t.Context(), subject, grant)
	if err != nil {
		t.Fatal(err)
	}
	return active
}

func (f *fixture) open(t *testing.T) {
	t.Helper()
	var err error
	f.svc, err = Open(t.Context(), f.db, testOrigin+prefix, f.dir)
	if err != nil {
		t.Fatal(err)
	}
	f.mux = http.NewServeMux()
	f.svc.Routes(f.mux)
	f.mux.Handle(prefix+"/mcp", f.svc.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := FromContext(r.Context())
		_ = json.NewEncoder(w).Encode(p)
	})))
	profile := func(w http.ResponseWriter, r *http.Request) {
		v, ok := f.svc.Browser(w, r)
		if ok {
			_ = json.NewEncoder(w).Encode(v)
		}
	}
	f.mux.HandleFunc("GET "+prefix+"/approve/{key}", profile)
	f.mux.HandleFunc("GET "+prefix+"/messages/{id}", profile)
	f.mux.HandleFunc("GET "+prefix+"/connections", profile)
}

type browser struct{ cookie *http.Cookie }

func (f *fixture) req(b *browser, method, path, body, kind string, head http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if kind != "" {
		r.Header.Set("Content-Type", kind)
	}
	for k, vs := range head {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	if b != nil && b.cookie != nil {
		r.AddCookie(b.cookie)
	}
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	if b != nil {
		for _, c := range w.Result().Cookies() {
			if c.Name == sessionCookie {
				b.cookie = c
			}
		}
	}
	return w
}
func want(t *testing.T, w *httptest.ResponseRecorder, code int) {
	t.Helper()
	if w.Code != code {
		t.Fatalf("status %v, want %v; body %q", w.Code, code, w.Body.String())
	}
}
func (f *fixture) post(b *browser, path string, v url.Values) *httptest.ResponseRecorder {
	return f.req(b, "POST", path, v.Encode(), "application/x-www-form-urlencoded", nil)
}
func (f *fixture) register(t *testing.T) string {
	t.Helper()
	w := f.req(nil, "POST", prefix+"/oauth/register", `{"client_name":"ChatGPT","redirect_uris":["http://localhost:49111/callback"],"token_endpoint_auth_method":"none"}`, "application/json", nil)
	want(t, w, 201)
	var data struct {
		ID string `json:"client_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil || data.ID == "" {
		t.Fatal("no public client ID", err)
	}
	return data.ID
}

var fieldName = regexp.MustCompile(`name="(csrf|flow)" value="([^"]+)"`)

func form(t *testing.T, w *httptest.ResponseRecorder) url.Values {
	t.Helper()
	if w.Header().Get("Referrer-Policy") != "strict-origin" {
		t.Fatal("browser forms need a same-origin Origin without sharing their request path")
	}
	want(t, w, 200)
	v := url.Values{}
	for _, m := range fieldName.FindAllStringSubmatch(w.Body.String(), -1) {
		v.Set(m[1], m[2])
	}
	if v.Get("csrf") == "" || v.Get("flow") == "" {
		t.Fatal("missing form fields")
	}
	return v
}
func (f *fixture) startClient(t *testing.T, b *browser, client string) *httptest.ResponseRecorder {
	t.Helper()
	sum := sha256.Sum256([]byte(verifier))
	params := url.Values{"client_id": {client}, "redirect_uri": {callback}, "response_type": {"code"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "state": {"original"}, "scope": {"messages"}, "resource": {testOrigin + prefix + "/mcp"}}
	w := f.req(b, "GET", prefix+"/oauth/authorize?"+params.Encode(), "", "", nil)
	want(t, w, 303)
	return w
}

func (f *fixture) oauthForm(t *testing.T, b *browser, client string) (url.Values, string) {
	t.Helper()
	w := f.startClient(t, b, client)
	if strings.HasPrefix(w.Header().Get("Location"), f.provider.server.URL+"/authorize") {
		w = f.req(b, "GET", f.provider.callback(t, w.Header().Get("Location"), "katya-account", nil), "", "", nil)
		want(t, w, 303)
	}
	w = f.req(b, "GET", w.Header().Get("Location"), "", "", nil)
	return form(t, w), w.Body.String()
}

type tokens struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
}

func (f *fixture) token(t *testing.T, v url.Values) tokens {
	t.Helper()
	w := f.post(nil, prefix+"/oauth/token", v)
	want(t, w, 200)
	var tok tokens
	if err := json.Unmarshal(w.Body.Bytes(), &tok); err != nil || tok.Access == "" || tok.Refresh == "" {
		t.Fatal("token response", err)
	}
	return tok
}
func (f *fixture) connect(t *testing.T, b *browser, client, mode string, v url.Values) tokens {
	t.Helper()
	v.Set("mode", mode)
	v.Set("handle", "@KATYA")
	res := f.post(b, prefix+"/login", v)
	want(t, res, 303)
	if mode == "handle" {
		if !strings.HasPrefix(res.Header().Get("Location"), prefix+"/login?flow=") {
			t.Fatal("creating a profile must lead to a separate connection decision")
		}
		page := f.req(b, "GET", res.Header().Get("Location"), "", "", nil)
		v = form(t, page)
		if !strings.Contains(page.Body.String(), "localhost:49111") || strings.Contains(page.Body.String(), "ChatGPT") {
			t.Fatal("client identity must come from the callback")
		}
		v.Set("mode", "connect")
		res = f.post(b, prefix+"/login", v)
		want(t, res, 303)
	}
	u, err := url.Parse(res.Header().Get("Location"))
	if err != nil || u.Scheme+"://"+u.Host+u.Path != callback || u.Query().Get("state") != "original" {
		t.Fatal("unexpected OAuth return")
	}
	code := u.Query().Get("code")
	return f.token(t, url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "redirect_uri": {callback}, "code": {code}, "code_verifier": {verifier}})
}
func (f *fixture) principal(t *testing.T, bearer string) Principal {
	t.Helper()
	res := f.req(nil, "GET", prefix+"/mcp", "", "", http.Header{"Authorization": {"Bearer " + bearer}})
	want(t, res, 200)
	var p Principal
	if err := json.Unmarshal(res.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTwoClientsSameInboxSeparateGrantsAndRestart(t *testing.T) {
	f := newFixture(t)
	b1, b2 := new(browser), new(browser)
	ch := f.req(nil, "GET", prefix+"/mcp", "", "", nil)
	want(t, ch, 401)
	if ch.Header().Get("WWW-Authenticate") != `Bearer resource_metadata="https://example.test/.well-known/oauth-protected-resource/ping/mcp"` {
		t.Fatal("bad discovery challenge")
	}
	resource := f.req(nil, "GET", "/.well-known/oauth-protected-resource/ping/mcp", "", "", nil)
	want(t, resource, 200)
	metadata := f.req(nil, "GET", "/.well-known/oauth-authorization-server", "", "", nil)
	want(t, metadata, 200)
	if !strings.Contains(metadata.Body.String(), testOrigin+prefix+"/oauth/token") || !strings.Contains(resource.Body.String(), testOrigin+prefix+"/mcp") {
		t.Fatal("wrong prefix")
	}
	client1 := f.register(t)
	v, html := f.oauthForm(t, b1, client1)
	if !strings.Contains(html, "Create profile") || strings.Contains(html, "can send as you") || strings.Contains(html, "Log In</a>") {
		t.Fatal("handle setup should only create the Ping profile")
	}
	first := f.connect(t, b1, client1, "handle", v)
	p1 := f.principal(t, first.Access)
	if p1.Handle != "katya" || p1.Grant == "" || p1.Subject == "katya" || !f.grantActive(t, p1.Subject, p1.Grant) {
		t.Fatalf("unexpected identity %+v", p1)
	}
	if b1.cookie.Path != prefix || !b1.cookie.HttpOnly || !b1.cookie.Secure || b1.cookie.Domain != "" || b1.cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("unexpected browser cookie")
	}
	client2 := f.register(t)
	v, _ = f.oauthForm(t, b2, client2)
	second := f.connect(t, b2, client2, "connect", v)
	p2 := f.principal(t, second.Access)
	if p1.Subject != p2.Subject || p1.Grant == p2.Grant || p2.Client != "http://localhost:49111" {
		t.Fatal("second connection identity")
	}
	v, html = f.oauthForm(t, b1, client1)
	if !strings.Contains(html, "Connect as @katya") || strings.Contains(html, `name="password"`) {
		t.Fatal("logged-in session requires one explicit connect without password")
	}
	v.Set("mode", "cancel")
	res := f.post(b1, prefix+"/login", v)
	want(t, res, 303)
	if !strings.Contains(res.Header().Get("Location"), "error=access_denied") {
		t.Fatal("cancel must deny")
	}
	want(t, f.post(b1, prefix+"/login", v), 410)
	if err := f.svc.Close(); err != nil {
		t.Fatal(err)
	}
	f.open(t)
	refreshed := f.token(t, url.Values{"grant_type": {"refresh_token"}, "client_id": {client1}, "refresh_token": {first.Refresh}})
	if p := f.principal(t, refreshed.Access); p != p1 {
		t.Fatal("lost identity after restart/refresh")
	}
	want(t, f.post(nil, prefix+"/oauth/revoke", url.Values{"client_id": {client1}, "token": {refreshed.Refresh}}), 200)
	if f.grantActive(t, p1.Subject, p1.Grant) || !f.grantActive(t, p2.Subject, p2.Grant) {
		t.Fatal("revocation must affect one connection only")
	}
}
func TestBrowserLoginReturnsToOriginalMessage(t *testing.T) {
	for _, path := range []string{prefix + "/approve/one-message", prefix + "/messages/one-message"} {
		t.Run(path, func(t *testing.T) {
			f := newFixture(t)
			original := new(browser)
			client := f.register(t)
			v, _ := f.oauthForm(t, original, client)
			f.connect(t, original, client, "handle", v)
			b := new(browser)
			res := f.req(b, "GET", path, "", "", nil)
			want(t, res, 303)
			back := f.provider.callback(t, res.Header().Get("Location"), "katya-account", nil)
			want(t, f.req(new(browser), "GET", back, "", "", nil), 410)
			res = f.req(b, "GET", back, "", "", nil)
			want(t, res, 303)
			want(t, f.req(b, "GET", back, "", "", nil), 410)
			res = f.req(b, "GET", res.Header().Get("Location"), "", "", nil)
			want(t, res, 303)
			if res.Header().Get("Location") != path {
				t.Fatal("lost original read request")
			}
			res = f.req(b, "GET", res.Header().Get("Location"), "", "", nil)
			want(t, res, 200)
			var s BrowserSession
			if err := json.Unmarshal(res.Body.Bytes(), &s); err != nil || s.Handle != "katya" {
				t.Fatal("wrong browser owner")
			}
			want(t, f.post(b, prefix+"/logout", url.Values{"csrf": {"not-a-csrf-token"}}), 403)
			want(t, f.post(b, prefix+"/logout", url.Values{"csrf": {s.CSRF}}), 303)
			want(t, f.req(b, "GET", path, "", "", nil), 303)
		})
	}
}
func TestUnprefixedDevelopmentOrigin(t *testing.T) {
	f := newFixture(t)
	if err := f.svc.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	const local = "http://127.0.0.1:3009"
	f.svc, err = Open(t.Context(), f.db, local, f.dir)
	if err != nil {
		t.Fatal(err)
	}
	f.mux = http.NewServeMux()
	f.svc.Routes(f.mux)
	for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource/mcp"} {
		want(t, f.req(nil, "GET", path, "", "", nil), 200)
	}
	meta := f.req(nil, "GET", "/.well-known/oauth-authorization-server", "", "", nil)
	if !strings.Contains(meta.Body.String(), local+"/oauth/authorize") {
		t.Fatal("lost unprefixed issuer")
	}
	var b browser
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/account", nil)
	f.svc.Browser(w, r)
	want(t, w, 303)
	b.cookie = w.Result().Cookies()[0]
	if b.cookie.Secure || b.cookie.Path != "/" || b.cookie.Domain != "" {
		t.Fatal("wrong dev cookie scope")
	}
}

func TestConsentCannotFinishAfterSessionEnded(t *testing.T) {
	f := newFixture(t)
	b := new(browser)
	client := f.register(t)
	v, _ := f.oauthForm(t, b, client)
	f.connect(t, b, client, "handle", v)
	v, _ = f.oauthForm(t, b, client)
	r := httptest.NewRequest("GET", "/ping/account", nil)
	r.AddCookie(b.cookie)
	sess, err := f.svc.session(r)
	if err != nil {
		t.Fatal(err)
	}
	want(t, f.post(b, prefix+"/logout", url.Values{"csrf": {sess.CSRF}}), 303)
	w := httptest.NewRecorder()
	flow, err := f.svc.loadFlow(t.Context(), v.Get("flow"), sess.id)
	if err != nil {
		t.Fatal(err)
	}
	f.svc.finish(w, r, v.Get("flow"), flow, sess, false)
	want(t, w, 410)
}

func TestLimiterTrustsPrivateUnixProxy(t *testing.T) {
	f := newFixture(t)
	handler := f.svc.limited("test", 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	hit := func(client string, unix bool) int {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "198.51.100.20:58000"
		r.Header.Set("X-Forwarded-For", client)
		if unix {
			r.RemoteAddr = "@"
			r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.UnixAddr{Name: "pilot.sock", Net: "unix"}))
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	if hit("192.0.2.1", true) != 204 || hit("192.0.2.2", true) != 204 || hit("192.0.2.2", true) != 429 {
		t.Fatal("Unix proxy rate limits must be per client")
	}
	if hit("192.0.2.3", false) != 204 || hit("192.0.2.4", false) != 429 {
		t.Fatal("public TCP client must not supply its own rate limit key")
	}
}

func TestCreateProfileThenCancelClient(t *testing.T) {
	f := newFixture(t)
	b := new(browser)
	client := f.register(t)
	v, _ := f.oauthForm(t, b, client)
	originalCSRF := v.Get("csrf")
	v.Set("mode", "handle")
	v.Set("handle", "katya")
	step := f.post(b, prefix+"/login", v)
	want(t, step, 303)
	consent := step.Header().Get("Location")
	if !strings.HasPrefix(consent, prefix+"/login?flow=") {
		t.Fatal("profile creation returned externally")
	}
	profile := func() {
		t.Helper()
		w := f.req(b, "GET", prefix+"/connections", "", "", nil)
		want(t, w, 200)
		var session BrowserSession
		if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil || session.Handle != "katya" || session.CSRF == originalCSRF {
			t.Fatal("profile identity was not established before authorizing the client")
		}
	}
	profile()
	for i := 0; i < 2; i++ {
		w := f.req(b, "GET", consent, "", "", nil)
		v = form(t, w)
		if !strings.Contains(w.Body.String(), `href="/ping/connections">Profile</a>`) || !strings.Contains(w.Body.String(), "Connect as @katya") {
			t.Fatal("consent must show signed-in Ping profile and require an explicit connection decision")
		}
	}
	v.Set("mode", "cancel")
	w := f.post(b, prefix+"/login", v)
	want(t, w, 303)
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil || u.Scheme+"://"+u.Host+u.Path != callback || u.Query().Get("state") != "original" || u.Query().Get("error") != "access_denied" || u.Query().Has("code") {
		t.Fatal("wrong cancellation return")
	}
	stale := f.req(b, "GET", consent, "", "", nil)
	want(t, stale, 410)
	if !strings.Contains(stale.Body.String(), "Sign-in link expired") || !strings.Contains(stale.Body.String(), `href="/ping/connections">Open Ping profile</a>`) {
		t.Fatal("missing local recovery")
	}
	v.Set("mode", "connect")
	want(t, f.post(b, prefix+"/login", v), 410)
	profile()
	retry := f.startClient(t, b, client)
	v = form(t, f.req(b, "GET", retry.Header().Get("Location"), "", "", nil))
	if p := f.principal(t, f.connect(t, b, client, "connect", v).Access); p.Handle != "katya" {
		t.Fatal("fresh independent consent failed")
	}
}

func TestWebsiteSignupAndReturnToProfile(t *testing.T) {
	f := newFixture(t)
	b := new(browser)
	path := prefix + "/connections"
	w := f.req(b, "GET", path, "", "", nil)
	back := f.provider.callback(t, w.Header().Get("Location"), "web-account", nil)
	w = f.req(b, "GET", back, "", "", nil)
	page := f.req(b, "GET", w.Header().Get("Location"), "", "", nil)
	v := form(t, page)
	v.Set("handle", "hello")
	v.Set("mode", "handle")
	w = f.post(b, prefix+"/login", v)
	want(t, w, 303)
	if w.Header().Get("Location") != path {
		t.Fatal("website signup must return to Ping profile")
	}
	w = f.req(b, "GET", path, "", "", nil)
	want(t, w, 200)
	var profile BrowserSession
	if err := json.Unmarshal(w.Body.Bytes(), &profile); err != nil || profile.Handle != "hello" {
		t.Fatal("missing new profile")
	}
	logout := f.post(b, prefix+"/logout", url.Values{"csrf": {profile.CSRF}})
	want(t, logout, 303)
	if logout.Header().Get("Location") != prefix+"/" {
		t.Fatal("logout left Ping")
	}
	w = f.req(b, "GET", path, "", "", nil)
	back = f.provider.callback(t, w.Header().Get("Location"), "web-account", nil)
	w = f.req(b, "GET", back, "", "", nil)
	w = f.req(b, "GET", w.Header().Get("Location"), "", "", nil)
	want(t, w, 303)
	if w.Header().Get("Location") != path {
		t.Fatal("returning website sign-in must return to Ping profile")
	}
	want(t, f.req(b, "GET", path, "", "", nil), 200)
}

func TestHandleInputKeepsFullAddress(t *testing.T) {
	f := newFixture(t)
	b := new(browser)
	upstream := f.req(b, "GET", prefix+"/connections", "", "", nil)
	back := f.provider.callback(t, upstream.Header().Get("Location"), "owner", nil)
	redirect := f.req(b, "GET", back, "", "", nil)
	page := f.req(b, "GET", redirect.Header().Get("Location"), "", "", nil)
	v := form(t, page)
	if strings.Contains(page.Body.String(), "maxlength=") {
		t.Fatal("handle input must let the server validate the complete address")
	}
	v.Set("mode", "handle")
	for _, example := range []string{"handle", "@handle", "  @HaNdLe  "} {
		v.Set("handle", example)
		w := f.post(b, prefix+"/login", v)
		want(t, w, http.StatusConflict)
		if !strings.Contains(w.Body.String(), "@handle is reserved for examples.") {
			t.Fatal("expected reserved handle feedback")
		}
	}
	max := strings.Repeat("x", 32)
	for _, value := range []string{max + "y", "@" + max + "y"} {
		v.Set("handle", value)
		w := f.post(b, prefix+"/login", v)
		want(t, w, 400)
		if !strings.Contains(w.Body.String(), max+"y") || !strings.Contains(w.Body.String(), "Use 3–32") {
			t.Fatal("show the full invalid handle and how to correct it")
		}
	}
	v.Set("handle", "@"+max)
	want(t, f.post(b, prefix+"/login", v), 303)
	w := f.req(b, "GET", prefix+"/connections", "", "", nil)
	want(t, w, 200)
	var profile BrowserSession
	if err := json.Unmarshal(w.Body.Bytes(), &profile); err != nil || profile.Handle != max {
		t.Fatal("the full 32-letter handle must be saved")
	}
}

func TestProfileTabsReopenWithCurrentBrowserIdentity(t *testing.T) {
	f := newFixture(t)
	b := new(browser)
	client := f.register(t)
	v, _ := f.oauthForm(t, b, client)
	f.connect(t, b, client, "handle", v)
	profile := prefix + "/connections"
	var owner BrowserSession
	if err := json.Unmarshal(f.req(b, "GET", profile, "", "", nil).Body.Bytes(), &owner); err != nil {
		t.Fatal(err)
	}
	want(t, f.post(b, prefix+"/logout", url.Values{"csrf": {owner.CSRF}}), 303)

	get := func(b *browser, path string) *httptest.ResponseRecorder {
		return f.req(b, "GET", path, "", "", nil)
	}
	begin := func(b *browser, subject string) string {
		return f.provider.callback(t, get(b, profile).Header().Get("Location"), subject, nil)
	}
	reopened := func(res *httptest.ResponseRecorder) {
		t.Helper()
		want(t, res, 303)
		if res.Header().Get("Location") != profile || len(res.Result().Cookies()) != 0 {
			t.Fatal("a stale profile tab may only redirect to the fixed profile URL")
		}
	}

	// Both tabs opened before the first anonymous Set-Cookie reached the browser.
	displaced := begin(new(browser), "other-account")
	active := begin(b, "katya-account")
	reopened(get(b, displaced))
	if w := get(b, profile); !strings.HasPrefix(w.Header().Get("Location"), f.provider.server.URL+"/authorize?") {
		t.Fatal("an anonymous browser must still complete its own sign-in")
	}
	// Another pair of tabs shares the anonymous cookie. One tab reaches /login first.
	pending := begin(b, "other-account")
	intermediate := get(b, begin(b, "other-account")).Header().Get("Location")
	other := new(browser)
	pendingClient := f.startClient(t, other, client)
	clientBack := f.provider.callback(t, pendingClient.Header().Get("Location"), "other-account", nil)
	pendingRead := get(other, prefix+"/approve/test")
	readBack := f.provider.callback(t, pendingRead.Header().Get("Location"), "other-account", nil)
	ownLogin := get(b, active)
	reopenedProfile := get(b, ownLogin.Header().Get("Location"))
	want(t, reopenedProfile, 303)
	if reopenedProfile.Header().Get("Location") != profile {
		t.Fatal("the returning owner must reach their profile")
	}
	for _, path := range []string{displaced, pending, intermediate} {
		reopened(get(b, path))
	}
	// Neither a stale OAuth decision nor a message approval may be recovered this way.
	want(t, get(b, clientBack), 410)
	want(t, get(b, readBack), 410)
	urlCopy, err := url.Parse(displaced)
	if err != nil {
		t.Fatal(err)
	}
	query := urlCopy.Query()
	key, _, _ := strings.Cut(query.Get("state"), ".")
	query.Set("state", key+"."+opaque())
	urlCopy.RawQuery = query.Encode()
	want(t, get(b, urlCopy.String()), 410)
	if _, err := f.db.Exec("UPDATE auth_flows SET expires=0 WHERE token=?", digest(key)); err != nil {
		t.Fatal(err)
	}
	want(t, get(b, displaced), 410)
	var current BrowserSession
	page := get(b, profile)
	want(t, page, 200)
	if err := json.Unmarshal(page.Body.Bytes(), &current); err != nil || current.Subject != owner.Subject || current.Handle != owner.Handle {
		t.Fatal("a different tab's callback must never replace the current identity")
	}
}

func TestProviderDenialReturnsOnceToOriginatingSurface(t *testing.T) {
	for _, clientFlow := range []bool{false, true} {
		f := newFixture(t)
		b := new(browser)
		var start *httptest.ResponseRecorder
		if clientFlow {
			start = f.startClient(t, b, f.register(t))
		} else {
			start = f.req(b, "GET", prefix+"/connections", "", "", nil)
		}
		provider, err := url.Parse(start.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		state := provider.Query().Get("state")
		denied := prefix + "/auth/callback?" + url.Values{"state": {state}, "error": {"access_denied"}}.Encode()
		want(t, f.req(new(browser), "GET", denied, "", "", nil), 410)
		w := f.req(b, "GET", denied, "", "", nil)
		want(t, w, 303)
		if clientFlow {
			u, err := url.Parse(w.Header().Get("Location"))
			if err != nil || u.Scheme+"://"+u.Host+u.Path != callback || u.Query().Get("state") != "original" || u.Query().Get("error") != "access_denied" || u.Query().Has("code") {
				t.Fatal("wrong provider denial callback")
			}
		} else if w.Header().Get("Location") != prefix+"/" {
			t.Fatal("website cancellation must return to Ping home")
		}
		replay := f.req(b, "GET", denied, "", "", nil)
		want(t, replay, 410)
		oldKey, _, _ := strings.Cut(state, ".")
		want(t, f.req(b, "GET", prefix+"/login?flow="+oldKey, "", "", nil), 410)
	}
}

func TestGrantLookupDistinguishesMissingFromUnavailable(t *testing.T) {
	f := newFixture(t)
	subject := f.svc.identity.subjectPrefix + "account"
	if active, err := f.svc.GrantActive(t.Context(), subject, "absent"); active || err != nil {
		t.Fatalf("missing grant: active=%t err=%v", active, err)
	}
	if err := f.svc.Close(); err != nil {
		t.Fatal(err)
	}
	if active, err := f.svc.GrantActive(t.Context(), subject, "absent"); active || err == nil {
		t.Fatalf("unavailable store: active=%t err=%v", active, err)
	}
}
