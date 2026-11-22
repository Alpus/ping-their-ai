package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ajent-social/go/mcpoauth"
	"github.com/ajent-social/go/mcpoauth/boltstore"
)

const schema = `
CREATE TABLE IF NOT EXISTS auth_accounts (
 subject TEXT PRIMARY KEY, handle TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS auth_sessions (
 token TEXT PRIMARY KEY, subject TEXT REFERENCES auth_accounts(subject), csrf TEXT NOT NULL, expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_sessions_expiry ON auth_sessions(expires);
CREATE TABLE IF NOT EXISTS auth_flows (
 token TEXT PRIMARY KEY, session TEXT NOT NULL, target TEXT NOT NULL,
 oauth_handle TEXT NOT NULL, client TEXT NOT NULL, expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_flows_expiry ON auth_flows(expires);
CREATE INDEX IF NOT EXISTS auth_flows_session ON auth_flows(session);
CREATE TABLE IF NOT EXISTS auth_oidc (
 flow TEXT PRIMARY KEY REFERENCES auth_flows(token) ON DELETE CASCADE,
 state TEXT UNIQUE, nonce TEXT NOT NULL, verifier TEXT NOT NULL, subject TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS auth_domain_policy (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), domain TEXT NOT NULL, version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_connections (
 id TEXT PRIMARY KEY, subject TEXT NOT NULL, expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_connections_subject ON auth_connections(subject,expires);
CREATE TABLE IF NOT EXISTS auth_offboarded (
 subject TEXT PRIMARY KEY REFERENCES auth_accounts(subject), generation TEXT NOT NULL, disabled INTEGER NOT NULL
);`

type Service struct {
	db                                  *sql.DB
	oauth                               *mcpoauth.Server
	store                               *boltstore.Store
	origin, prefix, resource, discovery string
	secure                              bool
	limits                              limits
	identity                            *identityProvider
	credentialPrefix                    string
	legacyPasswordColumn                bool
}

type Principal struct{ Subject, Grant, Handle, Client string }
type principalKey struct{}

func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

func Open(ctx context.Context, db *sql.DB, baseURL, dataDir string) (*Service, error) {
	base, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || base == nil || base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.RawPath != "" || (base.Path != "" && path.Clean(base.Path) != base.Path) {
		return nil, errors.New("invalid public base URL")
	}
	upstream, err := openProvider(ctx, strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, err
	}
	origin := base.Scheme + "://" + base.Host
	cfg := mcpoauth.Config{Issuer: origin, Resource: origin + base.Path + "/mcp", Scopes: []string{"messages"}, AllowLoopbackRedirects: true, AllowLocalhostRedirects: true,
		AuthorizePath: base.Path + "/oauth/authorize", TokenPath: base.Path + "/oauth/token", RegisterPath: base.Path + "/oauth/register", RevokePath: base.Path + "/oauth/revoke"}
	oauthDir := filepath.Join(dataDir, "oauth")
	if err := os.MkdirAll(oauthDir, 0700); err != nil {
		return nil, err
	}
	storePath := filepath.Join(oauthDir, "tokens.db")
	if _, err = db.ExecContext(ctx, schema); err != nil {
		return nil, err
	}
	if err = initializeConnections(ctx, db, storePath); err != nil {
		return nil, err
	}
	store, err := boltstore.Open(ctx, storePath)
	if err != nil {
		return nil, err
	}
	_, err = store.Sweep(ctx, time.Now())
	var legacy bool
	if err == nil {
		err = db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pragma_table_info('auth_accounts') WHERE name='password_hash')`).Scan(&legacy)
	}
	var policyVersion int
	if err == nil {
		// Keep legacy credentials on unrestricted upgrades. Each policy change
		// starts a new session/grant generation without changing inbox IDs.
		err = db.QueryRowContext(ctx, `INSERT INTO auth_domain_policy(singleton,domain,version)
			VALUES(1,?,CASE WHEN ?='' THEN 0 ELSE 1 END)
			ON CONFLICT(singleton) DO UPDATE SET version=version+(domain<>excluded.domain),domain=excluded.domain
			RETURNING version`, upstream.allowedDomain, upstream.allowedDomain).Scan(&policyVersion)
	}
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	var credentialPrefix string
	if policyVersion > 0 {
		credentialPrefix = fmt.Sprintf("policy%d.", policyVersion)
	}
	oauth, err := mcpoauth.New(cfg, &connectionsStore{Store: store, db: db, prefix: credentialPrefix})
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	return &Service{credentialPrefix: credentialPrefix, db: db, oauth: oauth, store: store, origin: origin, prefix: base.Path, resource: cfg.Resource, discovery: "/.well-known/oauth-protected-resource" + base.Path + "/mcp", secure: base.Scheme == "https", identity: upstream, legacyPasswordColumn: legacy}, nil
}
func (s *Service) Close() error { return s.store.Close() }

func (s *Service) Routes(mux *http.ServeMux) {
	mux.Handle("/.well-known/oauth-authorization-server", s.oauth.MetadataHandler())
	mux.Handle(s.discovery, s.oauth.ProtectedResourceHandler())
	mux.Handle(s.prefix+"/oauth/register", s.limited("dcr", 30, s.oauth.RegisterHandler()))
	mux.Handle(s.prefix+"/oauth/authorize", s.limited("authorize", 100, s.oauth.AuthorizeHandler(s.beginOAuth)))
	mux.Handle(s.prefix+"/oauth/token", s.oauth.TokenHandler())
	mux.Handle(s.prefix+"/oauth/revoke", s.oauth.RevokeHandler())
	mux.Handle(s.prefix+"/login", s.limited("login", 90, http.HandlerFunc(s.login)))
	mux.HandleFunc("POST "+s.prefix+"/logout", s.logout)
	mux.Handle("GET "+s.prefix+"/auth/callback", s.limited("identity", 120, http.HandlerFunc(s.callback)))
}

func (s *Service) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := mcpoauth.BearerToken(r)
		if ok {
			id, err := s.oauth.Verify(r.Context(), token)
			if err != nil && !errors.Is(err, mcpoauth.ErrDenied) {
				serverError(w)
				return
			}
			subject, currentPolicy := strings.CutPrefix(id.Subject, s.credentialPrefix)
			subject, _, _ = strings.Cut(subject, "/")
			if err == nil && currentPolicy && strings.HasPrefix(subject, s.identity.subjectPrefix) {
				var handle string
				err = s.db.QueryRowContext(r.Context(), "SELECT handle FROM auth_accounts WHERE subject=?", subject).Scan(&handle)
				if err == nil {
					p := Principal{Subject: subject, Grant: id.GrantID, Handle: handle, Client: id.Binding}
					next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
					return
				}
				if !errors.Is(err, sql.ErrNoRows) {
					serverError(w)
					return
				}
			}
		}
		challenge := fmt.Sprintf("Bearer resource_metadata=%q", s.origin+s.discovery)
		if r.Header.Get("Authorization") != "" {
			challenge += `, error="invalid_token"`
		}
		w.Header().Set("WWW-Authenticate", challenge)
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "Connect your account to continue.", http.StatusUnauthorized)
	})
}
func (s *Service) GrantActive(ctx context.Context, subject, grant string) (bool, error) {
	if !strings.HasPrefix(subject, s.identity.subjectPrefix) {
		return false, nil
	}
	g, err := s.store.Grant(ctx, grant)
	if errors.Is(err, mcpoauth.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if g.Resource != s.resource || !g.RevokedAt.IsZero() || !time.Now().Before(g.ExpiresAt) {
		return false, nil
	}
	owner, err := accountCredential(ctx, s.db, subject)
	if errors.Is(err, errOffboarded) {
		return false, nil
	}
	return err == nil && g.Subject == s.credentialPrefix+owner, err
}

var chatGPTCallback = regexp.MustCompile(`^https://chatgpt\.com/(connector_platform_oauth_redirect|connector/oauth/[a-zA-Z0-9_-]+)$`)

// The actual code destination was validated by the OAuth server. DCR display names are self-reported.
func clientLabel(callback string) string {
	switch {
	case callback == "https://claude.ai/api/mcp/auth_callback":
		return "Claude"
	case chatGPTCallback.MatchString(callback):
		return "ChatGPT"
	}
	u, err := url.Parse(callback)
	if err != nil || u.Host == "" || len(u.Host) > 240 {
		return "Custom MCP client"
	}
	return u.Scheme + "://" + u.Host
}
func opaque() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func digest(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func pageHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	// Chromium derives the form Origin from the referrer policy. Send only the origin, never a permission path.
	w.Header().Set("Referrer-Policy", "strict-origin")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
}
func serverError(w http.ResponseWriter) {
	http.Error(w, "Could not complete this request. Please try again.", http.StatusInternalServerError)
}

type limits struct {
	mu     sync.Mutex
	until  time.Time
	counts map[string]int
}

func (s *Service) limited(action string, n int, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.allow(w, r, action, n) {
			next.ServeHTTP(w, r)
		}
	})
}

func (s *Service) allow(w http.ResponseWriter, r *http.Request, action string, n int) bool {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	// Only the private Unix listener or a loopback proxy can vouch for the last forwarded hop.
	local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	addr := net.ParseIP(ip)
	if (local != nil && local.Network() == "unix") || (addr != nil && addr.IsLoopback()) {
		parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		if peer := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); peer != nil {
			ip = peer.String()
		}
	}
	key := action + ":" + ip
	l := &s.limits
	l.mu.Lock()
	if time.Now().After(l.until) {
		l.counts = make(map[string]int)
		l.until = time.Now().Add(time.Minute)
	}
	count, known := l.counts[key]
	allowed := count < n && (known || len(l.counts) < 8192)
	if allowed {
		l.counts[key] = count + 1
	}
	l.mu.Unlock()
	if !allowed {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "Too many requests. Try again in a minute.", 429)
		return false
	}
	return true
}
