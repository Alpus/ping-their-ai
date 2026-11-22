package authn

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const googleIssuer = "https://accounts.google.com"

var domainPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
var errDomain = errors.New("Google account is outside the allowed domain")

type identityProvider struct {
	allowedDomain string
	subjectPrefix string
	oauth         oauth2.Config
	verifier      *oidc.IDTokenVerifier
	client        *http.Client
}

func openProvider(ctx context.Context, base string) (*identityProvider, error) {
	domain := strings.ToLower(strings.TrimSpace(os.Getenv("GOOGLE_ALLOWED_DOMAIN")))
	if domain != "" && (len(domain) > 253 || !domainPattern.MatchString(domain) || net.ParseIP(domain) != nil) {
		return nil, errors.New("GOOGLE_ALLOWED_DOMAIN must be one domain, such as example.com")
	}
	issuer := os.Getenv("OIDC_ISSUER")
	id, secret := os.Getenv("OIDC_CLIENT_ID"), os.Getenv("OIDC_CLIENT_SECRET")
	if issuer == "" {
		issuer = googleIssuer
		id, secret = os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET")
		if id == "" || secret == "" {
			return nil, errors.New("set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET for Google sign-in")
		}
	} else if id == "" {
		return nil, errors.New("OIDC_CLIENT_ID is required with OIDC_ISSUER")
	}
	if domain != "" && issuer != googleIssuer {
		return nil, errors.New("GOOGLE_ALLOWED_DOMAIN requires direct Google sign-in")
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Scheme != "https" && !(u.Scheme == "http" && net.ParseIP(u.Hostname()).IsLoopback())) {
		return nil, errors.New("identity issuer must be HTTPS or a numeric loopback HTTP URL")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), issuer)
	if err != nil {
		return nil, errors.New("could not discover the configured sign-in provider")
	}
	endpoint := provider.Endpoint()
	if secret == "" || issuer == googleIssuer {
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	}
	scopes := []string{oidc.ScopeOpenID}
	if domain != "" {
		scopes = append(scopes, "email")
	}
	return &identityProvider{
		allowedDomain: domain,
		subjectPrefix: "oidc." + digest(issuer) + ".", client: client,
		oauth: oauth2.Config{ClientID: id, ClientSecret: secret, Endpoint: endpoint,
			RedirectURL: base + "/auth/callback", Scopes: scopes},
		verifier: provider.Verifier(&oidc.Config{ClientID: id}),
	}, nil
}

func (p *identityProvider) subject(ctx context.Context, code, nonce, verifier string) (string, error) {
	ctx = oidc.ClientContext(ctx, p.client)
	tok, err := p.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return "", err
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return "", errors.New("missing identity token")
	}
	id, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return "", err
	}
	var claims struct {
		AuthorizedParty string `json:"azp"`
	}
	if err := id.Claims(&claims); err != nil {
		return "", err
	}
	if id.Nonce != nonce || nonce == "" || id.Subject == "" ||
		((claims.AuthorizedParty != "" || len(id.Audience) > 1) && claims.AuthorizedParty != p.oauth.ClientID) {
		return "", errors.New("invalid identity token claims")
	}
	if p.allowedDomain != "" {
		var claims struct {
			Email         string          `json:"email"`
			EmailVerified json.RawMessage `json:"email_verified"`
			HostedDomain  string          `json:"hd"`
		}
		if err := id.Claims(&claims); err != nil {
			return "", err
		}
		local, domain, ok := strings.Cut(claims.Email, "@")
		verified := string(claims.EmailVerified) == "true" || string(claims.EmailVerified) == `"true"`
		gmail := p.allowedDomain == "gmail.com" && claims.HostedDomain == ""
		if !ok || local == "" || !verified || !strings.EqualFold(domain, p.allowedDomain) ||
			(!gmail && !strings.EqualFold(claims.HostedDomain, p.allowedDomain)) {
			return "", errDomain
		}
	}
	return p.subjectPrefix + digest(id.Subject), nil
}

func (s *Service) startIdentity(w http.ResponseWriter, r *http.Request, key string) {
	nonce, verifier, state := opaque(), oauth2.GenerateVerifier(), key+"."+opaque()
	_, err := s.db.ExecContext(r.Context(), `INSERT INTO auth_oidc(flow,state,nonce,verifier)
		VALUES (?,?,?,?) ON CONFLICT(flow) DO UPDATE SET state=excluded.state,nonce=excluded.nonce,
		verifier=excluded.verifier,subject='' `, digest(key), digest(state), nonce, verifier)
	if err != nil {
		serverError(w)
		return
	}
	opts := []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)}
	if domain := s.identity.allowedDomain; domain != "" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "select_account"))
		if domain != "gmail.com" {
			opts = append(opts, oauth2.SetAuthURLParam("hd", domain))
		}
	}
	dest := s.identity.oauth.AuthCodeURL(state, opts...)
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (s *Service) callback(w http.ResponseWriter, r *http.Request) {
	pageHeaders(w)
	v, err := s.session(r)
	state := r.URL.Query().Get("state")
	key, suffix, ok := strings.Cut(state, ".")
	if err != nil || !ok || len(key) != 43 || len(suffix) != 43 || v.Subject != "" {
		s.expired(w, r)
		return
	}
	ctx := r.Context()
	var nonce, verifier string
	err = s.db.QueryRowContext(ctx, `UPDATE auth_oidc SET state=NULL
		WHERE flow=? AND state=? AND EXISTS(SELECT 1 FROM auth_flows f JOIN auth_sessions s ON s.token=f.session
		WHERE f.token=flow AND f.session=? AND s.subject IS NULL AND min(f.expires,s.expires)>?)
		RETURNING nonce, verifier`, digest(key), digest(state), v.id, time.Now().Unix()).Scan(&nonce, &verifier)
	if errors.Is(err, sql.ErrNoRows) {
		s.expired(w, r)
		return
	}
	if err != nil {
		serverError(w)
		return
	}
	login := s.prefix + "/login?flow=" + url.QueryEscape(key)
	if r.URL.Query().Get("error") == "access_denied" {
		f, err := s.loadFlow(ctx, key, v.id)
		if err != nil {
			s.flowError(w, r, err)
			return
		}
		s.finish(w, r, key, f, v, true)
		return
	}
	if r.URL.Query().Get("error") != "" || r.URL.Query().Get("code") == "" {
		s.recovery(w, r, http.StatusBadRequest, "Sign-in could not finish", "Try signing in again.", login)
		return
	}
	subject, err := s.identity.subject(ctx, r.URL.Query().Get("code"), nonce, verifier)
	if errors.Is(err, errDomain) {
		s.recovery(w, r, http.StatusForbidden, "Use a different Google account", "Sign in with an @"+s.identity.allowedDomain+" account.", login)
		return
	}
	if err != nil {
		s.recovery(w, r, http.StatusUnauthorized, "Sign-in could not be verified", "Try signing in again.", login)
		return
	}
	result, err := s.db.ExecContext(ctx, `UPDATE auth_oidc SET subject=?,nonce='',verifier=''
		WHERE flow=? AND state IS NULL AND nonce=? AND EXISTS(SELECT 1 FROM auth_flows f WHERE f.token=flow AND f.session=? AND f.expires>?)
		AND NOT EXISTS(SELECT 1 FROM auth_offboarded WHERE subject=? AND disabled=1)`, subject, digest(key), nonce, v.id, time.Now().Unix(), subject)
	if err != nil {
		serverError(w)
		return
	}
	if n, _ := result.RowsAffected(); n != 1 {
		if _, err := accountCredential(ctx, s.db, subject); err != nil {
			s.flowError(w, r, err)
			return
		}
		s.expired(w, r)
		return
	}
	http.Redirect(w, r, login, http.StatusSeeOther)
}
