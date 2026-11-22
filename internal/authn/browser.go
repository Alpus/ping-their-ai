package authn

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ajent-social/go/mcpoauth"
)

const sessionCookie = "ping_their_ai_session"
const loginLife = 30 * 24 * time.Hour

var errFlow = errors.New("invalid or expired connection request")
var errHandleTaken = errors.New("that handle is already in use")
var handlePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{2,31}$`)

type BrowserSession struct{ Subject, Handle, CSRF string }
type session struct {
	BrowserSession
	id string
}
type flow struct{ target, oauthHandle, client, verified string }

func (s *Service) cookie(w http.ResponseWriter, value string, age int) {
	p := s.prefix
	if p == "" {
		p = "/"
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: value, Path: p, MaxAge: age, HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteLaxMode})
}
func (s *Service) session(r *http.Request) (session, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || len(c.Value) != 43 {
		return session{}, sql.ErrNoRows
	}
	v := session{id: digest(s.credentialPrefix + c.Value)}
	err = s.db.QueryRowContext(r.Context(), `SELECT COALESCE(a.subject,''),COALESCE(a.handle,''),s.csrf
	FROM auth_sessions s LEFT JOIN auth_accounts a ON a.subject=s.subject WHERE s.token=? AND s.expires>?`, v.id, time.Now().Unix()).Scan(&v.Subject, &v.Handle, &v.CSRF)
	if err == nil && v.Subject != "" && !strings.HasPrefix(v.Subject, s.identity.subjectPrefix) {
		return session{}, sql.ErrNoRows
	}
	return v, err
}

func (s *Service) SignedIn(r *http.Request) bool {
	v, err := s.session(r)
	return err == nil && v.Subject != ""
}
func (s *Service) browserForFlow(w http.ResponseWriter, r *http.Request) (session, error) {
	v, err := s.session(r)
	if !errors.Is(err, sql.ErrNoRows) {
		return v, err
	}
	token := opaque()
	v = session{id: digest(s.credentialPrefix + token), BrowserSession: BrowserSession{CSRF: opaque()}}
	now := time.Now()
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		return session{}, err
	}
	defer tx.Rollback()
	for _, q := range []string{"DELETE FROM auth_sessions WHERE expires<=?", "DELETE FROM auth_flows WHERE expires<=?"} {
		if _, err = tx.ExecContext(r.Context(), q, now.Unix()); err != nil {
			return session{}, err
		}
	}
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO auth_sessions(token,csrf,expires) VALUES(?,?,?)", v.id, v.CSRF, now.Add(15*time.Minute).Unix()); err != nil {
		return session{}, err
	}
	if err = tx.Commit(); err != nil {
		return session{}, err
	}
	s.cookie(w, token, 900)
	return v, nil
}

func (s *Service) start(w http.ResponseWriter, r *http.Request, f flow) {
	pageHeaders(w)
	v, err := s.browserForFlow(w, r)
	if err != nil {
		serverError(w)
		return
	}
	key := opaque()
	_, err = s.db.ExecContext(r.Context(), `INSERT INTO auth_flows(token,session,target,oauth_handle,client,expires) VALUES(?,?,?,?,?,?)`, digest(key), v.id, f.target, f.oauthHandle, f.client, time.Now().Add(10*time.Minute).Unix())
	if err != nil {
		serverError(w)
		return
	}
	if v.Subject == "" {
		s.startIdentity(w, r, key)
		return
	}
	http.Redirect(w, r, s.prefix+"/login?flow="+url.QueryEscape(key), http.StatusSeeOther)
}
func (s *Service) beginOAuth(w http.ResponseWriter, r *http.Request, handle string, _ mcpoauth.ConsentRequest) {
	s.start(w, r, flow{oauthHandle: handle, client: clientLabel(r.URL.Query().Get("redirect_uri"))})
}
func (s *Service) loadFlow(ctx context.Context, key, id string) (flow, error) {
	if len(key) != 43 {
		return flow{}, errFlow
	}
	var f flow
	err := s.db.QueryRowContext(ctx, `SELECT f.target,f.oauth_handle,f.client,COALESCE(o.subject,'') FROM auth_flows f LEFT JOIN auth_oidc o ON o.flow=f.token WHERE f.token=? AND f.session=? AND f.expires>?`, digest(key), id, time.Now().Unix()).Scan(&f.target, &f.oauthHandle, &f.client, &f.verified)
	if errors.Is(err, sql.ErrNoRows) {
		return flow{}, errFlow
	}
	return f, err
}
func (s *Service) Browser(w http.ResponseWriter, r *http.Request) (BrowserSession, bool) {
	pageHeaders(w)
	v, err := s.session(r)
	if err == nil && v.Subject != "" {
		return v.BrowserSession, true
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		serverError(w)
		return BrowserSession{}, false
	}
	if r.Method != http.MethodGet {
		retry := s.prefix + "/connections"
		if key := r.PathValue("key"); key != "" {
			retry = s.prefix + "/approve/" + url.PathEscape(key)
		} else if id := r.PathValue("id"); id != "" {
			retry = s.prefix + "/messages/" + url.PathEscape(id)
		}
		s.recovery(w, r, http.StatusForbidden, "Your session expired", "Sign in again to continue.", retry)
		return BrowserSession{}, false
	}
	target := r.URL.EscapedPath()
	key, detail := strings.CutPrefix(target, s.prefix+"/approve/")
	if !detail {
		key, detail = strings.CutPrefix(target, s.prefix+"/messages/")
	}
	if target != s.prefix+"/connections" && target != s.prefix+"/account" && (!detail || key == "" || strings.ContainsAny(key, "/%?#\\")) {
		http.NotFound(w, r)
		return BrowserSession{}, false
	}
	if s.allow(w, r, "browser-signin", 90) {
		s.start(w, r, flow{target: target})
	}
	return BrowserSession{}, false
}

func (s *Service) ValidForm(r *http.Request, v BrowserSession) bool {
	if r.Method != http.MethodPost || v.CSRF == "" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != s.origin {
		return false
	}
	kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || kind != "application/x-www-form-urlencoded" {
		return false
	}
	r.Body = http.MaxBytesReader(nil, r.Body, 8192)
	if err = r.ParseForm(); err != nil || len(r.PostForm["csrf"]) != 1 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(v.CSRF)) == 1
}
func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	pageHeaders(w)
	v, err := s.session(r)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && v.Subject == "") {
		http.Redirect(w, r, s.prefix+"/", http.StatusSeeOther)
		return
	}
	if err != nil {
		serverError(w)
		return
	}
	if !s.ValidForm(r, v.BrowserSession) {
		http.Error(w, "Invalid sign-out request.", 403)
		return
	}
	_, err = s.db.ExecContext(r.Context(), "DELETE FROM auth_sessions WHERE token=?", v.id)
	if err != nil {
		serverError(w)
		return
	}
	s.cookie(w, "", -1)
	http.Redirect(w, r, s.prefix+"/", http.StatusSeeOther)
}
func (s *Service) login(w http.ResponseWriter, r *http.Request) {
	pageHeaders(w)
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed.", 405)
		return
	}
	v, err := s.session(r)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.expired(w, r)
		} else {
			serverError(w)
		}
		return
	}
	key := r.URL.Query().Get("flow")
	mode := r.URL.Query().Get("mode")
	if r.Method == http.MethodPost {
		if !s.ValidForm(r, v.BrowserSession) {
			s.recovery(w, r, http.StatusForbidden, "Sign-in form expired", "Reopen the original connection to continue.", "")
			return
		}
		key, mode = r.PostForm.Get("flow"), r.PostForm.Get("mode")
	}
	f, err := s.loadFlow(r.Context(), key, v.id)
	if err != nil {
		s.flowError(w, r, err)
		return
	}
	if mode == "cancel" && r.Method == http.MethodPost {
		s.finish(w, r, key, f, v, true)
		return
	}
	stage := "connect"
	handle := v.Handle
	if v.Subject == "" {
		stage = "identity"
		if strings.HasPrefix(f.verified, s.identity.subjectPrefix) {
			stage = "handle"
			err = s.db.QueryRowContext(r.Context(), "SELECT handle FROM auth_accounts WHERE subject=?", f.verified).Scan(&handle)
			switch {
			case err == nil:
				v, err = s.establish(w, r, key, v, f.verified, "")
				if err != nil {
					s.flowError(w, r, err)
					return
				}
				stage = "connect"
				if r.Method == http.MethodPost {
					http.Redirect(w, r, s.prefix+"/login?flow="+url.QueryEscape(key), http.StatusSeeOther)
					return
				}
			case !errors.Is(err, sql.ErrNoRows):
				serverError(w)
				return
			}
		}
	}
	if r.Method == http.MethodGet {
		if stage == "connect" && f.oauthHandle == "" {
			s.finish(w, r, key, f, v, false)
			return
		}
		s.render(w, key, stage, f, v, handle, "", 200)
		return
	}
	if mode != stage {
		s.recovery(w, r, http.StatusBadRequest, "Reopen the sign-in form", "Continue with the current sign-in step.", s.prefix+"/login?flow="+url.QueryEscape(key))
		return
	}
	switch mode {
	case "identity":
		s.startIdentity(w, r, key)
	case "handle":
		handle = strings.TrimPrefix(strings.TrimSpace(r.PostForm.Get("handle")), "@")
		if !handlePattern.MatchString(handle) {
			s.render(w, key, mode, f, v, handle, "Use 3–32 letters, numbers or underscores, starting with a letter.", 400)
			return
		}
		if strings.EqualFold(handle, "handle") {
			s.render(w, key, mode, f, v, handle, "@handle is reserved for examples. Choose another.", http.StatusConflict)
			return
		}
		v, err = s.establish(w, r, key, v, f.verified, strings.ToLower(handle))
		if errors.Is(err, errHandleTaken) {
			s.render(w, key, mode, f, v, handle, "That handle is taken. Choose another.", 409)
			return
		}
		if err != nil {
			s.flowError(w, r, err)
			return
		}
		if f.oauthHandle != "" {
			http.Redirect(w, r, s.prefix+"/login?flow="+url.QueryEscape(key), http.StatusSeeOther)
			return
		}
		s.finish(w, r, key, f, v, false)
	case "connect":
		s.finish(w, r, key, f, v, false)
	}
}

// Establish the browser identity independently of the client's pending OAuth decision.
func (s *Service) establish(w http.ResponseWriter, r *http.Request, key string, old session, subject, newHandle string) (session, error) {
	ctx := r.Context()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return old, err
	}
	defer tx.Rollback()
	now := time.Now()
	if _, err := accountCredential(ctx, tx, subject); err != nil {
		return old, err
	}
	var verified string
	err = tx.QueryRowContext(ctx, `DELETE FROM auth_oidc WHERE flow=? AND subject=? AND subject<>'' AND
		EXISTS(SELECT 1 FROM auth_flows f JOIN auth_sessions s ON f.session=s.token
		WHERE f.token=auth_oidc.flow AND s.token=? AND s.subject IS NULL AND f.expires>? AND s.expires>?)
		RETURNING subject`, digest(key), subject, old.id, now.Unix(), now.Unix()).Scan(&verified)
	if errors.Is(err, sql.ErrNoRows) {
		return old, errFlow
	}
	if err != nil {
		return old, err
	}
	if newHandle != "" {
		query := "INSERT INTO auth_accounts(subject,handle) VALUES(?,?) ON CONFLICT DO NOTHING"
		if s.legacyPasswordColumn {
			query = "INSERT INTO auth_accounts(subject,handle,password_hash) VALUES(?,?,x'') ON CONFLICT DO NOTHING"
		}
		if _, err = tx.ExecContext(ctx, query, verified, newHandle); err != nil {
			return old, err
		}
	}
	raw := opaque()
	v := session{id: digest(s.credentialPrefix + raw), BrowserSession: BrowserSession{Subject: verified, CSRF: opaque()}}
	err = tx.QueryRowContext(ctx, "SELECT handle FROM auth_accounts WHERE subject=?", verified).Scan(&v.Handle)
	if errors.Is(err, sql.ErrNoRows) && newHandle != "" {
		return old, errHandleTaken
	}
	if err != nil {
		return old, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE auth_sessions SET token=?,subject=?,csrf=?,expires=? WHERE token=?", v.id, verified, v.CSRF, now.Add(loginLife).Unix(), old.id); err != nil {
		return old, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE auth_flows SET session=? WHERE token=? AND session=?", v.id, digest(key), old.id); err != nil {
		return old, err
	}
	// Keep sibling profile visits until expiry so those tabs can reopen the profile.
	// Their old session is gone. Discard all pending authorization decisions.
	if _, err = tx.ExecContext(ctx, `DELETE FROM auth_flows WHERE session=? AND
		(oauth_handle<>'' OR target NOT IN (?,?))`, old.id, s.prefix+"/connections", s.prefix+"/account"); err != nil {
		return old, err
	}
	if err = tx.Commit(); err != nil {
		return old, err
	}
	s.cookie(w, raw, int(loginLife.Seconds()))
	return v, nil
}

func (s *Service) flowError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errOffboarded) {
		s.recovery(w, r, http.StatusForbidden, "Account disabled", "Contact the operator of this Ping server.", "")
	} else if errors.Is(err, errFlow) {
		s.expired(w, r)
	} else {
		serverError(w)
	}
}

func (s *Service) finish(w http.ResponseWriter, r *http.Request, key string, f flow, v session, cancel bool) {
	ctx := r.Context()
	var consent mcpoauth.ConsentRequest
	var err error
	if f.oauthHandle != "" {
		consent, err = s.oauth.Consent(ctx, f.oauthHandle)
		if err != nil {
			s.expired(w, r)
			return
		}
	}
	var owner string
	if f.oauthHandle != "" && !cancel {
		owner, err = accountCredential(ctx, s.db, v.Subject)
		if err != nil {
			s.flowError(w, r, err)
			return
		}
	}
	now := time.Now().Unix()
	result, err := s.db.ExecContext(ctx, `DELETE FROM auth_flows WHERE token=? AND session=? AND expires>?
		AND EXISTS(SELECT 1 FROM auth_sessions s WHERE s.token=auth_flows.session AND s.expires>? AND COALESCE(s.subject,'')=?)
		AND (? OR ?<>'')`, digest(key), v.id, now, now, v.Subject, cancel, v.Subject)
	if err != nil {
		serverError(w)
		return
	}
	n, err := result.RowsAffected()
	if err != nil {
		serverError(w)
		return
	}
	if n != 1 {
		s.expired(w, r)
		return
	}
	dest := f.target
	if f.oauthHandle != "" {
		if cancel {
			dest, err = s.oauth.Deny(ctx, f.oauthHandle)
		} else {
			dest, err = s.oauth.Approve(ctx, f.oauthHandle, mcpoauth.Approval{Subject: s.credentialPrefix + owner, Binding: f.client, Scopes: consent.Scopes})
		}
		if err != nil {
			s.expired(w, r)
			return
		}
	} else if cancel {
		dest = s.prefix + "/"
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}
