package authn

import (
	_ "embed"
	"net/http"
	"strings"
	"time"

	"github.com/Alpus/ping-their-ai/internal/webui"
)

//go:embed login.html
var loginTemplate string
var loginPage = webui.Parse("login", loginTemplate)

func (s *Service) render(w http.ResponseWriter, key, mode string, f flow, v session, handle, issue string, status int) {
	// The form can redirect to either Google or the MCP client's registered callback.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'")
	title, action := "Sign in to Ping Their AI", "Continue with Google"
	switch mode {
	case "handle":
		title, action = "Choose your handle", "Create profile"
	case "connect":
		title, action = "Connect "+f.client+"?", "Connect as @"+handle
	}
	layout := webui.NewLayout(s.prefix, title, "connect-page auth-page", v.Subject != "")
	layout.HideAccountLink = mode != "connect"
	data := struct {
		webui.Layout
		Base, Key, Mode, CSRF, Handle, Client, Action, Issue string
	}{layout, s.prefix, key, mode, v.CSRF, handle, f.client, action, issue}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = loginPage.ExecuteTemplate(w, "layout", data)
}

func (s *Service) expired(w http.ResponseWriter, r *http.Request) {
	if s.reopenProfile(w, r) {
		return
	}
	s.recovery(w, r, http.StatusGone, "Sign-in link expired", "To connect an assistant, restart the connection from its settings.", "")
}

// A second tab may have replaced the session cookie. Discard the stale sign-in
// and let the profile route authenticate the current browser on its own.
func (s *Service) reopenProfile(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if c, err := r.Cookie(sessionCookie); err != nil || len(c.Value) != 43 {
		return false
	}
	q := r.URL.Query()
	var key, stateHash string
	switch r.URL.Path {
	case s.prefix + "/login":
		key = q.Get("flow")
	case s.prefix + "/auth/callback":
		state := q.Get("state")
		keyPart, suffix, ok := strings.Cut(state, ".")
		if !ok || len(suffix) != 43 || q.Get("code") == "" || q.Has("error") {
			return false
		}
		key, stateHash = keyPart, digest(state)
	default:
		return false
	}
	if len(key) != 43 {
		return false
	}
	var exists bool
	err := s.db.QueryRowContext(r.Context(), `SELECT EXISTS(
		SELECT 1 FROM auth_flows f JOIN auth_oidc o ON o.flow=f.token
		WHERE f.token=? AND f.expires>? AND f.oauth_handle='' AND f.target IN (?,?)
		AND (?='' OR o.state=?))`, digest(key), time.Now().Unix(), s.prefix+"/connections", s.prefix+"/account", stateHash, stateHash).Scan(&exists)
	if err != nil || !exists {
		return false
	}
	http.Redirect(w, r, s.prefix+"/connections", http.StatusSeeOther)
	return true
}

func (s *Service) recovery(w http.ResponseWriter, r *http.Request, status int, title, message, retry string) {
	data := struct {
		webui.Layout
		Mode, Issue, Retry string
	}{webui.NewLayout(s.prefix, title, "connect-page auth-page", s.SignedIn(r)), "recovery", message, retry}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = loginPage.ExecuteTemplate(w, "layout", data)
}
