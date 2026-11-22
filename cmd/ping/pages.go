package main

import (
	_ "embed"
	"net/http"
	"net/url"
	"strings"
	texttemplate "text/template"

	"github.com/Alpus/ping-their-ai/internal/authn"
	"github.com/Alpus/ping-their-ai/internal/message"
	"github.com/Alpus/ping-their-ai/internal/webui"
)

//go:embed templates/site.html
var siteBody string

//go:embed templates/install.md
var installSource string

var site = webui.Parse("site", siteBody)
var install = texttemplate.Must(texttemplate.New("install").Parse(installSource))

type pages struct {
	identity     *authn.Service
	messages     *message.Store
	base, prefix string
}
type page struct {
	webui.Layout
	Kind, Message, Handle, Sender, Action, CSRF, Revision string
	Prompt, ChatGPT, Claude                               string
	Trusts                                                any
	Connections                                           []authn.Connection
	Active                                                bool
}

func (p pages) show(w http.ResponseWriter, code int, data page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(code)
	_ = site.ExecuteTemplate(w, "layout", data)
}

func (p pages) standard(title string, signedIn bool) webui.Layout {
	return webui.NewLayout(p.prefix, title, "connect-page", signedIn)
}

func (p pages) claudeURL() string {
	values := url.Values{"modal": {"add-custom-connector"}, "connectorName": {"Ping Their AI"}, "connectorUrl": {p.base + "/mcp"}}
	return "https://claude.ai/customize/connectors?" + values.Encode()
}

func (p pages) routes(mux *http.ServeMux) {
	webui.Assets(mux, p.prefix)
	mux.HandleFunc("GET "+p.prefix+"/{$}", func(w http.ResponseWriter, r *http.Request) {
		// Give chats a fresh URL when the setup steps change.
		prompt := "Connect Ping Their AI. Follow the instructions at " + p.base + "/install.md?v=20261123-1 yourself. If I need to act, link directly to the setup step."
		chat := url.Values{"surface": {"work"}, "prompt": {prompt}}
		p.show(w, http.StatusOK, page{Layout: webui.NewLayout(p.prefix, "Ping Their AI", "home", p.identity.SignedIn(r)),
			Kind: "home", Prompt: prompt, ChatGPT: "https://chatgpt.com/?" + chat.Encode(), Claude: p.claudeURL()})
	})
	if p.prefix != "" {
		mux.HandleFunc("GET "+p.prefix, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, p.prefix+"/", http.StatusPermanentRedirect)
		})
	}
	mux.HandleFunc("GET "+p.prefix+"/install.md", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_ = install.Execute(w, struct{ Base, Claude, Domain, Notes string }{
			Base: p.base, Claude: p.claudeURL(),
			Domain: configured("GOOGLE_ALLOWED_DOMAIN", ""), Notes: configured("INSTALL_NOTES_MD", ""),
		})
	})
	mux.HandleFunc("GET "+p.prefix+"/privacy", func(w http.ResponseWriter, r *http.Request) {
		p.show(w, http.StatusOK, page{Layout: p.standard("Privacy", p.identity.SignedIn(r)), Kind: "privacy"})
	})
	mux.HandleFunc("GET "+p.prefix+"/messages/{id}", p.approve)
	mux.HandleFunc("POST "+p.prefix+"/messages/{id}", p.approve)
	mux.HandleFunc("GET "+p.prefix+"/approve/{key}", p.approve)
	mux.HandleFunc("POST "+p.prefix+"/approve/{key}", p.approve)
	mux.HandleFunc("GET "+p.prefix+"/connections", p.account)
	mux.HandleFunc("POST "+p.prefix+"/connections/revoke", p.account)
	mux.HandleFunc("POST "+p.prefix+"/connections/disconnect", p.account)
	mux.HandleFunc("GET "+p.prefix+"/account", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, p.prefix+"/connections", http.StatusSeeOther)
	})
	mux.HandleFunc("POST "+p.prefix+"/account/revoke", p.account)
}

// For unmatched page requests the mux can also return 405 or a slash redirect.
// Keep its status and headers for those responses.
type notFoundWriter struct {
	http.ResponseWriter
	show     func()
	rendered bool
}

func (w *notFoundWriter) WriteHeader(code int) {
	if code == http.StatusNotFound {
		w.rendered = true
		w.show()
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *notFoundWriter) Write(data []byte) (int, error) {
	if w.rendered {
		return len(data), nil
	}
	return w.ResponseWriter.Write(data)
}

func (p pages) withNotFound(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dest := r.Header.Get("Sec-Fetch-Dest")
		accept := r.Header.Get("Accept")
		document := (dest == "" || dest == "document" || dest == "iframe") && (accept == "" || strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*"))
		path := strings.TrimPrefix(r.URL.Path, p.prefix)
		protocol := strings.HasPrefix(path, "/.well-known/") || strings.HasPrefix(path, "/oauth/") || strings.HasPrefix(path, "/mcp/")
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && document && !protocol {
			if handler, pattern := mux.Handler(r); pattern == "" {
				handler.ServeHTTP(&notFoundWriter{ResponseWriter: w, show: func() {
					p.show(w, http.StatusNotFound, page{Kind: "not-found", Layout: webui.NewLayout(p.prefix, "Page not found", "not-found", false)})
				}}, r)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func (p pages) approve(w http.ResponseWriter, r *http.Request) {
	session, ok := p.identity.Browser(w, r)
	if !ok {
		return
	}
	id, key := r.PathValue("id"), r.PathValue("key")
	var out map[string]any
	var err error
	if r.Method != http.MethodPost {
		if id != "" {
			out, err = p.messages.PreviewMessage(r.Context(), session.Subject, id)
		} else {
			out, err = p.messages.Approval(r.Context(), session.Subject, key)
		}
		if err != nil {
			p.show(w, 500, page{Layout: p.standard("Try again", true), Message: "The inbox is temporarily unavailable."})
			return
		}
		if out["status"] == "unavailable" {
			p.missing(w)
			return
		}
		sender, _ := out["sender"].(string)
		body, _ := out["body"].(string)
		revision, _ := out["revision"].(string)
		kind, title := "approval", "Let your AI read this message?"
		if out["status"] == "readable" {
			kind, title = "message", "Message"
		}
		p.show(w, 200, page{Kind: kind, Layout: p.standard(title, true), Sender: sender, Message: body, CSRF: session.CSRF, Revision: revision, Action: r.URL.Path})
		return
	}
	if !p.identity.ValidForm(r, session) {
		http.Error(w, "Reopen the link and try again.", 403)
		return
	}
	decision := r.PostForm.Get("decision")
	if id != "" {
		out, err = p.messages.DecideMessage(r.Context(), session.Subject, id, decision, r.PostForm.Get("revision"))
	} else {
		out, err = p.messages.Decide(r.Context(), session.Subject, key, decision)
	}
	if err != nil {
		p.show(w, 500, page{Layout: p.standard("Try again", true), Message: "The inbox is temporarily unavailable."})
		return
	}
	switch out["status"] {
	case "permissions_changed":
		p.show(w, http.StatusConflict, page{Kind: "permissions-changed", Layout: p.standard("Permissions changed", true), Action: r.URL.Path})
	case "only_message_allowed":
		p.show(w, http.StatusConflict, page{Kind: "done", Layout: p.standard("Only this message is allowed", true), Message: "Future messages from this sender still need your approval."})
	case "message_allowed", "approved_once", "trusted":
		p.show(w, 200, page{Kind: "done", Layout: p.standard("Access granted", true), Message: "You can return to your chat."})
	case "later":
		p.show(w, 200, page{Kind: "done", Layout: p.standard("Request dismissed", true), Message: "The message is still in your inbox."})
	default:
		p.missing(w)
	}
}
func (p pages) missing(w http.ResponseWriter) {
	p.show(w, http.StatusNotFound, page{Layout: p.standard("Request unavailable", true), Message: "This link may have expired or may belong to another account. Ask your AI for a new link."})
}
func (p pages) account(w http.ResponseWriter, r *http.Request) {
	session, ok := p.identity.Browser(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		if !p.identity.ValidForm(r, session) {
			http.Error(w, "Reopen your account and try again.", 403)
			return
		}
		var err error
		if r.URL.Path == p.prefix+"/connections/disconnect" {
			err = p.identity.Disconnect(r.Context(), session.Subject, r.PostForm.Get("grant"))
		} else {
			_, err = p.messages.Revoke(r.Context(), session.Subject, r.PostForm.Get("peer"))
		}
		if err != nil {
			p.show(w, 500, page{Layout: p.standard("Try again", true), Message: "The inbox is temporarily unavailable."})
			return
		}
		http.Redirect(w, r, p.prefix+"/connections", http.StatusSeeOther)
		return
	}
	out, err := p.messages.Trusts(r.Context(), session.Subject)
	if err != nil {
		p.show(w, 500, page{Layout: p.standard("Try again", true), Message: "The inbox is temporarily unavailable."})
		return
	}
	connections, err := p.identity.Connections(r.Context(), session.Subject)
	if err != nil {
		p.show(w, 500, page{Layout: p.standard("Try again", true), Message: "Your connections are temporarily unavailable."})
		return
	}
	p.show(w, 200, page{Kind: "account", Connections: connections, Layout: webui.NewLayout(p.prefix, "Your inbox", "connections-page connect-page", true), Handle: session.Handle, CSRF: session.CSRF, Trusts: out["trusts"], Active: out["status"] == "ready"})
}
