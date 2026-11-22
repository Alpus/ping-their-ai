// Package webui supplies the layout and local assets shared by all browser pages.
package webui

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/yuin/goldmark"
)

//go:embed layout.html
var shell string

//go:embed assets
var assets embed.FS

type branding struct {
	Name       string
	Footer     template.HTML
	TrustTitle string
	TrustBody  template.HTML
}

type Layout struct {
	Brand           branding
	Prefix          string
	Title           string
	MainClass       string
	SignedIn        bool
	HideAccountLink bool
}

var appearance = sync.OnceValue(func() branding {
	name := strings.TrimSpace(os.Getenv("SITE_NAME"))
	if name == "" {
		name = "Ping Their AI"
	}
	return branding{
		Name: name, Footer: markdown(os.Getenv("FOOTER_MD")),
		TrustTitle: strings.TrimSpace(os.Getenv("TRUST_TITLE")), TrustBody: markdown(os.Getenv("TRUST_BODY_MD")),
	}
})

// Markdown's default HTML renderer suppresses raw HTML and dangerous link schemes.
func markdown(source string) template.HTML {
	var buf bytes.Buffer
	if err := goldmark.Convert([]byte(source), &buf); err != nil {
		return ""
	}
	return template.HTML(strings.TrimSpace(buf.String()))
}

func NewLayout(prefix, title, mainClass string, signedIn bool) Layout {
	return Layout{Brand: appearance(), Prefix: prefix, Title: title, MainClass: mainClass, SignedIn: signedIn}
}

func Parse(name, body string) *template.Template {
	t := template.Must(template.New(name).Parse(shell))
	return template.Must(t.Parse(body))
}

func Assets(mux *http.ServeMux, prefix string) {
	mux.Handle("GET "+prefix+"/assets/", http.StripPrefix(prefix, http.FileServerFS(assets)))
}
