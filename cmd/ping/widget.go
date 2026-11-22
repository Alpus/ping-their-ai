package main

import (
	"context"
	_ "embed"
	"net/url"
	"slices"
	"strings"
	"text/template"

	"github.com/Alpus/ping-their-ai/internal/authn"
	"github.com/Alpus/ping-their-ai/internal/message"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const cardURI = "ui://ping/read-v5.2.html"
const previousCardURI = "ui://ping/read-v5.1.html"
const cardExtension = "io.modelcontextprotocol/ui"
const firstInboxWideCardURI = "ui://ping/read-v5.html"
const cardMIME = "text/html;profile=mcp-app"
const decisionTool = "choose_read_access"
const previewTool = "preview_message"

//go:embed widget.html
var cardHTML string

var cardTemplate = template.Must(template.New("card").Parse(cardHTML))

type previewArgs struct {
	Message string `json:"message_id" jsonschema:"ID of the message displayed by the approval card."`
	Request string `json:"request_id" jsonschema:"ID of the pending approval request associated with the card."`
	Proof   string `json:"proof" jsonschema:"Proof issued to the approval card for this message, request and connection."`
}

type decisionArgs struct {
	previewArgs
	Decision string `json:"decision" jsonschema:"allow_message for this message across the recipient's AIs, always for this sender, later to dismiss, or once from an older card for a single read."`
}

// Client is the persisted binding from the validated OAuth redirect for which the
// caller redeemed the code. Arbitrary MCP clients use the independent browser.
func trustedWidget(p authn.Principal) bool { return p.Client == "ChatGPT" || p.Client == "Claude" }

// The OAuth client binding protects component-only data. The current MCP
// request separately declares whether this host can display an approval card.
func supportsReadCard(caps *mcp.ClientCapabilities) bool {
	if caps == nil {
		return false
	}
	settings, _ := caps.Extensions[cardExtension].(map[string]any)
	types, _ := settings["mimeTypes"].([]any)
	return slices.Contains(types, any(cardMIME))
}

func installReadCard(server *mcp.Server, inbox *message.Store, base string) {
	u, _ := url.Parse(base)
	meta := mcp.Meta{"ui": map[string]any{"prefersBorder": true, "csp": map[string]any{"connectDomains": []string{}, "resourceDomains": []string{}}}, "openai/widgetCSP": map[string]any{"connect_domains": []string{}, "resource_domains": []string{}, "redirect_domains": []string{u.Scheme + "://" + u.Host}}}
	// v5 introduced inbox-wide message approval. Older cards retain the original single-read choice.
	for _, uri := range []string{cardURI, previousCardURI, firstInboxWideCardURI, "ui://ping/read-v4.2.html", "ui://ping/read-v4.1.html", "ui://ping/read-v4.html", "ui://ping/read-v3.html", "ui://ping/read-v2.html", "ui://ping/read-v1.html"} {
		server.AddResource(&mcp.Resource{URI: uri, Name: "Message access", MIMEType: cardMIME, Meta: meta}, func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			var html strings.Builder
			if err := cardTemplate.Execute(&html, uri == cardURI || uri == previousCardURI || uri == firstInboxWideCardURI); err != nil {
				return nil, err
			}
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: cardMIME, Text: html.String(), Meta: meta}}}, nil
		})
	}
	security := []map[string]any{{"type": "oauth2", "scopes": []string{"messages"}}}
	read := &mcp.Tool{Name: "read_message", Title: "Open a message", Description: "Reads one message by ID and returns its authorized text. An incoming result includes its private browser URL. A request for a link alone can be answered from message metadata without reading. For incoming text awaiting permission, approval_required contains a card or browser approval link and no message body. The first authorized incoming read records a timestamp visible to the sender.",
		Meta:        mcp.Meta{"ui": map[string]any{"resourceUri": cardURI}, "openai/outputTemplate": cardURI, "openai/widgetAccessible": true, "securitySchemes": security},
		Annotations: &mcp.ToolAnnotations{Title: "Open a message", DestructiveHint: new(true), OpenWorldHint: new(false)}}
	mcp.AddTool(server, read, func(ctx context.Context, req *mcp.CallToolRequest, a readArgs) (*mcp.CallToolResult, outcome, error) {
		p, ok := authn.FromContext(ctx)
		if !ok {
			return toolFailure("Sign in to continue."), nil, nil
		}
		out, err := inbox.Read(ctx, p.Subject, p.Grant, p.Client, a.ID, a.Request)
		if err != nil {
			return toolFailure("The inbox is temporarily unavailable."), nil, nil
		}
		return renderMessage(inbox, p, base, a, out, supportsReadCard(req.ClientCapabilities()))
	})
	componentOnly := mcp.Meta{"ui": map[string]any{"visibility": []string{"app"}}, "openai/visibility": "private", "openai/widgetAccessible": true, "securitySchemes": security}
	preview := &mcp.Tool{Name: previewTool, Title: "Preview this message", Description: "Displays the message text privately inside the recipient’s approval card. Previewing leaves AI read access unchanged.", Meta: componentOnly,
		Annotations: &mcp.ToolAnnotations{Title: "Preview this message", ReadOnlyHint: true, DestructiveHint: new(false), OpenWorldHint: new(false)}}
	mcp.AddTool(server, preview, func(ctx context.Context, _ *mcp.CallToolRequest, a previewArgs) (*mcp.CallToolResult, outcome, error) {
		p, ok := authn.FromContext(ctx)
		if !ok || !trustedWidget(p) {
			return toolFailure("Open the link in your browser."), nil, nil
		}
		row, err := inbox.PreviewWidget(ctx, p.Subject, p.Grant, a.Message, a.Request, a.Proof)
		if err != nil {
			return toolFailure("The inbox is temporarily unavailable."), nil, nil
		}
		if row["status"] != "pending" {
			return nil, outcome{"status": "unavailable"}, nil
		}
		// Only the requesting component receives the text, even for a component call.
		return &mcp.CallToolResult{Meta: mcp.Meta{"ping/preview": row["body"]}}, outcome{"status": "preview"}, nil
	})
	decide := &mcp.Tool{Name: decisionTool, Title: "Choose access", Description: "Records the recipient’s access decision from the approval card for this request.",
		Meta:        componentOnly,
		Annotations: &mcp.ToolAnnotations{Title: "Choose access", DestructiveHint: new(true), OpenWorldHint: new(false)}}
	mcp.AddTool(server, decide, func(ctx context.Context, _ *mcp.CallToolRequest, a decisionArgs) (*mcp.CallToolResult, outcome, error) {
		p, ok := authn.FromContext(ctx)
		if !ok || !trustedWidget(p) {
			return toolFailure("Use the approval link in your browser."), nil, nil
		}
		out, err := inbox.DecideWidget(ctx, p.Subject, p.Grant, a.Message, a.Request, a.Proof, a.Decision)
		if err != nil {
			return toolFailure("The inbox is temporarily unavailable."), nil, nil
		}
		return nil, out, nil
	})
}

func renderMessage(inbox *message.Store, p authn.Principal, base string, args readArgs, out outcome, supportsCard bool) (*mcp.CallToolResult, outcome, error) {
	if out["direction"] == "incoming" {
		out["message_url"] = browserMessageURL(base, args.ID)
	}
	key, ok := out["approval_key"].(string)
	if !ok {
		guideResult("read_message", out)
		if out["status"] == "read" {
			out["next"] = readHelp
			if out["direction"] == "outgoing" {
				out["next"] = "Use this previously sent message to answer the owner’s current question. A history lookup does not start a new send."
			}
			return nil, out, nil
		}
		return nil, out, nil
	}
	delete(out, "approval_key")
	out["request_id"] = key
	link := base + "/approve/" + url.PathEscape(key)
	out["approval_url"] = link
	out["approval_prompt"] = "Message from " + out["sender"].(string) + ". [Review and approve](" + link + ")"
	var card *mcp.CallToolResult
	if args.LinkOnly != nil {
		supportsCard = !*args.LinkOnly
	}
	if !supportsCard || !trustedWidget(p) {
		out["presentation"] = "link"
		out["next"] = "In this reply, show the link in approval_prompt once, in the user's language. Preserve its exact URL. The message.received subscription delivers approved text directly. For a manual read outside that subscription, message.readable can resume by request_id. If events are unavailable or subscription fails, still show the link and ask the user to return here after approving. Then call read_message with both IDs."
	} else {
		out["presentation"] = "card"
		out["next"] = "Use the permission card alone. Say only, in the recipient’s language: “Review the message and choose an option on the card.” Let the card show its button labels and start the follow-up after approval. Do not ask for a second chat reply or post a link. Only if the recipient says the card is missing, call read_message again with the same message_id and request_id and link_only=true."
		card = &mcp.CallToolResult{Meta: mcp.Meta{"openai/outputTemplate": cardURI, "ping/decisionProof": inbox.WidgetProof(p.Subject, p.Grant, args.ID, key)}}
	}
	return card, out, nil
}
