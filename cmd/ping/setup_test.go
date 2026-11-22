package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Alpus/ping-their-ai/internal/authn"
	"github.com/Alpus/ping-their-ai/internal/message"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestRegisterMatchesWholeEndpointBeforeActivatingInbox(t *testing.T) {
	who := authn.Principal{Subject: "user", Handle: "friend"}
	const hosted = "https://example.test/ping/mcp"
	const team = "https://example.test/team/mcp"
	for _, endpoint := range []string{hosted, team} {
		db, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		inbox, err := message.New(t.Context(), db,
			func(context.Context, *sql.Tx, string, string, string) error { return nil },
			func(context.Context, *sql.Tx, string, string, string, string) error { return nil },
			func(context.Context, *sql.Tx, string, string, bool) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		out, err := registerInbox(t.Context(), inbox, who, endpoint, registerArgs{ExpectedURL: team})
		if err != nil || out["mcp_url"] != endpoint {
			t.Fatalf("unexpected instance: %v, %v", out, err)
		}
		active, err := inbox.Registered(t.Context(), who.Subject)
		if err != nil || active != (endpoint == team) {
			t.Fatalf("registration on %s: %t, %v", endpoint, active, err)
		}
		if endpoint == hosted && (out["status"] != "instance_mismatch" || out["handle"] != nil) {
			t.Fatalf("unexpected mismatched handle: %v", out)
		}
		if endpoint == team && (out["status"] != "ready" || out["handle"] != "@friend") {
			t.Fatalf("unexpected matching result: %v", out)
		}
		legacy, err := registerInbox(t.Context(), inbox, who, endpoint, registerArgs{})
		if err != nil || legacy["status"] != "ready" || legacy["mcp_url"] != endpoint {
			t.Fatalf("legacy no-argument registration: %v, %v", legacy, err)
		}
	}
}

// A stateless legacy transport cannot recover the current chat's capabilities
// from a prior initialize. Exercise actual HTTP requests through the SDK.
func TestStatelessCardNegotiation(t *testing.T) {
	s := mcp.NewServer(&mcp.Implementation{Name: "ping-test", Version: "1"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "read_message"}, func(_ context.Context, req *mcp.CallToolRequest, args readArgs) (*mcp.CallToolResult, outcome, error) {
		who := authn.Principal{Client: "ChatGPT"}
		out := outcome{"status": "approval_required", "approval_key": "req", "sender": "@friend"}
		return renderMessage(new(message.Store), who, "https://example.test", args, out, supportsReadCard(req.ClientCapabilities()))
	})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	call := func(version, method, params string) map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"`+method+`","params":`+params+`}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", version)
		req.Header.Set("Mcp-Method", method)
		if method == "tools/call" {
			req.Header.Set("Mcp-Name", "read_message")
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		var response struct{ Result map[string]any }
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.Result == nil {
			t.Fatalf("%s %s: %d %s", version, method, w.Code, w.Body.String())
		}
		return response.Result
	}
	const capability = `{"extensions":{"io.modelcontextprotocol/ui":{"mimeTypes":["text/html;profile=mcp-app"]}}}`
	call("2025-11-25", "initialize", `{"protocolVersion":"2025-11-25","clientInfo":{"name":"chat","version":"1"},"capabilities":`+capability+`}`)
	for _, tc := range []struct{ version, meta, preference, want string }{
		{"2025-11-25", "", "", "link"},
		{"2025-11-25", "", `,"link_only":false`, "card"},
		{"2025-11-25", "", `,"link_only":true`, "link"},
		{"2026-07-28", capability, "", "card"},
		{"2026-07-28", capability, `,"link_only":true`, "link"},
		{"2026-07-28", "{}", "", "link"},
	} {
		params := `{"name":"read_message","arguments":{"message_id":"msg"` + tc.preference + `}`
		if tc.meta != "" {
			params += `,"_meta":{"io.modelcontextprotocol/protocolVersion":"` + tc.version + `","io.modelcontextprotocol/clientInfo":{"name":"chat","version":"1"},"io.modelcontextprotocol/clientCapabilities":` + tc.meta + `}`
		}
		result := call(tc.version, "tools/call", params+"}")
		out, _ := result["structuredContent"].(map[string]any)
		meta, _ := result["_meta"].(map[string]any)
		if out["presentation"] != tc.want || (meta["ping/decisionProof"] != nil) != (tc.want == "card") {
			t.Fatalf("%+v: unexpected presentation %v", tc, result)
		}
	}
}

func TestInstallGuideResolvesCurrentInstanceFromOlderLinks(t *testing.T) {
	for _, prefix := range []string{"", "/team/ping"} {
		base := "https://inbox.example" + prefix
		p := pages{base: base, prefix: prefix}
		mux := http.NewServeMux()
		p.routes(mux)
		for _, suffix := range []string{"", "?v=20261122-3", "?v=20261123-1"} {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest("GET", prefix+"/install.md"+suffix, nil))
			content := w.Body.String()
			if w.Code != http.StatusOK || !strings.Contains(content, `"expected_mcp_url":"`+base+`/mcp"`) || !strings.Contains(content, "instance_mismatch") || strings.Contains(content, "nopluginsfound.com") {
				t.Fatalf("guide at %s does not identify the requested endpoint", prefix+suffix)
			}
		}
	}
}

// Check the serialized fields: false and an absent hint are different for clients.
func TestToolDirectoryAnnotationsOnWire(t *testing.T) {
	type hints struct{ readOnly, destructive bool }
	for _, tc := range []struct {
		name    string
		install func(*mcp.Server, *message.Store, string)
		want    map[string]hints
	}{
		{"inbox", installTools, map[string]hints{
			"register": {false, false}, "list_contacts": {true, false}, "save_contact": {false, true},
			"send": {false, true}, "messages": {true, false}, "read_message": {false, true},
		}},
		{"card", installReadCard, map[string]hints{
			"read_message": {false, true}, previewTool: {true, false}, decisionTool: {false, true},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := mcp.NewServer(&mcp.Implementation{Name: "ping-test", Version: "1"}, nil)
			tc.install(s, nil, "https://example.test/ping")
			h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			req.Header.Set("MCP-Protocol-Version", "2025-11-25")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			var reply struct {
				Result struct {
					Tools []struct {
						Name, Title, Description string
						Annotations              map[string]any
						InputSchema              struct {
							Properties map[string]struct{ Description string }
						}
					}
				}
			}
			if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || len(reply.Result.Tools) != len(tc.want) {
				t.Fatalf("unexpected tools/list: %s", w.Body.String())
			}
			for _, tool := range reply.Result.Tools {
				want, ok := tc.want[tool.Name]
				if !ok || tool.Title == "" || tool.Description == "" || tool.Annotations["title"] != tool.Title ||
					tool.Annotations["readOnlyHint"] != want.readOnly || tool.Annotations["destructiveHint"] != want.destructive {
					t.Errorf("unexpected descriptor for %s: %+v", tool.Name, tool)
				}
				for field, property := range tool.InputSchema.Properties {
					if property.Description == "" {
						t.Errorf("%s.%s lacks an input description", tool.Name, field)
					}
				}
			}
		})
	}
}
