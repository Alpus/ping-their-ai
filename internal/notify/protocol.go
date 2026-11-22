// Package notify implements the MCP Events webhook extension for a registered inbox.
package notify

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const eventName = "message.created"
const receivedEvent = "message.received"
const readableEvent = "message.readable"
const createdNext = "If the owner only asked for notifications, show the sender and this review link: %s. If the owner asked to process messages, read_message returns either the authorized text or the recipient’s approval step. For approval, show a supported card or the review link in a text-only chat."
const readableNext = "An approval was recorded. Call read_message with message_id and request_id now. Follow the read result and this chat owner’s instructions. Permission to read alone does not authorize a reply."
const readWindow = 15 * time.Minute

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9]{26,64}$`)

type Principal struct{ Subject, Grant string }

// Delivery supplies account-level message access and transactional read receipts.
type Delivery struct {
	MessageURL  func(messageID string) string
	Body        func(context.Context, string, string) (*string, error)
	Acknowledge func(context.Context, *sql.Tx, string, string) error
}

type Service struct {
	db            *sql.DB
	principal     func(context.Context) (Principal, bool)
	registered    func(context.Context, string) (bool, error)
	active        func(context.Context, string, string) (bool, error)
	delivery      Delivery
	client        *http.Client
	now           func() time.Time
	wake          chan struct{}
	verifications chan struct{}
	locksMu       sync.Mutex
	locks         map[string]*subscriptionLock
}

func New(ctx context.Context, db *sql.DB, principal func(context.Context) (Principal, bool), registered func(context.Context, string) (bool, error), active func(context.Context, string, string) (bool, error), delivery Delivery) (*Service, error) {
	if db == nil || principal == nil || registered == nil || active == nil || delivery.MessageURL == nil || delivery.Body == nil || delivery.Acknowledge == nil {
		return nil, errors.New("notification service requires storage and authorization")
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		return nil, err
	}
	return &Service{db: db, principal: principal, registered: registered, active: active, delivery: delivery, client: publicClient(), now: time.Now,
		wake: make(chan struct{}, 1), verifications: make(chan struct{}, 4), locks: make(map[string]*subscriptionLock)}, nil
}

type capabilities struct {
	*mcp.ServerCapabilities
	Events struct{} `json:"events"`
}

func advertise(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		res, err := next(ctx, method, req)
		if err != nil {
			return res, err
		}
		// The SDK sets resultType on its built-in results. Custom event
		// results must add the MCP 2.0 envelope field themselves.
		if r, ok := res.(interface{ markComplete() }); ok && req.GetParams() != nil &&
			req.GetParams().GetMeta()[mcp.MetaKeyProtocolVersion] == "2026-07-28" {
			r.markComplete()
		}
		switch r := res.(type) {
		case *mcp.InitializeResult:
			return &struct {
				*mcp.InitializeResult
				Capabilities capabilities `json:"capabilities"`
			}{r, capabilities{ServerCapabilities: r.Capabilities}}, nil
		case *mcp.DiscoverResult:
			return &struct {
				*mcp.DiscoverResult
				Capabilities capabilities `json:"capabilities"`
			}{r, capabilities{ServerCapabilities: r.Capabilities}}, nil
		default:
			return res, nil
		}
	}
}

func (s *Service) Install(server *mcp.Server) error {
	if err := mcp.AddReceivingCustomMethod(server, "events/list", s.list); err != nil {
		return err
	}
	if err := mcp.AddReceivingCustomMethod(server, "events/subscribe", s.subscribe); err != nil {
		return err
	}
	if err := mcp.AddReceivingCustomMethod(server, "events/unsubscribe", s.unsubscribe); err != nil {
		return err
	}
	server.AddReceivingMiddleware(advertise)
	return nil
}

type listParams struct {
	mcp.ParamsBase
	Cursor *string `json:"cursor,omitempty"`
}
type eventResult struct {
	mcp.ResultBase
	ResultType string `json:"resultType,omitempty"`
}

func (r *eventResult) markComplete() { r.ResultType = "complete" }

type listResult struct {
	eventResult
	Events []eventDefinition `json:"events"`
}
type eventDefinition struct {
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	Delivery      []string        `json:"delivery"`
	InputSchema   json.RawMessage `json:"inputSchema"`
	PayloadSchema json.RawMessage `json:"payloadSchema"`
}

var inboxEvent = eventDefinition{
	Name: eventName, Description: "Notifies a subscribed chat about existing unread messages and new arrivals. Each notification identifies the sender and message without revealing the body.",
	Delivery:      []string{"webhook"},
	InputSchema:   json.RawMessage(`{"type":"object","properties":{"include_next":{"type":"boolean","default":true,"description":"Whether the notification includes Ping’s next-step hint."}},"required":["include_next"],"additionalProperties":false}`),
	PayloadSchema: json.RawMessage(`{"type":"object","properties":{"message_id":{"type":"string"},"sender_handle":{"type":"string"},"next":{"type":"string"}},"required":["message_id","sender_handle"],"additionalProperties":false}`),
}

var received = eventDefinition{
	Name: receivedEvent, Description: "Each subscribed chat receives its own copy of unread and new messages. An approval_required notification includes the sender and recipient’s review link. The recipient reviews the message in a supported card or opens the link in a text-only chat. Once the recipient approves the message or trusts the sender, readable delivers the text on the same subscription. Successful text delivery records a read receipt.",
	Delivery:      []string{"webhook"},
	InputSchema:   json.RawMessage(`{"type":"object","properties":{"include_review_action":{"type":"boolean","default":false,"description":"For a text-only chat, include one ready-to-display review link with every pending notification."}},"additionalProperties":false}`),
	PayloadSchema: json.RawMessage(`{"type":"object","properties":{"status":{"type":"string","enum":["approval_required","readable"]},"message_id":{"type":"string"},"sender_handle":{"type":"string"},"sent_at":{"type":"string","format":"date-time"},"message_url":{"type":"string","format":"uri","description":"Recipient-only browser link. A text-only chat uses it for review while approval is pending. The link remains valid after reading."},"body":{"type":"string"},"review_action":{"type":"string","description":"One Markdown link for the recipient to review this message. Always present in pending notifications when include_review_action is enabled. Use this link in text-only chats or a supported card."}},"required":["status","message_id","sender_handle","sent_at","message_url"],"oneOf":[{"properties":{"status":{"const":"approval_required"}},"not":{"required":["body"]}},{"properties":{"status":{"const":"readable"}},"required":["body"],"not":{"required":["review_action"]}}],"additionalProperties":false}`),
}

var readEvent = eventDefinition{
	Name:          readableEvent,
	Description:   "Notifies the requesting chat when browser approval makes a particular message available. Includes the message ID and the original approval request ID.",
	Delivery:      []string{"webhook"},
	InputSchema:   json.RawMessage(`{"type":"object","properties":{"request_id":{"type":"string","description":"ID of the pending browser approval request."},"include_next":{"type":"boolean","default":true,"description":"Whether the approval notification includes Ping’s next-step hint."}},"required":["request_id","include_next"],"additionalProperties":false}`),
	PayloadSchema: json.RawMessage(`{"type":"object","properties":{"message_id":{"type":"string"},"request_id":{"type":"string"},"next":{"type":"string"}},"required":["message_id","request_id"],"additionalProperties":false}`),
}

type subParams struct {
	mcp.ParamsBase
	Name      string                     `json:"name"`
	Arguments map[string]json.RawMessage `json:"arguments"`
	Delivery  struct {
		Mode   string `json:"mode"`
		URL    string `json:"url"`
		Secret string `json:"secret"`
	} `json:"delivery"`
	TTL    *int64  `json:"ttlMs"`
	Cursor *string `json:"cursor"`
}

type subResult struct {
	eventResult
	ID            string  `json:"id"`
	RefreshBefore string  `json:"refreshBefore"`
	Cursor        *string `json:"cursor"`
	Truncated     bool    `json:"truncated"`
}

func invalidParams(message string) error {
	return &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: message}
}

func (s *Service) authenticated(ctx context.Context) (Principal, error) {
	p, ok := s.principal(ctx)
	if !ok || p.Subject == "" || p.Grant == "" {
		return Principal{}, &jsonrpc.Error{Code: -32001, Message: "Authentication required"}
	}
	return p, nil
}

func (s *Service) owner(ctx context.Context) (Principal, error) {
	p, err := s.authenticated(ctx)
	if err != nil {
		return Principal{}, err
	}
	ok, err := s.registered(ctx, p.Subject)
	if err != nil {
		return Principal{}, err
	}
	if !ok {
		return Principal{}, &jsonrpc.Error{Code: -32024, Message: "Register the inbox to use incoming events"}
	}
	return p, nil
}

func (s *Service) list(ctx context.Context, _ *mcp.ServerSession, a *listParams) (*listResult, error) {
	if _, err := s.authenticated(ctx); err != nil {
		return nil, err
	}
	if a != nil && a.Cursor != nil {
		return nil, invalidParams("The event catalog has one page")
	}
	return &listResult{Events: []eventDefinition{received, inboxEvent, readEvent}}, nil
}

func subscriptionID(p Principal, a *subParams) (id, request string, err error) {
	if a == nil || a.Delivery.Mode != "webhook" || a.Cursor != nil {
		return "", "", invalidParams("Use webhook delivery and a null cursor")
	}
	// Clients with a cached pre-instructions schema still send no format option.
	argumentCount := len(a.Arguments)
	if raw, ok := a.Arguments["include_next"]; ok {
		if string(raw) != "true" && string(raw) != "false" {
			return "", "", invalidParams("include_next must be a boolean")
		}
		argumentCount--
	}
	switch a.Name {
	case receivedEvent:
		if len(a.Arguments) > 0 {
			option := string(a.Arguments["include_review_action"])
			if len(a.Arguments) != 1 || (option != "true" && option != "false") {
				return "", "", invalidParams("message.received accepts only a boolean include_review_action")
			}
		}
	case eventName:
		if argumentCount != 0 {
			return "", "", invalidParams("message.created accepts only optional include_next")
		}
	case readableEvent:
		if argumentCount != 1 || json.Unmarshal(a.Arguments["request_id"], &request) != nil || !requestIDPattern.MatchString(request) {
			return "", "", invalidParams("message.readable needs the original approval request_id")
		}
	default:
		return "", "", invalidParams("Unknown event name")
	}
	if err := validateURL(a.Delivery.URL); err != nil {
		return "", "", invalidParams("The callback must be a public HTTPS URL without credentials or a fragment")
	}
	filter := "{}" // Keep existing inbox subscription IDs stable across upgrades.
	if request != "" {
		filter = request
	}
	identity, _ := json.Marshal([5]string{p.Subject, p.Grant, a.Delivery.URL, a.Name, filter})
	sum := sha256.Sum256(identity)
	return "sub_" + base64.RawURLEncoding.EncodeToString(sum[:]), request, nil
}

// Keep deliveries and changes to the same subscription serialized. An unrelated
// slow endpoint must never hold the lock needed by another subscription.
type subscriptionLock struct {
	sync.Mutex
	users int
}

func (s *Service) lockSubscription(id string) func() {
	s.locksMu.Lock()
	lock := s.locks[id]
	if lock == nil {
		lock = &subscriptionLock{}
		s.locks[id] = lock
	}
	lock.users++
	s.locksMu.Unlock()
	lock.Lock()
	return func() {
		lock.Unlock()
		s.locksMu.Lock()
		lock.users--
		if lock.users == 0 {
			delete(s.locks, id)
		}
		s.locksMu.Unlock()
	}
}

func (s *Service) subscribe(ctx context.Context, _ *mcp.ServerSession, a *subParams) (*subResult, error) {
	p, err := s.owner(ctx)
	if err != nil {
		return nil, err
	}
	id, request, err := subscriptionID(p, a)
	if err != nil {
		return nil, err
	}
	ttl := 24 * time.Hour
	if a.TTL != nil {
		if *a.TTL <= 0 {
			return nil, invalidParams("ttlMs must be positive or null")
		}
		ttl = time.Duration(min(*a.TTL, ttl.Milliseconds())) * time.Millisecond
	}
	if request != "" {
		ttl = min(ttl, readWindow)
	}
	key, err := decodeKey(a.Delivery.Secret)
	if err != nil {
		return nil, invalidParams("Expected a whsec_ signing key of 24 to 64 bytes")
	}
	unlock := s.lockSubscription(id)
	defer unlock()
	includeNext := string(a.Arguments["include_next"]) == "true" || string(a.Arguments["include_review_action"]) == "true"
	expires, err := s.saveVerified(ctx, id, p, a.Delivery.URL, key, ttl, request, includeNext, a.Name == receivedEvent)
	if err != nil {
		return nil, err
	}
	return &subResult{ID: id, RefreshBefore: expires.UTC().Format(time.RFC3339Nano)}, nil
}

func (s *Service) unsubscribe(ctx context.Context, _ *mcp.ServerSession, a *subParams) (*eventResult, error) {
	p, err := s.owner(ctx)
	if err != nil {
		return nil, err
	}
	id, _, err := subscriptionID(p, a)
	if err != nil {
		return nil, err
	}
	unlock := s.lockSubscription(id)
	defer unlock()
	_, err = s.db.ExecContext(ctx, "DELETE FROM notify_subscriptions WHERE id=? AND owner=? AND grant_id=?", id, p.Subject, p.Grant)
	return &eventResult{}, err
}
