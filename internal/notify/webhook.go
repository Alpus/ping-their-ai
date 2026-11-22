package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

var invalidDestination = errors.New("webhook requires a public HTTPS destination")

func validateURL(raw string) error {
	if len(raw) == 0 || len(raw) > 2048 {
		return invalidDestination
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || strings.Contains(raw, "#") || strings.Contains(u.Host, "%") {
		return invalidDestination
	}
	hostname := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") {
		return invalidDestination
	}
	if ip, err := netip.ParseAddr(hostname); err == nil && !publicIP(ip) {
		return invalidDestination
	}
	return nil
}

var specialNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
}
var globalIPv6 = netip.MustParsePrefix("2000::/3")

func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || (!ip.Is4() && !globalIPv6.Contains(ip)) {
		return false
	}
	for _, prefix := range specialNetworks {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func publicClient() *http.Client {
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	resolver := &net.Resolver{PreferGo: true, StrictErrors: true}
	transport := &http.Transport{MaxIdleConns: 16, IdleConnTimeout: 30 * time.Second, MaxConnsPerHost: 4,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 4 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 * 1024, DisableCompression: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, invalidDestination
			}
			ips, err := resolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 || len(ips) > 64 {
				return nil, invalidDestination
			}
			for _, ip := range ips {
				if !publicIP(ip) {
					return nil, invalidDestination
				}
			}
			// TLS still uses the original hostname. The dialer sees only approved IP literals.
			for _, ip := range ips {
				var conn net.Conn
				conn, err = dialer.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
				if err == nil {
					return conn, nil
				}
				if ctx.Err() != nil {
					break
				}
			}
			return nil, err
		}}
	return &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func decodeKey(secret string) ([]byte, error) {
	encoded, ok := strings.CutPrefix(secret, "whsec_")
	if !ok || len(encoded) > 88 || strings.ContainsAny(encoded, "\r\n") {
		return nil, errors.New("invalid signing key")
	}
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) < 24 || len(key) > 64 {
		return nil, errors.New("invalid signing key")
	}
	return key, nil
}

func signature(id, timestamp string, body, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + timestamp + "."))
	mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

type endpoint struct {
	url         string
	key, oldKey []byte
}

func (s *Service) post(ctx context.Context, target endpoint, subID, webhookID string, body []byte) (*http.Response, error) {
	if err := validateURL(target.url); err != nil {
		return nil, err
	}
	if len(body) > 256*1024 {
		return nil, errors.New("notification too large")
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, target.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	ts := strconv.FormatInt(s.now().Unix(), 10)
	sig := signature(webhookID, ts, body, target.key)
	if len(target.oldKey) > 0 {
		sig += " " + signature(webhookID, ts, body, target.oldKey)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("webhook-id", webhookID)
	r.Header.Set("webhook-timestamp", ts)
	r.Header.Set("webhook-signature", sig)
	r.Header.Set("X-MCP-Subscription-Id", subID)
	return s.client.Do(r)
}

func callbackError(reason string) error {
	data, _ := json.Marshal(map[string]string{"reason": reason})
	return &jsonrpc.Error{Code: -32015, Message: "Webhook verification failed", Data: data}
}

func (s *Service) verify(ctx context.Context, target endpoint, subID string) error {
	challenge := rand.Text()
	body, _ := json.Marshal(map[string]string{"type": "verification", "challenge": challenge})
	resp, err := s.post(ctx, target, subID, "verify_"+rand.Text(), body)
	if err != nil {
		var timeout net.Error
		var certificate *tls.CertificateVerificationError
		var unknownAuthority x509.UnknownAuthorityError
		switch {
		case errors.As(err, &timeout) && timeout.Timeout():
			return callbackError("timeout")
		case errors.As(err, &certificate) || errors.As(err, &unknownAuthority):
			return callbackError("tls_error")
		default:
			return callbackError("connection_refused")
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		switch resp.StatusCode / 100 {
		case 4:
			return callbackError("http_4xx")
		case 5:
			return callbackError("http_5xx")
		}
		return callbackError("challenge_failed")
	}
	const maxEcho = 4096
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxEcho+1))
	var echo struct {
		Challenge string `json:"challenge"`
	}
	if err != nil || len(b) > maxEcho || json.Unmarshal(b, &echo) != nil || subtle.ConstantTimeCompare([]byte(echo.Challenge), []byte(challenge)) != 1 {
		return callbackError("challenge_failed")
	}
	return nil
}
