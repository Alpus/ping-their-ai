// Command ping runs the Ping Their AI inbox and its remote MCP endpoint.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Alpus/ping-their-ai/internal/authn"
	"github.com/Alpus/ping-their-ai/internal/message"
	"github.com/Alpus/ping-their-ai/internal/notify"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	_ "modernc.org/sqlite"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(os.Args) > 1 {
		if len(os.Args) != 3 || (os.Args[1] != "offboard" && os.Args[1] != "reinstate") {
			log.Fatal("usage: ping offboard|reinstate @handle")
		}
		db, err := openMailDB(configured("DATA_DIR", "data"), "rw")
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()
		enabled := os.Args[1] == "reinstate"
		if err = authn.SetAccountAccess(ctx, db, os.Args[2], enabled); err != nil {
			log.Fatal(err)
		}
		log.Printf("Account %s enabled=%t", os.Args[2], enabled)
		return
	}
	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}

func configured(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func openMailDB(dir, mode string) (*sql.DB, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	file := &url.URL{Scheme: "file", Path: filepath.Join(dir, "mail.sqlite")}
	// Both the server and operator commands read before writing in a transaction.
	// Reserve the writer at BEGIN so the busy timeout applies before either reads.
	db, err := sql.Open("sqlite", file.String()+"?mode="+mode+"&_txlock=immediate&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err == nil {
		db.SetMaxOpenConns(1)
	}
	return db, err
}

func run(ctx context.Context) error {
	base := strings.TrimRight(configured("PUBLIC_URL", "http://127.0.0.1:8787"), "/")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || strings.Contains(u.Path, "..") {
		return errors.New("PUBLIC_URL must be the application's external base URL")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && net.ParseIP(u.Hostname()).IsLoopback()) {
		return errors.New("use HTTPS or an HTTP numeric loopback address for PUBLIC_URL")
	}
	dir, err := filepath.Abs(configured("DATA_DIR", "data"))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	db, err := openMailDB(dir, "rwc")
	if err != nil {
		return err
	}
	defer db.Close()
	identity, err := authn.Open(ctx, db, base, dir)
	if err != nil {
		return err
	}
	defer identity.Close()
	var inbox *message.Store
	events, err := notify.New(ctx, db, func(ctx context.Context) (notify.Principal, bool) {
		p, ok := authn.FromContext(ctx)
		return notify.Principal{Subject: p.Subject, Grant: p.Grant}, ok
	}, func(ctx context.Context, owner string) (bool, error) { return inbox.Registered(ctx, owner) }, identity.GrantActive, notify.Delivery{
		MessageURL: func(id string) string { return browserMessageURL(base, id) },
		Body: func(ctx context.Context, owner, id string) (*string, error) {
			return inbox.DeliveryBody(ctx, owner, id)
		},
		Acknowledge: func(ctx context.Context, tx *sql.Tx, owner, id string) error {
			return inbox.AcknowledgeDelivery(ctx, tx, owner, id)
		},
	})
	if err != nil {
		return err
	}
	inbox, err = message.New(ctx, db, events.Enqueue, events.Readable, events.Approved)
	if err != nil {
		return err
	}

	capabilities := &mcp.ServerCapabilities{Logging: &mcp.LoggingCapabilities{}}
	capabilities.AddExtension(cardExtension, map[string]any{})
	server := mcp.NewServer(&mcp.Implementation{Name: "ping-their-ai", Title: "Ping Their AI", Version: "0.2.16"}, &mcp.ServerOptions{Instructions: onboarding, Capabilities: capabilities})
	installTools(server, inbox, base)
	if err := events.Install(server); err != nil {
		return err
	}
	transport := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	mux := http.NewServeMux()
	identity.Routes(mux)
	mux.Handle(u.Path+"/mcp", identity.Protect(transport))
	website := pages{identity: identity, messages: inbox, base: base, prefix: u.Path}
	website.routes(mux)
	mux.HandleFunc("GET "+u.Path+"/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	})
	srv := &http.Server{Handler: secure(website.withNotFound(mux), u), ReadHeaderTimeout: 8 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	listener, err := listen()
	if err != nil {
		return err
	}
	defer listener.Close()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); events.Run(runCtx) }()
	end := make(chan error, 1)
	go func() { end <- srv.Serve(listener) }()
	log.Print("Ping Their AI is ready")
	select {
	case err = <-end:
	case <-ctx.Done():
		shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
		err = srv.Shutdown(shutdown)
		done()
	}
	cancel()
	<-workerDone
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func secure(next http.Handler, public *url.URL) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		if !strings.EqualFold(r.Host, public.Host) {
			http.Error(w, "Unexpected host", http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		next.ServeHTTP(w, r)
	})
}

func listen() (net.Listener, error) {
	sock := os.Getenv("SOCKET_PATH")
	if sock == "" {
		return net.Listen("tcp", configured("LISTEN_ADDR", "127.0.0.1:8787"))
	}
	if entry, err := os.Lstat(sock); err == nil {
		if entry.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("SOCKET_PATH already exists and is not a socket")
		}
		conn, dialErr := net.DialTimeout("unix", sock, time.Second)
		if dialErr == nil {
			conn.Close()
			return nil, errors.New("SOCKET_PATH is already serving")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, dialErr
		}
		if err := os.Remove(sock); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sock, 0660); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}
