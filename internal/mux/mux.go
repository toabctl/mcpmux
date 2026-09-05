// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

// Package mux is the core of mcpmux: it connects to a set of backend MCP
// servers, aggregates their tools under namespaced names, and exposes them
// through a single proxy MCP server (over stdio or streamable HTTP).
package mux

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/toabctl/mcpmux/internal/config"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// clientName is the implementation name mcpmux reports to upstream servers.
const clientName = "mcpmux"

// clientVersion is reported to peers; overridden via SetVersion.
var clientVersion = "dev"

// SetVersion records the build version reported to peers.
func SetVersion(v string) { clientVersion = v }

// Mux aggregates several backend MCP servers behind a single proxy server.
type Mux struct {
	log    *slog.Logger
	server *mcp.Server

	mu       sync.Mutex // guards backends
	backends []*backend

	// wg tracks background Connect goroutines so Close can wait for them.
	wg sync.WaitGroup
	// svg tracks per-backend supervisor goroutines (the reconnect watchers).
	svg sync.WaitGroup
	// closing tells supervisors that a session closing during shutdown is
	// intentional and must not trigger a reconnect.
	closing atomic.Bool
	//nolint:containedctx // The Mux's own lifetime needs a cancellation signal
	// that outlives any single call: closeCtx is cancelled by Close, and each
	// per-backend goroutine derives its work context from it as well as from
	// the caller's, so a backend sleeping out a long retry backoff (up to the
	// configured ceiling) or waiting on an in-flight attempt cannot hold up
	// shutdown. A bare channel would cover the sleep but not the attempt.
	closeCtx    context.Context
	closeCancel context.CancelFunc
	closeOnce   sync.Once
}

// NewServer builds an unconnected Mux: the proxy server and its middleware, with
// no backends attached. Callers bring backends up with Connect /
// ConnectInBackground. This lets a daemon start serving (and signal systemd
// readiness) before interactive OAuth backends have finished authorizing.
func NewServer(cfg *config.Config, log *slog.Logger) *Mux {
	//nolint:gosec // G118: the cancel is retained on the Mux and called by Close.
	closeCtx, closeCancel := context.WithCancel(context.Background())
	m := &Mux{
		log:         log,
		server:      mcp.NewServer(&mcp.Implementation{Name: clientName, Version: clientVersion}, serverOptions(cfg)),
		closeCtx:    closeCtx,
		closeCancel: closeCancel,
	}
	// Debug-log every inbound request from the client (no-op unless --log-level debug).
	m.server.AddReceivingMiddleware(requestLogger(log))
	return m
}

// RetryPolicy bounds the loop that brings up a backend which failed its initial
// connect: MaxDelay caps the exponential backoff between attempts and
// AttemptTimeout bounds each individual attempt.
type RetryPolicy struct {
	MaxDelay       time.Duration
	AttemptTimeout time.Duration
}

// ConnectOptions tunes how Connect brings backends up.
type ConnectOptions struct {
	// Eager drives an interactive OAuth backend through its browser consent
	// during connect rather than lazily on its first tool call.
	Eager bool
	// Retry, when non-nil, keeps a backend that fails its initial connect and
	// retries it in the background instead of skipping it for the process's
	// lifetime. Only non-interactive backends are retried; see connectOne.
	// A one-shot caller (the list command) leaves this nil.
	Retry *RetryPolicy
}

// attemptTimeout returns the per-attempt connect bound, or zero for an
// unbounded attempt. The bound is tied to retry because it is retry that makes
// a timed-out attempt recoverable: without it, cutting off a slow-but-working
// backend would lose it until the next restart.
func (o ConnectOptions) attemptTimeout() time.Duration {
	if o.Retry == nil {
		return 0
	}
	return o.Retry.AttemptTimeout
}

// New connects to every configured backend synchronously, aggregates their tools
// and returns a ready Mux. It is used by callers that want the full catalog
// before proceeding (e.g. the `list` command); it blocks on any interactive
// OAuth consent. On zero connected backends it returns an error. The caller owns
// Close.
func New(ctx context.Context, cfg *config.Config, log *slog.Logger) (*Mux, error) {
	m := NewServer(cfg, log)
	// No retry policy: a one-shot caller must not linger on a backend that is
	// down. Backends are therefore either registered or skipped here.
	m.Connect(ctx, cfg.Backends, ConnectOptions{Eager: cfg.EagerAuth})
	if m.registeredCount() == 0 {
		m.Close()
		return nil, fmt.Errorf("no backends could be connected")
	}
	return m, nil
}

// Connect dials the given backends sequentially, registering each one's tools as
// it succeeds (one bad backend must not take down the proxy). Sequential
// iteration keeps interactive OAuth consents to one browser window at a time. A
// backend that fails is either kept for background retry or skipped, per
// opts.Retry. It returns the number of backends connected. Safe to call after
// the server has started serving: tool registration notifies connected clients
// via tools/list_changed.
func (m *Mux) Connect(ctx context.Context, backends []config.Backend, opts ConnectOptions) int {
	if len(backends) == 0 {
		return 0
	}
	connected := 0
	var pending, skipped []string
	for _, bc := range backends {
		n, isPending, err := m.connectOne(ctx, bc, opts)
		switch {
		case err == nil:
			m.log.Info("registered backend", "backend", bc.Name, "tools", n)
			connected++
		case isPending:
			m.log.Warn("backend pending; retrying in the background",
				"backend", bc.Name, "err", err)
			pending = append(pending, bc.Name)
		default:
			m.log.Warn("skipping backend", "backend", bc.Name, "err", err)
			skipped = append(skipped, bc.Name)
		}
	}
	m.logSummary(connected, pending, skipped)
	return connected
}

// logSummary records one grep-able line per Connect pass. Per-backend warnings
// scroll past and are easy to miss, so a pass where several backends did not
// come up is also reported as a single count of what is up, pending and
// skipped.
func (m *Mux) logSummary(connected int, pending, skipped []string) {
	if len(pending) == 0 && len(skipped) == 0 {
		m.log.Info("backends up", "connected", connected)
		return
	}
	m.log.Warn("backends up with failures",
		"connected", connected,
		"pending", len(pending), "pending_backends", strings.Join(pending, ","),
		"skipped", len(skipped), "skipped_backends", strings.Join(skipped, ","))
}

// ConnectInBackground connects the given backends in a goroutine so their
// interactive OAuth consents happen after the proxy is already serving, instead
// of blocking startup. Close waits for the goroutine to finish. A nil/empty
// slice is a no-op.
func (m *Mux) ConnectInBackground(ctx context.Context, backends []config.Backend, opts ConnectOptions) {
	if len(backends) == 0 {
		return
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.Connect(ctx, backends, opts)
	}()
}

// connectOne brings a single backend up and records it under m.mu. It returns
// the number of tools registered; on failure it reports whether the backend was
// kept for background retry (pending) or skipped for good.
//
// Retry is deliberately withheld from a backend that may open a browser: every
// attempt takes the process-wide auth mutex (serializing all other consents),
// rebinds the fixed callback port, and could pop a consent window the user
// never asked for. Such a backend is skipped on failure, as before, and
// recovered by RetryPendingNow or a restart.
func (m *Mux) connectOne(ctx context.Context, bc config.Backend, opts ConnectOptions) (tools int, pending bool, err error) {
	b, err := newBackend(bc, m.log)
	if err != nil {
		return 0, false, err
	}

	n, err := m.bringUp(ctx, b, opts)
	switch {
	case err == nil:
		m.add(b)
		// Watch the backend and reconnect it if its session dies. ctx is the
		// long-lived connect context (cancelled only at shutdown), so it bounds
		// the supervisor's lifetime and any reconnect's transport build.
		m.svg.Add(1)
		go m.run(ctx, b, opts, true)
		return n, false, nil
	case opts.Retry == nil || b.interactive:
		return 0, false, err
	default:
		// Keep the backend so its retry loop, Catalog and Close all see it; its
		// session stays nil until an attempt succeeds.
		m.add(b)
		m.svg.Add(1)
		go m.run(ctx, b, opts, false)
		return 0, true, err
	}
}

// bringUp opens a session for b and publishes its tools. Both halves have to
// succeed for the backend to be usable, so a failure in either is reported the
// same way and leaves no session behind for the caller to clean up.
func (m *Mux) bringUp(ctx context.Context, b *backend, opts ConnectOptions) (int, error) {
	if err := b.open(ctx, opts, m.log); err != nil {
		return 0, fmt.Errorf("connect failed: %w", err)
	}
	n, err := m.register(ctx, b, opts)
	if err != nil {
		if s := b.current(); s != nil {
			_ = s.Close()
		}
		b.session.Store(nil)
		return 0, fmt.Errorf("list tools failed: %w", err)
	}
	return n, nil
}

// add records a backend so Catalog, Close and RetryPendingNow can see it. A
// backend is added whether or not it has connected yet.
func (m *Mux) add(b *backend) {
	m.mu.Lock()
	m.backends = append(m.backends, b)
	m.mu.Unlock()
}

// registeredCount reports how many backends have published their tools, as
// opposed to merely being tracked while their retry loop works on them.
func (m *Mux) registeredCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, b := range m.backends {
		if b.registered {
			n++
		}
	}
	return n
}

// RetryPendingNow asks every backend still waiting on its first successful
// connect to attempt again immediately instead of waiting out its backoff, and
// returns how many were kicked. It is the daemon's recovery hook (see the
// SIGUSR1 handler): after refreshing whatever credential the backends need, one
// signal brings them up without the restart that would re-trigger every
// interactive OAuth consent. Sends are non-blocking, so a kick that arrives
// mid-attempt is coalesced into the next iteration.
func (m *Mux) RetryPendingNow() int {
	m.mu.Lock()
	kicked := 0
	for _, b := range m.backends {
		if b.registered {
			continue
		}
		select {
		case b.kick <- struct{}{}:
			kicked++
		default:
		}
	}
	m.mu.Unlock()
	m.log.Info("kicked pending backends", "backends", kicked)
	return kicked
}

// register pulls a backend's tool catalog and exposes each tool on the proxy
// server under "<backend>__<tool>", forwarding invocations to the backend. It is
// idempotent: a backend brought up by its retry loop must not publish its
// catalog twice, which would duplicate Catalog rows and re-notify clients.
func (m *Mux) register(ctx context.Context, b *backend, opts ConnectOptions) (int, error) {
	m.mu.Lock()
	registered, known := b.registered, len(b.tools)
	m.mu.Unlock()
	if registered {
		return known, nil
	}

	// Bound the round-trip for the same reason connect is bounded: a peer that
	// answers initialize and then stalls must not wedge the retry loop.
	listCtx := ctx
	if d := opts.attemptTimeout(); d > 0 {
		var cancel context.CancelFunc
		listCtx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}
	res, err := b.current().ListTools(listCtx, nil)
	if err != nil {
		return 0, fmt.Errorf("list tools for backend %q: %w", b.name, err)
	}

	// Collect into a local slice and publish it under m.mu at the end: Catalog
	// may read a late-registering backend's tools concurrently.
	var tools []ToolInfo
	for _, tool := range res.Tools {
		// Copy the tool verbatim and only re-namespace its name; the input
		// schema, description, etc. are forwarded to the client unchanged.
		proxied := *tool
		proxied.Name = toolName(b.name, tool.Name)
		// Front-load the backend's description onto the tool so the client's
		// model can tell which backend a tool belongs to (e.g. two AWS profiles
		// exposing identically-named tools).
		if b.desc != "" {
			proxied.Description = withBackendContext(b.desc, tool.Description)
		}
		// AddTool requires a non-nil object input schema; supply a permissive
		// default for backends that advertise none.
		if proxied.InputSchema == nil {
			proxied.InputSchema = map[string]any{"type": "object"}
		}

		// Capture the tool name for the closure. The session is read via
		// b.current() per call (not captured) so it follows a reconnect swap.
		origName := tool.Name

		m.server.AddTool(&proxied, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return b.current().CallTool(ctx, &mcp.CallToolParams{
				Name:      origName,
				Arguments: req.Params.Arguments,
			})
		})
		// Record the aggregated tool so Catalog can report it without a second
		// round-trip to the backend.
		tools = append(tools, ToolInfo{
			Backend:     b.name,
			Name:        proxied.Name,
			Description: tool.Description,
		})
		// At debug level, list each tool with its description (one line per tool).
		m.log.Debug("backend tool",
			"backend", b.name,
			"tool", origName,
			"description", tool.Description)
	}

	m.mu.Lock()
	b.tools, b.registered = tools, true
	m.mu.Unlock()
	return len(res.Tools), nil
}

// toolName builds the namespaced tool name exposed to the client.
func toolName(backend, tool string) string {
	return backend + "__" + tool
}

// withBackendContext front-loads a backend's description onto a tool's own
// description (kept first so it survives client-side truncation), so the
// client's model sees which backend a tool belongs to.
func withBackendContext(backendDesc, toolDesc string) string {
	if toolDesc == "" {
		return backendDesc
	}
	return backendDesc + "\n\n" + toolDesc
}

// serverOptions builds the proxy server's options. When any backend has a
// description, it sets server instructions listing each backend's "<name>__"
// prefix and description, which clients with tool search use to decide when to
// surface a backend's tools. Returns nil when no backend is described.
func serverOptions(cfg *config.Config) *mcp.ServerOptions {
	var lines []string
	for _, b := range cfg.Backends {
		if b.Description != "" {
			lines = append(lines, fmt.Sprintf("- %s__*: %s", b.Name, b.Description))
		}
	}
	if len(lines) == 0 {
		return nil
	}
	return &mcp.ServerOptions{
		Instructions: "Tools are namespaced as <backend>__<tool>, aggregated from these backends:\n" +
			strings.Join(lines, "\n"),
	}
}

// ToolInfo describes one aggregated tool for diagnostics.
type ToolInfo struct {
	Backend     string // backend name
	Name        string // namespaced name exposed to clients (<backend>__<tool>)
	Description string // tool description, as advertised by the backend
}

// Catalog returns the aggregated tools across all backends, captured when each
// backend was registered (no additional backend round-trips).
func (m *Mux) Catalog() []ToolInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ToolInfo
	for _, b := range m.backends {
		out = append(out, b.tools...)
	}
	return out
}

// ServeStdio runs the proxy over stdin/stdout until ctx is cancelled.
func (m *Mux) ServeStdio(ctx context.Context) error {
	m.log.Info("serving", "transport", "stdio")
	return m.server.Run(ctx, &mcp.StdioTransport{})
}

// ServeHTTP binds addr and serves the proxy over streamable HTTP. It returns
// when ctx is cancelled or on a fatal error.
func (m *Mux) ServeHTTP(ctx context.Context, addr, path string) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	return m.ServeHTTPListener(ctx, ln, path)
}

// httpHandler builds the HTTP handler for the proxy: the streamable-HTTP MCP
// endpoint mounted at path, wrapped in cross-origin protection. The wrapper
// rejects cross-origin browser requests (CSRF / defense-in-depth); non-browser
// clients, which send no Origin/Sec-Fetch-Site header, are unaffected. The SDK
// separately rejects DNS-rebinding (non-localhost Host) requests by default.
func (m *Mux) httpHandler(path string) http.Handler {
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return m.server }, nil)
	router := http.NewServeMux()
	router.Handle(path, mcpHandler)
	return http.NewCrossOriginProtection().Handler(router)
}

// ServeHTTPListener serves the proxy over streamable HTTP on an existing
// listener, mounting the single MCP endpoint at path. This is the entry point
// for systemd socket activation, where the listening socket is supplied by the
// service manager. It returns when ctx is cancelled or on a fatal error.
func (m *Mux) ServeHTTPListener(ctx context.Context, ln net.Listener, path string) error {
	srv := &http.Server{
		Handler:           m.httpHandler(path),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No ReadTimeout/WriteTimeout: streamable HTTP uses long-lived SSE
		// responses that a write deadline would sever.
	}

	// On shutdown, drain in-flight requests with a bounded grace period. ctx is
	// already cancelled here, so a fresh background context is required. The
	// serveDone channel lets this goroutine exit if Serve returns on its own
	// (e.g. a fatal error) before ctx is cancelled, rather than leaking.
	serveDone := make(chan struct{})
	defer close(serveDone)
	go func() { //nolint:gosec // G118: the request context is intentionally not reused (it is done).
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := srv.Shutdown(shutdownCtx); err != nil {
				_ = srv.Close()
			}
		case <-serveDone:
		}
	}()

	m.log.Info("serving", "transport", "http", "address", ln.Addr().String(), "path", path)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Close shuts down every backend session. It first marks the Mux as closing (so
// supervisors treat the impending session closures as intentional and do not
// reconnect), cancels the per-backend goroutines directly — otherwise one
// sleeping out a retry backoff would stall shutdown for as long as its current
// delay — and waits for any in-flight background Connect to return (the
// caller is expected to have cancelled the context, which aborts an in-progress
// connect/consent) so closing sessions cannot race the goroutine that registers
// them. Closing each session unblocks its supervisor's Wait; once all sessions
// are closed it waits for the supervisors to exit.
func (m *Mux) Close() {
	m.closing.Store(true)
	m.closeOnce.Do(m.closeCancel)
	m.wg.Wait()
	m.mu.Lock()
	for _, b := range m.backends {
		if s := b.current(); s != nil {
			_ = s.Close()
		}
	}
	m.mu.Unlock()
	m.svg.Wait()
}
