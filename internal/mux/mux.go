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
	log      *slog.Logger
	server   *mcp.Server
	backends []*backend
}

// New connects to every configured backend, aggregates their tools onto a
// single proxy server and returns a ready-to-serve Mux. On any error the
// already-opened backends are closed before returning. The caller owns Close.
func New(ctx context.Context, cfg *config.Config, log *slog.Logger) (*Mux, error) {
	m := &Mux{
		log:    log,
		server: mcp.NewServer(&mcp.Implementation{Name: clientName, Version: clientVersion}, serverOptions(cfg)),
	}
	// Debug-log every inbound request from the client (no-op unless --log-level debug).
	m.server.AddReceivingMiddleware(requestLogger(log))

	for _, bc := range cfg.Backends {
		// A single bad backend (auth failure, server down) must not take down
		// the whole proxy: log it and carry on with the rest.
		b, err := connectBackend(ctx, bc, log)
		if err != nil {
			log.Warn("skipping backend: connect failed", "backend", bc.Name, "err", err)
			continue
		}
		b.desc = bc.Description

		n, err := m.register(ctx, b)
		if err != nil {
			log.Warn("skipping backend: list tools failed", "backend", bc.Name, "err", err)
			_ = b.session.Close()
			continue
		}

		m.backends = append(m.backends, b)
		log.Info("registered backend", "backend", b.name, "tools", n)
	}

	if len(m.backends) == 0 {
		m.Close()
		return nil, fmt.Errorf("no backends could be connected")
	}
	return m, nil
}

// register pulls a backend's tool catalog and exposes each tool on the proxy
// server under "<backend>__<tool>", forwarding invocations to the backend.
func (m *Mux) register(ctx context.Context, b *backend) (int, error) {
	res, err := b.session.ListTools(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("list tools for backend %q: %w", b.name, err)
	}

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

		// Capture per-tool values for the closure.
		session := b.session
		origName := tool.Name

		m.server.AddTool(&proxied, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return session.CallTool(ctx, &mcp.CallToolParams{
				Name:      origName,
				Arguments: req.Params.Arguments,
			})
		})
		// Record the aggregated tool so Catalog can report it without a second
		// round-trip to the backend.
		b.tools = append(b.tools, ToolInfo{
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

// Close shuts down every backend session.
func (m *Mux) Close() {
	for _, b := range m.backends {
		if b.session != nil {
			_ = b.session.Close()
		}
	}
}
