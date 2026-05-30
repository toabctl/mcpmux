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

	"mcpmux/internal/config"

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
		server: mcp.NewServer(&mcp.Implementation{Name: clientName, Version: clientVersion}, nil),
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

// ToolInfo describes one aggregated tool for diagnostics.
type ToolInfo struct {
	Backend     string // backend name
	Name        string // namespaced name exposed to clients (<backend>__<tool>)
	Description string // tool description, as advertised by the backend
}

// Catalog returns the aggregated tools across all backends, with descriptions.
func (m *Mux) Catalog(ctx context.Context) ([]ToolInfo, error) {
	var out []ToolInfo
	for _, b := range m.backends {
		res, err := b.session.ListTools(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("list tools for backend %q: %w", b.name, err)
		}
		for _, t := range res.Tools {
			out = append(out, ToolInfo{
				Backend:     b.name,
				Name:        toolName(b.name, t.Name),
				Description: t.Description,
			})
		}
	}
	return out, nil
}

// ServeStdio runs the proxy over stdin/stdout until ctx is cancelled.
func (m *Mux) ServeStdio(ctx context.Context) error {
	m.log.Info("serving", "transport", "stdio")
	return m.server.Run(ctx, &mcp.StdioTransport{})
}

// ServeHTTP binds addr and serves the proxy over streamable HTTP. It returns
// when ctx is cancelled or on a fatal error.
func (m *Mux) ServeHTTP(ctx context.Context, addr, path string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	return m.ServeHTTPListener(ctx, ln, path)
}

// ServeHTTPListener serves the proxy over streamable HTTP on an existing
// listener, mounting the single MCP endpoint at path. This is the entry point
// for systemd socket activation, where the listening socket is supplied by the
// service manager. It returns when ctx is cancelled or on a fatal error.
func (m *Mux) ServeHTTPListener(ctx context.Context, ln net.Listener, path string) error {
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return m.server }, nil)

	router := http.NewServeMux()
	router.Handle(path, handler)
	srv := &http.Server{Handler: router}

	go func() {
		<-ctx.Done()
		_ = srv.Close()
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
