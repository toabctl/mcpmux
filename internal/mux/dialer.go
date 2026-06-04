// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package mux

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/toabctl/mcpmux/internal/auth"
	"github.com/toabctl/mcpmux/internal/config"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// dialer produces a connectable transport for one backend. It is the single
// seam the connect path uses, so the rest of the mux is oblivious to how a
// backend is reached. dial is called once at startup and again on every
// reconnect: a dialer wrapping a single-use resource (a subprocess) returns a
// fresh transport each call, whereas one wrapping a reusable, token-holding
// transport (HTTP) returns the same instance so its cached OAuth credentials
// survive a reconnect.
//
// Implementing dialer is all a new backend transport kind needs to gain
// connect (and, later, reconnect). Optional capability interfaces layer extra
// features on top and are discovered by type assertion — see eagerAuthorizer.
type dialer interface {
	dial(ctx context.Context) (mcp.Transport, error)
}

// eagerAuthorizer is implemented by dialers that can complete an interactive
// browser consent up front — only the OAuth authorization-code (PKCE) flow.
// The connect path discovers it by type assertion: a backend whose dialer
// satisfies it is treated as interactive (connected in the background, with its
// consent batched at startup); one that does not connects with no human in the
// loop.
type eagerAuthorizer interface {
	eagerAuthorize(ctx context.Context) error
}

// newDialer builds the dialer for a backend from its transport/auth config.
// It is cheap and side-effect-free: the transport (and any OAuth callback
// server or credential-helper invocation) is constructed lazily in dial, so
// newDialer is safe to call merely to inspect a backend's capabilities (see
// isInteractive).
func newDialer(b config.Backend, log *slog.Logger) (dialer, error) {
	switch b.Transport {
	case config.TransportCommand:
		return &commandDialer{b: b, log: log}, nil
	case config.TransportHTTP:
		h := &httpDialer{b: b, log: log}
		if b.Auth.Type == config.AuthOAuth {
			return &oauthDialer{httpDialer: h}, nil
		}
		return h, nil
	default:
		return nil, fmt.Errorf("backend %q: unsupported transport %q", b.Name, b.Transport)
	}
}

// commandDialer runs a backend as a subprocess. A child process is single-use:
// exec.Cmd cannot be restarted, so every dial builds a fresh CommandTransport,
// which on reconnect re-spawns the subprocess.
type commandDialer struct {
	b   config.Backend
	log *slog.Logger
}

func (d *commandDialer) dial(ctx context.Context) (mcp.Transport, error) {
	return transportFor(ctx, d.b, d.log)
}

// httpDialer reaches a backend over streamable HTTP with static or
// helper-command credentials. The transport is built once and cached: returning
// the same instance on every dial means a reconnect reuses the established
// credential plumbing rather than rebuilding it.
type httpDialer struct {
	b   config.Backend
	log *slog.Logger

	mu sync.Mutex
	tr *mcp.StreamableClientTransport
}

func (d *httpDialer) dial(ctx context.Context) (mcp.Transport, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.tr == nil {
		tr, err := transportFor(ctx, d.b, d.log)
		if err != nil {
			return nil, err
		}
		// transportFor always returns a *mcp.StreamableClientTransport for the
		// HTTP transport; capture the concrete type so capabilities (e.g. OAuth
		// eager authorization) can reach the OAuthHandler.
		d.tr = tr.(*mcp.StreamableClientTransport)
	}
	return d.tr, nil
}

// oauthDialer is an httpDialer whose credentials come from the interactive
// authorization-code (PKCE) flow. It additionally satisfies eagerAuthorizer:
// because dial caches the transport, the eager consent and the live connection
// share one OAuthHandler, so the token obtained at startup is the one used for
// requests (and preserved across reconnects).
type oauthDialer struct {
	*httpDialer
}

func (d *oauthDialer) eagerAuthorize(ctx context.Context) error {
	tr, err := d.dial(ctx)
	if err != nil {
		return err
	}
	st := tr.(*mcp.StreamableClientTransport)
	return auth.EagerAuthorize(ctx, st.OAuthHandler, d.b.Endpoint, d.b.Name, d.log)
}

// isInteractive reports whether bringing a backend up may open a browser for an
// interactive OAuth consent, derived from whether its dialer can eagerly
// authorize. Everything else (command transports, static or helper-command
// credentials) connects without human interaction.
func isInteractive(b config.Backend) bool {
	d, err := newDialer(b, nil)
	if err != nil {
		return false
	}
	_, ok := d.(eagerAuthorizer)
	return ok
}
