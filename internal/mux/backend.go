// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package mux

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"sync/atomic"
	"time"

	"github.com/toabctl/mcpmux/internal/auth"
	"github.com/toabctl/mcpmux/internal/config"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// oauthConnectTimeout bounds how long startup waits for an interactive browser
// authorization before giving up on that backend (which is then skipped, so the
// proxy still comes up with the others). Keep below the service's
// TimeoutStartSec so mcpmux degrades gracefully rather than being killed.
const oauthConnectTimeout = 10 * time.Minute

// keepaliveInterval pings an otherwise idle backend so a half-open connection
// is detected and closed promptly, waking the supervisor to reconnect.
const keepaliveInterval = 30 * time.Second

// backend is a live client session to one upstream MCP server. The session is
// swapped atomically when the supervisor reconnects a dropped backend, so the
// dialer (which knows how to re-establish the transport) is retained.
type backend struct {
	name   string
	desc   string // optional operator description, surfaced to the client
	dialer dialer // re-establishes the transport on (re)connect
	// session is the live client session, replaced atomically on reconnect;
	// read it per request via current() rather than capturing it.
	session atomic.Pointer[mcp.ClientSession]
	// tools is the backend's aggregated tool catalog, captured at registration
	// so Catalog can report it without re-querying the backend.
	tools []ToolInfo
}

// current returns the backend's live session.
func (b *backend) current() *mcp.ClientSession { return b.session.Load() }

// connect dials the backend and opens a fresh session. The transport is built
// with ctx (long-lived); an interactive backend's Connect is bounded so a
// walked-away browser prompt can't hang forever. Used for both the initial
// connect and every reconnect. KeepAlive lets the SDK notice a dead peer and
// close the session, which the supervisor observes via session.Wait.
func (b *backend) connect(ctx context.Context) (*mcp.ClientSession, error) {
	transport, err := b.dialer.dial(ctx)
	if err != nil {
		return nil, err
	}
	connectCtx := ctx
	if _, interactive := b.dialer.(eagerAuthorizer); interactive {
		var cancel context.CancelFunc
		connectCtx, cancel = context.WithTimeout(ctx, oauthConnectTimeout)
		defer cancel()
	}
	client := mcp.NewClient(&mcp.Implementation{Name: clientName, Version: clientVersion},
		&mcp.ClientOptions{KeepAlive: keepaliveInterval})
	return client.Connect(connectCtx, transport, nil)
}

// PartitionBackends splits backends into those that connect without human
// interaction and those that may prompt for an interactive OAuth consent,
// preserving config order within each group. A daemon connects the
// non-interactive group synchronously (so its tools and systemd readiness are
// immediate) and the interactive group in the background.
func PartitionBackends(backends []config.Backend) (noninteractive, interactive []config.Backend) {
	for _, b := range backends {
		if isInteractive(b) {
			interactive = append(interactive, b)
		} else {
			noninteractive = append(noninteractive, b)
		}
	}
	return noninteractive, interactive
}

// connectBackend dials a single upstream server and returns an open session.
// When eager is set, an interactive OAuth backend that did not authorize during
// connect (its server's initialize returned 200 rather than a 401) is driven
// through its authorization flow now, so all browser consents happen at startup.
func connectBackend(ctx context.Context, bc config.Backend, eager bool, log *slog.Logger) (*backend, error) {
	d, err := newDialer(bc, log)
	if err != nil {
		return nil, err
	}
	b := &backend{name: bc.Name, dialer: d}

	session, err := b.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect backend %q: %w", bc.Name, err)
	}
	b.session.Store(session)

	// Batch all interactive consents at startup rather than letting them pop up
	// on a later tool call. Best-effort: if it fails (e.g. the user dismisses the
	// window), the backend stays up and authorizes lazily on first use instead.
	// The dialer caches its transport, so this consent and the live session
	// share one OAuthHandler.
	if eager {
		if ea, ok := d.(eagerAuthorizer); ok {
			ectx, cancel := context.WithTimeout(ctx, oauthConnectTimeout)
			if err := ea.eagerAuthorize(ectx); err != nil {
				log.Warn("eager auth failed; backend will authorize lazily", "backend", bc.Name, "err", err)
			}
			cancel()
		}
	}
	return b, nil
}

// transportFor builds the client transport for a backend from its config. ctx
// bounds the lifetime of any credential-helper invocations or OAuth callback
// servers the transport owns.
func transportFor(ctx context.Context, b config.Backend, log *slog.Logger) (mcp.Transport, error) {
	switch b.Transport {
	case config.TransportCommand:
		//nolint:gosec // G204: the backend command is operator-supplied config, not external input.
		cmd := exec.CommandContext(ctx, b.Command[0], b.Command[1:]...)
		// Inherit the parent environment, then layer the backend's secrets on top.
		cmd.Env = os.Environ()
		for k, v := range b.Env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
		// Surface the subprocess's diagnostics on our stderr.
		cmd.Stderr = os.Stderr
		return &mcp.CommandTransport{Command: cmd}, nil

	case config.TransportHTTP:
		t := &mcp.StreamableClientTransport{Endpoint: b.Endpoint}
		switch b.Auth.Type {
		case config.AuthCommand:
			// Dynamic bearer token from a credential helper; the transport
			// sets the header from this source and refreshes via Authorize.
			ts := auth.NewExecTokenSource(ctx, b.Auth.Command, b.Auth.TokenTTL())
			t.OAuthHandler = auth.NewExecHandler(ts)
		case config.AuthOAuth:
			// Interactive authorization-code + PKCE flow. Uses dynamic client
			// registration by default, or a pre-registered client when
			// client_id is configured (literal/${ENV} or a helper command).
			clientID, err := resolveValue(ctx, b.Auth.ClientID, b.Auth.ClientIDCommand)
			if err != nil {
				return nil, fmt.Errorf("backend %q: auth.client_id: %w", b.Name, err)
			}
			clientSecret, err := resolveValue(ctx, b.Auth.ClientSecret, b.Auth.ClientSecretCommand)
			if err != nil {
				return nil, fmt.Errorf("backend %q: auth.client_secret: %w", b.Name, err)
			}
			h, err := auth.NewOAuthHandler(ctx, log, auth.OAuthOptions{
				Label:               b.Name,
				Scopes:              b.Auth.Scopes,
				ClientName:          b.Auth.ClientName,
				OpenBrowser:         b.Auth.OpenBrowserEnabled(),
				CallbackPort:        b.Auth.CallbackPort,
				ClientID:            clientID,
				ClientSecret:        clientSecret,
				AllowIssuerMismatch: b.Auth.AllowIssuerMismatch,
			})
			if err != nil {
				return nil, err
			}
			t.OAuthHandler = h
		default:
			// Static credentials (bearer/header) or none. Scope the credential
			// to the backend host so a redirect cannot leak it elsewhere.
			key, value := b.Auth.HTTPHeader()
			host := ""
			if u, err := url.Parse(b.Endpoint); err == nil {
				host = u.Host
			}
			t.HTTPClient = httpClientFor(host, key, value)
		}
		return t, nil

	default:
		return nil, fmt.Errorf("backend %q: unsupported transport %q", b.Name, b.Transport)
	}
}

// resolveValue returns literal when set; otherwise, when command is non-empty,
// runs it and returns its trimmed stdout. Both empty yields "" (a valid absent
// optional credential). Config validation guarantees literal and command are
// not both set.
func resolveValue(ctx context.Context, literal string, command []string) (string, error) {
	if literal != "" {
		return literal, nil
	}
	if len(command) > 0 {
		return auth.RunString(ctx, command)
	}
	return "", nil
}
