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

// backend is a live client session to one upstream MCP server.
type backend struct {
	name    string
	desc    string // optional operator description, surfaced to the client
	session *mcp.ClientSession
	// tools is the backend's aggregated tool catalog, captured at registration
	// so Catalog can report it without re-querying the backend.
	tools []ToolInfo
}

// connectBackend dials a single upstream server and returns an open session.
func connectBackend(ctx context.Context, b config.Backend, log *slog.Logger) (*backend, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: clientName, Version: clientVersion}, nil)

	transport, err := transportFor(ctx, b, log)
	if err != nil {
		return nil, err
	}

	// Interactive OAuth blocks on the user; bound it so a walked-away browser
	// prompt doesn't hang startup forever (the backend is then skipped).
	connectCtx := ctx
	if b.Transport == config.TransportHTTP && b.Auth.Type == config.AuthOAuth {
		var cancel context.CancelFunc
		connectCtx, cancel = context.WithTimeout(ctx, oauthConnectTimeout)
		defer cancel()
	}

	session, err := client.Connect(connectCtx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("connect backend %q: %w", b.Name, err)
	}
	return &backend{name: b.Name, session: session}, nil
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
				Label:        b.Name,
				Scopes:       b.Auth.Scopes,
				ClientName:   b.Auth.ClientName,
				OpenBrowser:  b.Auth.OpenBrowserEnabled(),
				CallbackPort: b.Auth.CallbackPort,
				ClientID:     clientID,
				ClientSecret: clientSecret,
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
