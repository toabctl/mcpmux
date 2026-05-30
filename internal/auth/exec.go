// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

// Package auth provides credential mechanisms for mcpmux's backend
// connections. The exec credential helper obtains a bearer token by running an
// external command (e.g. "chainctl auth token --audience <resource>"),
// re-running it only when the cached token is near expiry or has been rejected.
//
// The types here implement golang.org/x/oauth2.TokenSource and the MCP SDK's
// auth.OAuthHandler interface (structurally), so they plug directly into a
// streamable-HTTP transport without this package depending on the SDK.
package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// execTimeout bounds a single credential-helper invocation.
const execTimeout = 30 * time.Second

// runnerFunc executes a credential helper and returns its stdout. It is a seam
// for testing.
type runnerFunc func(ctx context.Context, argv []string) ([]byte, error)

// ExecTokenSource is an oauth2.TokenSource that runs an external command to
// mint a bearer token, caching it until shortly before it expires. It is safe
// for concurrent use.
type ExecTokenSource struct {
	ctx    context.Context
	argv   []string
	ttl    time.Duration // fallback validity for non-JWT tokens
	leeway time.Duration // refresh this long before expiry

	runner runnerFunc
	now    func() time.Time

	mu  sync.Mutex
	cur *oauth2.Token
}

// NewExecTokenSource returns a token source that runs argv to obtain tokens.
// ttl caps how long an opaque (non-JWT) token is cached; for JWTs the "exp"
// claim takes precedence. ctx bounds the lifetime of all invocations.
func NewExecTokenSource(ctx context.Context, argv []string, ttl time.Duration) *ExecTokenSource {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &ExecTokenSource{
		ctx:    ctx,
		argv:   argv,
		ttl:    ttl,
		leeway: 30 * time.Second,
		runner: defaultRunner,
		now:    time.Now,
	}
}

// Token returns a cached token if still valid, otherwise runs the command.
func (s *ExecTokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cur != nil && s.now().Before(s.cur.Expiry.Add(-s.leeway)) {
		return s.cur, nil
	}

	cctx, cancel := context.WithTimeout(s.ctx, execTimeout)
	defer cancel()

	out, err := s.runner(cctx, s.argv)
	if err != nil {
		return nil, fmt.Errorf("token command %q failed: %w", s.argv[0], err)
	}
	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return nil, fmt.Errorf("token command %q produced no output", s.argv[0])
	}

	tok := &oauth2.Token{AccessToken: raw} // empty TokenType => "Bearer"
	if exp, ok := jwtExpiry(raw); ok {
		tok.Expiry = exp
	} else {
		tok.Expiry = s.now().Add(s.ttl)
	}
	s.cur = tok
	return tok, nil
}

// Invalidate drops the cached token so the next Token call re-runs the command.
func (s *ExecTokenSource) Invalidate() {
	s.mu.Lock()
	s.cur = nil
	s.mu.Unlock()
}

// ExecHandler adapts an ExecTokenSource to the MCP SDK's auth.OAuthHandler
// interface: the transport sets the bearer header from TokenSource on every
// request, and calls Authorize on a 401/403 to force a fresh token.
type ExecHandler struct {
	ts *ExecTokenSource
}

// NewExecHandler wraps an ExecTokenSource as an OAuthHandler.
func NewExecHandler(ts *ExecTokenSource) *ExecHandler {
	return &ExecHandler{ts: ts}
}

// TokenSource returns the underlying token source.
func (h *ExecHandler) TokenSource(context.Context) (oauth2.TokenSource, error) {
	return h.ts, nil
}

// Authorize is invoked by the transport when a request fails with 401/403. It
// discards the cached token and mints a fresh one; on success the transport
// retries the request. It is responsible for closing the response body.
func (h *ExecHandler) Authorize(_ context.Context, _ *http.Request, resp *http.Response) error {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	h.ts.Invalidate()
	if _, err := h.ts.Token(); err != nil {
		return err
	}
	return nil
}

// defaultRunner executes argv with the process environment, returning stdout.
func defaultRunner(ctx context.Context, argv []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = os.Environ()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("%w: %s", err, msg)
		}
		return nil, err
	}
	return stdout.Bytes(), nil
}

// jwtExpiry extracts the "exp" claim from a JWT without verifying its
// signature (the token comes from a trusted local helper). It returns ok=false
// for anything that is not a well-formed JWT with an exp claim.
func jwtExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0), true
}
