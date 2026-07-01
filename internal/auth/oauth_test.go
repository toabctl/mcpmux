// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
)

// TestHandleCallbackAutoClose verifies the auto-close script is emitted only on
// the success page, not on the error or no-authorization pages.
func TestHandleCallbackAutoClose(t *testing.T) {
	tests := []struct {
		name          string
		waiting       bool // a receiver is registered, so delivery succeeds
		query         string
		wantTitle     string
		wantAutoClose bool
	}{
		{"success", true, "code=abc&state=xyz", "Authorization complete", true},
		{"error", true, "error=access_denied", "Authorization failed", false},
		{"no auth in progress", false, "code=abc", "No authorization in progress", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &browserAuthorizer{}
			if tt.waiting {
				a.waiting = make(chan callbackResult, 1)
			}
			rec := httptest.NewRecorder()
			a.handleCallback(rec, httptest.NewRequest(http.MethodGet, "/callback?"+tt.query, nil))
			body := rec.Body.String()
			if !strings.Contains(body, tt.wantTitle) {
				t.Errorf("body missing title %q: %s", tt.wantTitle, body)
			}
			if got := strings.Contains(body, "window.close()"); got != tt.wantAutoClose {
				t.Errorf("auto-close present = %v, want %v", got, tt.wantAutoClose)
			}
		})
	}
}

// freePort returns a currently-free loopback TCP port.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// driveFetch runs a.fetch and the loopback callback concurrently, returning
// fetch's result. It retries the callback GET until fetch has registered its
// waiter (avoiding a race on startup), or fails the test on timeout.
func driveFetch(t *testing.T, a *browserAuthorizer, query string) (*sdkauth.AuthorizationResult, error) {
	t.Helper()
	type result struct {
		r *sdkauth.AuthorizationResult
		e error
	}
	done := make(chan result, 1)
	go func() {
		r, e := a.fetch(context.Background(), &sdkauth.AuthorizationArgs{URL: "http://example.test/authorize"})
		done <- result{r, e}
	}()

	for i := 0; i < 200; i++ {
		if resp, err := http.Get(a.redirect + "?" + query); err == nil {
			_ = resp.Body.Close()
		}
		select {
		case res := <-done:
			return res.r, res.e
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatal("fetch did not complete")
	return nil, nil
}

// drives fetch and the loopback callback for an ephemeral-port authorizer.
func driveCallback(t *testing.T, query string) (*sdkauth.AuthorizationResult, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a, err := newBrowserAuthorizer(ctx, "test", 0, false, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("newBrowserAuthorizer: %v", err)
	}
	return driveFetch(t, a, query)
}

func TestBrowserAuthorizer_Success(t *testing.T) {
	r, err := driveCallback(t, "code=the-code&state=the-state")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if r.Code != "the-code" || r.State != "the-state" {
		t.Errorf("got code=%q state=%q", r.Code, r.State)
	}
}

func TestBrowserAuthorizer_ErrorParam(t *testing.T) {
	r, err := driveCallback(t, "error=access_denied")
	if err == nil {
		t.Fatalf("expected error, got result %+v", r)
	}
}

// TestBrowserAuthorizer_FixedPort checks that a configured callback_port is
// honored in the redirect URI (0 would pick an ephemeral port instead).
func TestBrowserAuthorizer_FixedPort(t *testing.T) {
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, err := newBrowserAuthorizer(ctx, "x", port, false, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("newBrowserAuthorizer: %v", err)
	}
	want := fmt.Sprintf("http://127.0.0.1:%d/callback", port)
	if a.redirect != want {
		t.Errorf("redirect = %q, want %q", a.redirect, want)
	}
}

// TestBrowserAuthorizer_FixedPortLazy verifies a fixed callback port is bound
// only while a flow runs: it is free at construction, free again after fetch,
// and can therefore be reused by another authorizer (the basis for sharing one
// callback_port across backends).
func TestBrowserAuthorizer_FixedPortLazy(t *testing.T) {
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	a, err := newBrowserAuthorizer(ctx, "x", port, false, log)
	if err != nil {
		t.Fatalf("newBrowserAuthorizer: %v", err)
	}
	// Construction must not hold the port.
	if ln, err := net.Listen("tcp", addr); err != nil {
		t.Fatalf("port held at construction, want lazy binding: %v", err)
	} else {
		_ = ln.Close()
	}

	if r, err := driveFetch(t, a, "code=c&state=s"); err != nil || r == nil || r.Code != "c" {
		t.Fatalf("first fetch: r=%+v err=%v", r, err)
	}
	// Port must be released after the flow, so a second authorizer can reuse it.
	b, err := newBrowserAuthorizer(ctx, "y", port, false, log)
	if err != nil {
		t.Fatalf("newBrowserAuthorizer (reuse): %v", err)
	}
	if r, err := driveFetch(t, b, "code=c2&state=s2"); err != nil || r == nil || r.Code != "c2" {
		t.Fatalf("second fetch on shared port: r=%+v err=%v", r, err)
	}
	if ln, err := net.Listen("tcp", addr); err != nil {
		t.Fatalf("port not released after fetch: %v", err)
	} else {
		_ = ln.Close()
	}
}

func TestNewOAuthHandler_PreregisteredClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h, err := NewOAuthHandler(ctx, log, OAuthOptions{Label: "x", ClientID: "cid", ClientSecret: "csecret"})
	if err != nil {
		t.Fatalf("preregistered client: %v", err)
	}
	if h == nil {
		t.Fatal("nil handler")
	}
}

func TestNewOAuthHandler_DynamicRegistration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h, err := NewOAuthHandler(ctx, log, OAuthOptions{Label: "x"}) // no ClientID -> DCR
	if err != nil {
		t.Fatalf("dynamic registration: %v", err)
	}
	if h == nil {
		t.Fatal("nil handler")
	}
}

func TestClientMetadata(t *testing.T) {
	m := clientMetadata(OAuthOptions{Scopes: []string{"read", "write"}}, "http://127.0.0.1:1/callback")
	if m.ClientName != "mcpmux" {
		t.Errorf("default ClientName = %q, want mcpmux", m.ClientName)
	}
	if m.Scope != "read write" {
		t.Errorf("Scope = %q, want %q", m.Scope, "read write")
	}
	if len(m.RedirectURIs) != 1 || m.RedirectURIs[0] != "http://127.0.0.1:1/callback" {
		t.Errorf("RedirectURIs = %v", m.RedirectURIs)
	}
	if m.TokenEndpointAuthMethod != "none" {
		t.Errorf("TokenEndpointAuthMethod = %q, want none", m.TokenEndpointAuthMethod)
	}

	custom := clientMetadata(OAuthOptions{ClientName: "myapp"}, "x")
	if custom.ClientName != "myapp" {
		t.Errorf("custom ClientName = %q, want myapp", custom.ClientName)
	}
	if custom.Scope != "" {
		t.Errorf("empty scopes should yield empty Scope, got %q", custom.Scope)
	}
}
