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
	"testing"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
)

// drives fetch and the loopback callback, returning fetch's result. It retries
// the callback GET until fetch has registered its waiter (avoiding a race on
// startup), or fails the test on timeout.
func driveCallback(t *testing.T, query string) (*sdkauth.AuthorizationResult, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a, err := newBrowserAuthorizer(ctx, "test", 0, false, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("newBrowserAuthorizer: %v", err)
	}

	type result struct {
		r *sdkauth.AuthorizationResult
		e error
	}
	done := make(chan result, 1)
	go func() {
		r, e := a.fetch(ctx, &sdkauth.AuthorizationArgs{URL: "http://example.test/authorize"})
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
	// Grab a free port, then ask the authorizer to bind it explicitly.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

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
