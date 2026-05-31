// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package mux

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/toabctl/mcpmux/internal/config"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// testCtx returns a context that is cancelled when the test finishes, so any
// background callback server started by an OAuth backend shuts down.
func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}

func TestTransportFor_CommandPassesArgvAndEnv(t *testing.T) {
	b := config.Backend{
		Name:      "x",
		Transport: config.TransportCommand,
		Command:   []string{"echo", "hi"},
		Env:       map[string]string{"MCPMUX_TEST_VAR": "value123"},
	}
	tr, err := transportFor(testCtx(t), b, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	ct, ok := tr.(*mcp.CommandTransport)
	if !ok {
		t.Fatalf("got %T, want *mcp.CommandTransport", tr)
	}
	if got := ct.Command.Args; len(got) != 2 || got[0] != "echo" || got[1] != "hi" {
		t.Errorf("argv = %v, want [echo hi]", got)
	}
	if !slices.Contains(ct.Command.Env, "MCPMUX_TEST_VAR=value123") {
		t.Errorf("env does not contain the configured var; got %v", ct.Command.Env)
	}
}

// TestTransportFor_HTTPAuthHeaders verifies that bearer/header auth actually
// attaches the right header to outgoing requests, and that none sends nothing.
func TestTransportFor_HTTPAuthHeaders(t *testing.T) {
	tests := []struct {
		name   string
		auth   config.Auth
		header string
		want   string // expected value the server receives ("" = header absent)
	}{
		{"bearer", config.Auth{Type: config.AuthBearer, Token: "tok123"}, "Authorization", "Bearer tok123"},
		{"header", config.Auth{Type: config.AuthHeader, Header: "X-Api-Key", Value: "secret"}, "X-Api-Key", "secret"},
		{"none", config.Auth{Type: config.AuthNone}, "Authorization", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Echo the header back in the body so the read is race-free.
				_, _ = io.WriteString(w, r.Header.Get(tc.header))
			}))
			defer srv.Close()

			b := config.Backend{Name: "x", Transport: config.TransportHTTP, Endpoint: srv.URL, Auth: tc.auth}
			tr, err := transportFor(testCtx(t), b, testLogger())
			if err != nil {
				t.Fatal(err)
			}
			st, ok := tr.(*mcp.StreamableClientTransport)
			if !ok {
				t.Fatalf("got %T, want *mcp.StreamableClientTransport", tr)
			}
			if st.Endpoint != srv.URL {
				t.Errorf("endpoint = %q, want %q", st.Endpoint, srv.URL)
			}

			client := st.HTTPClient
			if client == nil {
				if tc.want != "" {
					t.Fatalf("HTTPClient is nil but expected header %q", tc.want)
				}
				client = http.DefaultClient // none: default client, no injected header
			}
			resp, err := client.Get(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if string(body) != tc.want {
				t.Errorf("server saw %s=%q, want %q", tc.header, string(body), tc.want)
			}
		})
	}
}

// TestTransportFor_HTTPSetsOAuthHandler covers command + oauth auth: both must
// install an OAuthHandler (and no static HTTP client).
func TestTransportFor_HTTPSetsOAuthHandler(t *testing.T) {
	tests := []struct {
		name string
		auth config.Auth
	}{
		{"command", config.Auth{Type: config.AuthCommand, Command: []string{"true"}}},
		{"oauth", config.Auth{Type: config.AuthOAuth}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := config.Backend{Name: "x", Transport: config.TransportHTTP, Endpoint: "https://example.test/mcp", Auth: tc.auth}
			tr, err := transportFor(testCtx(t), b, testLogger())
			if err != nil {
				t.Fatal(err)
			}
			st := tr.(*mcp.StreamableClientTransport)
			if st.OAuthHandler == nil {
				t.Error("expected OAuthHandler to be set")
			}
			if st.HTTPClient != nil {
				t.Error("did not expect a static HTTPClient when an OAuthHandler is used")
			}
		})
	}
}

func TestTransportFor_UnsupportedTransport(t *testing.T) {
	b := config.Backend{Name: "x", Transport: "bogus"}
	if _, err := transportFor(testCtx(t), b, testLogger()); err == nil {
		t.Error("expected an error for an unsupported transport")
	}
}
