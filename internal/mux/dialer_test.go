// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package mux

import (
	"testing"

	"github.com/toabctl/mcpmux/internal/config"
)

// TestNewDialer_Capabilities verifies that newDialer maps transport/auth config
// to the right dialer kind and that only interactive OAuth backends advertise
// the eagerAuthorizer capability.
func TestNewDialer_Capabilities(t *testing.T) {
	tests := []struct {
		name        string
		backend     config.Backend
		interactive bool // expected: dialer implements eagerAuthorizer
	}{
		{"command", config.Backend{Name: "c", Transport: config.TransportCommand, Command: []string{"true"}}, false},
		{"http-none", config.Backend{Name: "n", Transport: config.TransportHTTP, Endpoint: "https://x.test", Auth: config.Auth{Type: config.AuthNone}}, false},
		{"http-bearer", config.Backend{Name: "b", Transport: config.TransportHTTP, Endpoint: "https://x.test", Auth: config.Auth{Type: config.AuthBearer}}, false},
		{"http-command", config.Backend{Name: "hc", Transport: config.TransportHTTP, Endpoint: "https://x.test", Auth: config.Auth{Type: config.AuthCommand, Command: []string{"true"}}}, false},
		{"http-oauth", config.Backend{Name: "o", Transport: config.TransportHTTP, Endpoint: "https://x.test", Auth: config.Auth{Type: config.AuthOAuth}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := newDialer(tc.backend, testLogger())
			if err != nil {
				t.Fatalf("newDialer: %v", err)
			}
			if _, ok := d.(eagerAuthorizer); ok != tc.interactive {
				t.Errorf("eagerAuthorizer capability = %v, want %v", ok, tc.interactive)
			}
			// isInteractive must agree with the capability it is derived from.
			if got := isInteractive(tc.backend); got != tc.interactive {
				t.Errorf("isInteractive = %v, want %v", got, tc.interactive)
			}
		})
	}
}

func TestNewDialer_UnsupportedTransport(t *testing.T) {
	if _, err := newDialer(config.Backend{Name: "x", Transport: "bogus"}, testLogger()); err == nil {
		t.Error("expected an error for an unsupported transport")
	}
}

// TestHTTPDialer_ReusesTransport pins the property reconnect relies on: an HTTP
// dialer hands back the same transport instance every time, so the established
// OAuthHandler (and its in-memory token) is preserved across reconnects.
func TestHTTPDialer_ReusesTransport(t *testing.T) {
	b := config.Backend{Name: "h", Transport: config.TransportHTTP, Endpoint: "https://x.test/mcp", Auth: config.Auth{Type: config.AuthBearer, Token: "t"}}
	d, err := newDialer(b, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	first, err := d.dial(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.dial(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Error("httpDialer.dial returned a new transport; want the cached instance reused")
	}
}

// TestCommandDialer_RebuildsTransport pins the complementary property: a command
// dialer builds a fresh transport each call, because a subprocess is single-use
// and a reconnect must re-spawn it.
func TestCommandDialer_RebuildsTransport(t *testing.T) {
	b := config.Backend{Name: "c", Transport: config.TransportCommand, Command: []string{"true"}}
	d, err := newDialer(b, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	first, err := d.dial(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.dial(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Error("commandDialer.dial reused a transport; want a fresh one each call")
	}
}
