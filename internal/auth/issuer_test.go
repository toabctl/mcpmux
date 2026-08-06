// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIssuerNormalizingClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/.well-known/oauth-authorization-server") {
			// Mismatched issuer, like Slack's metadata.
			_, _ = io.WriteString(w, `{"issuer":"https://elsewhere.example","authorization_endpoint":"https://x/a","token_endpoint":"https://x/t"}`)
			return
		}
		_, _ = io.WriteString(w, `{"issuer":"untouched"}`)
	}))
	defer srv.Close()

	c := issuerNormalizingClient()

	// The AS-metadata issuer is rewritten to the URL it was served from.
	resp, err := c.Get(srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err := json.Unmarshal(body, &meta); err != nil {
		t.Fatal(err)
	}
	if meta["issuer"] != srv.URL { // scheme://host of the request
		t.Errorf("issuer = %v, want %q", meta["issuer"], srv.URL)
	}
	if meta["token_endpoint"] != "https://x/t" {
		t.Errorf("endpoints must be left intact, got token_endpoint = %v", meta["token_endpoint"])
	}

	// Non-metadata responses pass through unchanged.
	resp2, err := c.Get(srv.URL + "/something/else")
	if err != nil {
		t.Fatal(err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if !strings.Contains(string(body2), `"untouched"`) {
		t.Errorf("non-metadata body was modified: %s", body2)
	}
}

func TestIssuerNormalizingClient_ProtectedResource(t *testing.T) {
	const prm = `{"resource":"https://x/mcp","authorization_servers":["https://as.example/"],` +
		`"scopes_supported":["gmail.readonly","gmail.metadata"]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, prm)
	}))
	defer srv.Close()

	resp, err := issuerNormalizingClient().Get(srv.URL + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}

	// authorization_servers is trailing-slash-normalized.
	if servers, _ := m["authorization_servers"].([]any); len(servers) != 1 || servers[0] != "https://as.example" {
		t.Errorf("authorization_servers = %v, want [https://as.example]", m["authorization_servers"])
	}
	// scopes_supported is left intact (scope filtering happens via ScopeFilter).
	if raw, _ := m["scopes_supported"].([]any); len(raw) != 2 {
		t.Errorf("scopes_supported must be untouched, got %v", m["scopes_supported"])
	}
}
