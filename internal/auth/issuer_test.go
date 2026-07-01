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

func TestMetadataRewritingClient_FiltersScopes(t *testing.T) {
	const prm = `{"resource":"https://x/mcp","authorization_servers":["https://as.example/"],` +
		`"scopes_supported":["https://mail.google.com/","gmail.modify","gmail.compose","gmail.readonly","gmail.metadata"]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, prm)
	}))
	defer srv.Close()

	get := func(c *http.Client) map[string]any {
		resp, err := c.Get(srv.URL + "/.well-known/oauth-protected-resource/mcp")
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	scopes := func(m map[string]any) []string {
		raw, _ := m["scopes_supported"].([]any)
		out := make([]string, len(raw))
		for i, v := range raw {
			out[i], _ = v.(string)
		}
		return out
	}

	// The allowlist restricts scopes_supported to its members, order preserved,
	// dropping the poisonous gmail.metadata (and everything else not allowed).
	m := get(metadataRewritingClient(true, []string{"gmail.readonly", "gmail.compose"}))
	if got := strings.Join(scopes(m), " "); got != "gmail.compose gmail.readonly" {
		t.Errorf("filtered scopes = %q, want %q", got, "gmail.compose gmail.readonly")
	}
	// authorization_servers is still trailing-slash-normalized alongside filtering.
	if servers, _ := m["authorization_servers"].([]any); len(servers) != 1 || servers[0] != "https://as.example" {
		t.Errorf("authorization_servers = %v, want [https://as.example]", m["authorization_servers"])
	}

	// Issuer normalization alone (no allowlist) leaves scopes_supported intact.
	if got := strings.Join(scopes(get(issuerNormalizingClient())), " "); !strings.Contains(got, "gmail.metadata") {
		t.Errorf("without an allowlist scopes must be untouched, got %q", got)
	}
}

func TestMetadataRewritingClient_NilWhenNoop(t *testing.T) {
	if metadataRewritingClient(false, nil) != nil {
		t.Error("expected nil client when neither issuer normalization nor scope filtering is requested")
	}
}

func TestFilterScopes_FailOpen(t *testing.T) {
	advertised := []any{"a", "b"}
	// Allowlist matching nothing: no change, so the flow still requests the
	// server's scopes rather than an empty set.
	if _, ok := filterScopes(advertised, map[string]bool{"z": true}); ok {
		t.Error("empty intersection should report no change")
	}
	// Allowlist covering everything: also no change.
	if _, ok := filterScopes(advertised, map[string]bool{"a": true, "b": true}); ok {
		t.Error("full match should report no change")
	}
	// Non-array input is ignored.
	if _, ok := filterScopes("nope", map[string]bool{"a": true}); ok {
		t.Error("non-array scopes_supported should report no change")
	}
}
