// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// metadataRewritingClient returns an *http.Client that rewrites well-known OAuth
// metadata before the SDK reads it, or nil when no rewrite is requested.
// normalizeIssuer fixes RFC 8414 issuer mismatches (Slack's declared issuer;
// Google's trailing-slash authorization_servers). allowScopes restricts a
// protected resource's advertised scopes_supported to an allowlist — the only
// way to drop an unwanted scope, since the SDK requests whatever it discovers
// (e.g. Gmail's gmail.metadata disables the search "q" param even alongside
// gmail.readonly). Other requests, and endpoints inside the metadata, are
// untouched. Assumes a path-less authorization server (issuer is scheme://host).
func metadataRewritingClient(normalizeIssuer bool, allowScopes []string) *http.Client {
	if !normalizeIssuer && len(allowScopes) == 0 {
		return nil
	}
	var allow map[string]bool
	if len(allowScopes) > 0 {
		allow = make(map[string]bool, len(allowScopes))
		for _, s := range allowScopes {
			allow[s] = true
		}
	}
	return &http.Client{Transport: &metadataRewritingTransport{
		base:            http.DefaultTransport,
		normalizeIssuer: normalizeIssuer,
		allowScopes:     allow,
	}}
}

// issuerNormalizingClient returns a client that only normalizes issuer
// mismatches (see metadataRewritingClient).
func issuerNormalizingClient() *http.Client {
	return metadataRewritingClient(true, nil)
}

type metadataRewritingTransport struct {
	base            http.RoundTripper
	normalizeIssuer bool
	allowScopes     map[string]bool // nil: no scope filtering
}

func (t *metadataRewritingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	isAuthServer := strings.Contains(req.URL.Path, "/.well-known/oauth-authorization-server") ||
		strings.Contains(req.URL.Path, "/.well-known/openid-configuration")
	isProtectedResource := strings.Contains(req.URL.Path, "/.well-known/oauth-protected-resource")
	if resp.StatusCode != http.StatusOK || (!isAuthServer && !isProtectedResource) {
		return resp, nil
	}

	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}

	var meta map[string]any
	if json.Unmarshal(body, &meta) == nil {
		changed := false
		if t.normalizeIssuer && isAuthServer {
			want := req.URL.Scheme + "://" + req.URL.Host
			if iss, ok := meta["issuer"].(string); ok && iss != want {
				meta["issuer"] = want
				changed = true
			}
		}
		if isProtectedResource {
			if t.normalizeIssuer {
				// Strip trailing slashes from authorization_servers so the SDK's
				// byte-exact issuer check matches the AS metadata's path-less issuer.
				if servers, ok := meta["authorization_servers"].([]any); ok {
					for i, v := range servers {
						if s, ok := v.(string); ok {
							if trimmed := strings.TrimRight(s, "/"); trimmed != s {
								servers[i] = trimmed
								changed = true
							}
						}
					}
				}
			}
			if len(t.allowScopes) > 0 {
				if filtered, ok := filterScopes(meta["scopes_supported"], t.allowScopes); ok {
					meta["scopes_supported"] = filtered
					changed = true
				}
			}
		}
		if changed {
			if patched, err := json.Marshal(meta); err == nil {
				body = patched
			}
		}
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return resp, nil
}

// filterScopes restricts advertised scopes_supported (a []any of strings) to
// those in allow, preserving order, and reports whether it changed anything.
// An empty intersection is left as no change so a bad allowlist can't make the
// client request no scopes at all.
func filterScopes(advertised any, allow map[string]bool) ([]any, bool) {
	list, ok := advertised.([]any)
	if !ok {
		return nil, false
	}
	kept := make([]any, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok && allow[s] {
			kept = append(kept, v)
		}
	}
	if len(kept) == 0 || len(kept) == len(list) {
		return nil, false
	}
	return kept, true
}
