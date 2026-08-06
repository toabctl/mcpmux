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

// issuerNormalizingClient returns an *http.Client that rewrites well-known
// OAuth metadata before the SDK reads it, fixing RFC 8414 issuer mismatches
// (Slack's declared issuer; Google's trailing-slash authorization_servers).
// Other requests, and endpoints inside the metadata, are untouched. Assumes a
// path-less authorization server (issuer is scheme://host).
func issuerNormalizingClient() *http.Client {
	return &http.Client{Transport: &issuerNormalizingTransport{base: http.DefaultTransport}}
}

type issuerNormalizingTransport struct {
	base http.RoundTripper
}

func (t *issuerNormalizingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
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
		if isAuthServer {
			want := req.URL.Scheme + "://" + req.URL.Host
			if iss, ok := meta["issuer"].(string); ok && iss != want {
				meta["issuer"] = want
				changed = true
			}
		}
		if isProtectedResource {
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
