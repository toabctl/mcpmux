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

// issuerNormalizingClient returns an *http.Client that rewrites the "issuer"
// field of an OAuth authorization-server metadata response to match the URL the
// metadata was served from. It works around authorization servers (e.g. Slack,
// whose metadata at https://mcp.slack.com declares issuer "https://slack.com")
// that violate RFC 8414 §3.3, which the SDK otherwise rejects before the flow
// can start. Only the well-known metadata responses are touched; every other
// request (token exchange, refresh, …) passes through unchanged. The endpoints
// in the metadata are not altered — only the self-declared issuer string — so
// the client still follows the server's own TLS-served authorize/token URLs.
//
// This assumes a path-less authorization server (the issuer is scheme://host),
// which holds for the servers that need this workaround.
func issuerNormalizingClient() *http.Client {
	return &http.Client{Transport: &issuerNormalizingTransport{base: http.DefaultTransport}}
}

type issuerNormalizingTransport struct{ base http.RoundTripper }

func (t *issuerNormalizingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	if resp.StatusCode != http.StatusOK ||
		(!strings.Contains(req.URL.Path, "/.well-known/oauth-authorization-server") &&
			!strings.Contains(req.URL.Path, "/.well-known/openid-configuration")) {
		return resp, nil
	}

	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}

	var meta map[string]any
	if json.Unmarshal(body, &meta) == nil {
		want := req.URL.Scheme + "://" + req.URL.Host
		if iss, ok := meta["issuer"].(string); ok && iss != want {
			meta["issuer"] = want
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
