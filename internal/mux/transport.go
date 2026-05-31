// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package mux

import "net/http"

// headerRoundTripper injects a single static header into requests addressed to
// a specific host. Scoping to the host ensures credentials are not forwarded to
// a different origin if the backend issues a cross-host redirect (Go's built-in
// stripping of Authorization on redirects does not cover transport-injected
// headers).
type headerRoundTripper struct {
	base  http.RoundTripper
	host  string // only inject for requests to this host[:port]
	key   string
	value string
}

func (rt *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != rt.host {
		// Redirected (or otherwise addressed) elsewhere: do not attach credentials.
		return rt.base.RoundTrip(req)
	}
	// Clone so we never mutate a request the SDK might reuse or retry.
	r := req.Clone(req.Context())
	r.Header.Set(rt.key, rt.value)
	return rt.base.RoundTrip(r)
}

// httpClientFor returns an *http.Client that attaches the given header to
// requests addressed to host, or nil when no auth header is configured (the SDK
// then uses its default client).
func httpClientFor(host, key, value string) *http.Client {
	if key == "" {
		return nil
	}
	return &http.Client{
		Transport: &headerRoundTripper{base: http.DefaultTransport, host: host, key: key, value: value},
	}
}
