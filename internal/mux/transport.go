package mux

import "net/http"

// headerRoundTripper injects a single static header into every outgoing
// request. It is used to attach credentials to HTTP backend connections.
type headerRoundTripper struct {
	base  http.RoundTripper
	key   string
	value string
}

func (rt *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone so we never mutate a request the SDK might reuse or retry.
	r := req.Clone(req.Context())
	r.Header.Set(rt.key, rt.value)
	return rt.base.RoundTrip(r)
}

// httpClientFor returns an *http.Client that attaches the given header to every
// request, or nil when no auth header is configured (the SDK then uses its
// default client).
func httpClientFor(key, value string) *http.Client {
	if key == "" {
		return nil
	}
	return &http.Client{
		Transport: &headerRoundTripper{base: http.DefaultTransport, key: key, value: value},
	}
}
