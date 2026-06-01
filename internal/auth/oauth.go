// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

// OAuthOptions configures the interactive (authorization-code + PKCE) OAuth
// flow for a backend. The client is registered dynamically (RFC 7591).
type OAuthOptions struct {
	// Label identifies the backend in prompts and logs.
	Label string
	// Scopes optionally requested at registration/authorization.
	Scopes []string
	// ClientName is the DCR client_name presented to the user (default "mcpmux").
	ClientName string
	// OpenBrowser controls whether the auth URL is launched automatically. The
	// URL is always printed regardless, so headless/SSH use still works.
	OpenBrowser bool
	// CallbackPort fixes the loopback callback port; 0 picks an ephemeral one.
	CallbackPort int
	// ClientID/ClientSecret select a pre-registered ("confidential") client
	// instead of dynamic client registration, for servers that don't support
	// DCR. ClientSecret may be empty for a pre-registered public client.
	ClientID     string
	ClientSecret string
	// AllowIssuerMismatch tolerates an authorization server whose metadata
	// declares an issuer different from the URL it is served from (RFC 8414
	// §3.3 violation), by normalizing the issuer client-side. Needed for Slack.
	AllowIssuerMismatch bool
}

// NewOAuthHandler builds an OAuthHandler that performs the authorization-code
// flow in a browser, reserving a loopback callback endpoint for the daemon's
// lifetime (bounded by ctx). The SDK handles discovery, dynamic client
// registration, PKCE, token exchange and in-memory refresh.
func NewOAuthHandler(ctx context.Context, log *slog.Logger, o OAuthOptions) (sdkauth.OAuthHandler, error) {
	ba, err := newBrowserAuthorizer(ctx, o.Label, o.CallbackPort, o.OpenBrowser, log)
	if err != nil {
		return nil, err
	}

	cfg := &sdkauth.AuthorizationCodeHandlerConfig{
		RedirectURL:              ba.redirect,
		AuthorizationCodeFetcher: ba.fetch,
	}
	if o.AllowIssuerMismatch {
		// Normalize the AS-metadata issuer so the SDK's RFC 8414 check accepts a
		// server (e.g. Slack) whose metadata declares a mismatched issuer.
		cfg.Client = issuerNormalizingClient()
	}
	if o.ClientID != "" {
		// Pre-registered client: the server doesn't support dynamic client
		// registration (e.g. Slack). The redirect URI must be registered with
		// the provider, hence the fixed callback port.
		cc := &oauthex.ClientCredentials{ClientID: o.ClientID}
		if o.ClientSecret != "" {
			cc.ClientSecretAuth = &oauthex.ClientSecretAuth{ClientSecret: o.ClientSecret}
		}
		cfg.PreregisteredClient = cc
	} else {
		cfg.DynamicClientRegistrationConfig = &sdkauth.DynamicClientRegistrationConfig{Metadata: clientMetadata(o, ba.redirect)}
	}
	h, err := sdkauth.NewAuthorizationCodeHandler(cfg)
	if err != nil {
		return nil, fmt.Errorf("build oauth handler for %q: %w", o.Label, err)
	}
	return h, nil
}

// clientMetadata builds the dynamic client registration metadata for a backend
// from its OAuth options. ClientName defaults to "mcpmux"; Scopes are joined
// into a space-separated scope string.
func clientMetadata(o OAuthOptions, redirectURI string) *oauthex.ClientRegistrationMetadata {
	clientName := o.ClientName
	if clientName == "" {
		clientName = "mcpmux"
	}
	return &oauthex.ClientRegistrationMetadata{
		RedirectURIs:            []string{redirectURI},
		ClientName:              clientName,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none", // public client; the AS may override at registration
		Scope:                   strings.Join(o.Scopes, " "),
	}
}

// callbackResult carries the redirect parameters from the loopback handler.
type callbackResult struct {
	code, state, errMsg string
}

// authMu serializes interactive (browser) authorizations across all backends.
// A loopback callback port is only needed for the brief authorization-code
// redirect, so holding this lock while one flow runs lets backends that share a
// fixed callback_port use it one at a time instead of each reserving a distinct
// port for the daemon's whole lifetime. A human can only complete one browser
// consent at a time anyway, so serializing costs nothing in practice.
var authMu sync.Mutex

// browserAuthorizer runs a loopback HTTP server that captures the OAuth
// redirect, and supplies the AuthorizationCodeFetcher used by the SDK handler.
type browserAuthorizer struct {
	redirect string
	port     int // configured callback_port; 0 means an ephemeral port
	open     bool
	openURL  func(string) error
	log      *slog.Logger
	label    string

	mu      sync.Mutex
	waiting chan callbackResult // non-nil only while a flow is in progress
}

func newBrowserAuthorizer(ctx context.Context, label string, port int, open bool, log *slog.Logger) (*browserAuthorizer, error) {
	a := &browserAuthorizer{
		port:    port,
		open:    open,
		openURL: openBrowser,
		log:     log,
		label:   label,
	}
	if port == 0 {
		// Ephemeral: the port must be discovered now so the redirect URI is stable,
		// and is then held for the daemon's lifetime. Ephemeral ports don't collide,
		// so there is nothing to share or serialize.
		var lc net.ListenConfig
		ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
		if err != nil {
			return nil, fmt.Errorf("reserve oauth callback port for %q: %w", label, err)
		}
		a.redirect = fmt.Sprintf("http://%s/callback", ln.Addr().String())
		srv := a.serveCallback(ln)
		go func() {
			<-ctx.Done()
			_ = srv.Close()
		}()
		return a, nil
	}
	// Fixed port: do not reserve it now. fetch() binds it only while an
	// authorization is in flight (under authMu), so the port stays free otherwise
	// and multiple backends can be configured to share it.
	a.redirect = fmt.Sprintf("http://127.0.0.1:%d/callback", port)
	return a, nil
}

// serveCallback starts an HTTP server on ln that delivers the OAuth redirect to
// this authorizer, and returns it so the caller controls its lifetime.
func (a *browserAuthorizer) serveCallback(ln net.Listener) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", a.handleCallback)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return srv
}

func (a *browserAuthorizer) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	res := callbackResult{code: q.Get("code"), state: q.Get("state"), errMsg: q.Get("error")}

	a.mu.Lock()
	ch := a.waiting
	a.mu.Unlock()

	delivered := false
	if ch != nil {
		select {
		case ch <- res:
			delivered = true
		default:
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	switch {
	case res.errMsg != "":
		_, _ = fmt.Fprintf(w, callbackPage, "Authorization failed", html.EscapeString(res.errMsg))
	case delivered:
		_, _ = fmt.Fprintf(w, callbackPage, "Authorization complete", "You can close this tab and return to mcpmux.")
	default:
		_, _ = fmt.Fprintf(w, callbackPage, "No authorization in progress", "You can close this tab.")
	}
}

// fetch implements sdkauth.AuthorizationCodeFetcher. For a fixed callback_port
// it binds the loopback listener only for the duration of this flow — serialized
// via authMu so backends can share one port — and releases it on return. For an
// ephemeral port the listener was already started at construction.
func (a *browserAuthorizer) fetch(ctx context.Context, args *sdkauth.AuthorizationArgs) (*sdkauth.AuthorizationResult, error) {
	if a.port == 0 {
		return a.await(ctx, args)
	}
	authMu.Lock()
	defer authMu.Unlock()

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", a.port))
	if err != nil {
		return nil, fmt.Errorf("reserve oauth callback port for %q: %w", a.label, err)
	}
	srv := a.serveCallback(ln)
	defer func() { _ = srv.Close() }()
	return a.await(ctx, args)
}

// await surfaces the auth URL (optionally opening a browser), then blocks until
// the loopback callback fires or ctx is done. The callback listener must already
// be serving when this is called.
func (a *browserAuthorizer) await(ctx context.Context, args *sdkauth.AuthorizationArgs) (*sdkauth.AuthorizationResult, error) {
	ch := make(chan callbackResult, 1)
	a.mu.Lock()
	a.waiting = ch
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.waiting = nil
		a.mu.Unlock()
	}()

	a.log.Info("backend authorization required (open the URL if a browser did not)",
		"backend", a.label, "url", args.URL)
	if a.open {
		if err := a.openURL(args.URL); err != nil {
			a.log.Warn("could not open browser automatically", "backend", a.label, "err", err)
		}
	}

	select {
	case res := <-ch:
		if res.errMsg != "" {
			return nil, fmt.Errorf("authorization error for %q: %s", a.label, res.errMsg)
		}
		if res.code == "" {
			return nil, fmt.Errorf("authorization callback for %q missing code", a.label)
		}
		return &sdkauth.AuthorizationResult{Code: res.code, State: res.state}, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("authorization for %q did not complete: %w", a.label, ctx.Err())
	}
}

// openBrowser launches the system browser for url without blocking.
func openBrowser(url string) error {
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name, args = "open", []string{url}
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		if b := os.Getenv("BROWSER"); b != "" {
			name = b
		} else {
			name = "xdg-open"
		}
		args = []string{url}
	}
	// G204: opens a fixed browser launcher (or $BROWSER) with a URL we built.
	// noctx: fire-and-forget; the browser must outlive the request context.
	//nolint:gosec,noctx
	return exec.Command(name, args...).Start()
}

const callbackPage = `<!doctype html><html><head><meta charset="utf-8">
<title>mcpmux</title><style>
body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;
display:flex;height:100vh;margin:0;align-items:center;justify-content:center}
.card{text-align:center;padding:2rem 3rem;background:#171a21;border-radius:12px}
h1{font-size:1.25rem;margin:0 0 .5rem}p{margin:0;color:#9aa0aa}
</style></head><body><div class="card"><h1>%s</h1><p>%s</p></div></body></html>`
