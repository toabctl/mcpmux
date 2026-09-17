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
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"
)

// OAuthOptions configures the interactive (authorization-code + PKCE) OAuth
// flow for a backend. The client is registered dynamically (RFC 7591).
type OAuthOptions struct {
	// Label identifies the backend in prompts and logs.
	Label string
	// Scopes optionally restricts the OAuth scopes: the advertised scope for
	// dynamic registration, and an allowlist filtering the server's advertised
	// scopes for the auth-code flow. Empty requests whatever the server offers.
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
	// Store, when non-nil, persists the token so a restart reuses it instead
	// of opening another browser consent.
	Store Store
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
		cfg.Client = issuerNormalizingClient()
	}
	// Configured scopes restrict the server-advertised set via the SDK's
	// ScopeFilter hook, which runs before offline_access and the step-up union.
	if len(o.Scopes) > 0 {
		cfg.ScopeFilter = scopeAllowlist(o.Scopes)
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
	// A refresh token is what makes a stored credential outlive the access
	// token's hour; the SDK only asks for offline_access when the server
	// advertises it, and clientMetadata already declares the grant.
	cfg.RequestRefreshToken = true
	if o.Store != nil {
		bindStore(cfg, o.Store, o.Label, log)
	}
	h, err := sdkauth.NewAuthorizationCodeHandler(cfg)
	if err != nil {
		return nil, fmt.Errorf("build oauth handler for %q: %w", o.Label, err)
	}
	return h, nil
}

// bindStore wires a token store into the handler config: every newly issued
// token is saved, and a usable stored one is injected as the initial token
// source, which is what stops the SDK from running a browser consent.
//
// A stored credential that the server no longer honours is not a dead end: the
// transport drops the header on invalid_grant and the resulting 401 runs the
// normal consent, and EagerAuthorize likewise falls through to it when the
// restored token fails to refresh. Either way the fresh token overwrites this
// one.
func bindStore(cfg *sdkauth.AuthorizationCodeHandlerConfig, st Store, label string, log *slog.Logger) {
	save := func(oc *oauth2.Config, tok *oauth2.Token) {
		if err := st.Save(label, credentialFrom(oc, tok)); err != nil {
			log.Warn("could not persist oauth token", "backend", label, "err", err)
		}
	}
	cfg.NewTokenSource = func(ctx context.Context, oc *oauth2.Config, tok *oauth2.Token) (oauth2.TokenSource, error) {
		save(oc, tok)
		return &persistSource{
			inner: oc.TokenSource(ctx, tok),
			save:  func(t *oauth2.Token) { save(oc, t) },
		}, nil
	}

	cred, err := st.Load(label)
	if err != nil {
		log.Warn("could not read stored oauth token", "backend", label, "err", err)
		return
	}
	if cred == nil {
		return
	}
	// Without a refresh token an expired access token is unusable, and a
	// consent is the only way forward.
	if cred.RefreshToken == "" && !cred.Expiry.IsZero() && !cred.Expiry.After(time.Now()) {
		return
	}
	oc := cred.oauth2Config()
	// The oauth2 library reuses this context for every later refresh, so it
	// must outlive the call that builds the source (see go-sdk #988).
	ctx := context.Background()
	if cfg.Client != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, cfg.Client)
	}
	cfg.InitialTokenSource = &persistSource{
		inner: oc.TokenSource(ctx, cred.token()),
		save:  func(t *oauth2.Token) { save(oc, t) },
	}
	log.Info("reusing stored oauth token; no browser consent needed", "backend", label)
}

// EagerAuthorize forces an interactive OAuth handler to run its
// authorization-code flow now, instead of lazily on the first 401 from a tool
// call. This lets a daemon batch all browser consents at startup rather than
// surfacing them at random times mid session.
//
// It is a no-op when the handler already holds a token — e.g. servers that
// challenge the initialize request authorize during connect, so only the
// lazy ones (whose initialize returns 200) are driven here. The 401 the handler
// expects is synthesized with an empty challenge; the SDK then discovers the
// protected-resource metadata from the endpoint's well-known path. Serialized
// with live flows via the shared authMu, so consents still open one at a time.
func EagerAuthorize(ctx context.Context, h sdkauth.OAuthHandler, endpoint, label string, log *slog.Logger) error {
	if h == nil {
		return nil
	}
	if ts, err := h.TokenSource(ctx); err == nil && ts != nil {
		if _, err := ts.Token(); err == nil {
			return nil // already authorized (e.g. challenged during connect)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return err
	}
	log.Info("eagerly authorizing backend at startup", "backend", label)
	resp := &http.Response{
		StatusCode: http.StatusUnauthorized,
		Header:     http.Header{},
		Body:       http.NoBody,
		Request:    req,
	}
	return h.Authorize(ctx, req, resp)
}

// scopeAllowlist returns a ScopeFilter restricting the discovered scopes to
// those in allow, preserving discovery order (e.g. dropping Gmail's
// gmail.metadata, which disables the search "q" param even alongside
// gmail.readonly). An empty intersection leaves the discovered set unchanged
// so a bad allowlist can't make the client request no scopes at all.
func scopeAllowlist(allow []string) func(discovered []string) []string {
	want := make(map[string]bool, len(allow))
	for _, s := range allow {
		want[s] = true
	}
	return func(discovered []string) []string {
		kept := make([]string, 0, len(discovered))
		for _, s := range discovered {
			if want[s] {
				kept = append(kept, s)
			}
		}
		if len(kept) == 0 {
			return discovered
		}
		return kept
	}
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
		_, _ = fmt.Fprintf(w, callbackPage, "Authorization failed", html.EscapeString(res.errMsg), "")
	case delivered:
		_, _ = fmt.Fprintf(w, callbackPage, "Authorization complete", "You can close this tab and return to mcpmux.", autoCloseScript)
	default:
		_, _ = fmt.Fprintf(w, callbackPage, "No authorization in progress", "You can close this tab.", "")
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
	switch runtime.GOOS {
	case "darwin":
		return launch("open", []string{url}, nil)
	case "windows":
		return launch("rundll32", []string{"url.dll,FileProtocolHandler", url}, nil)
	}
	name := "xdg-open"
	if b := os.Getenv("BROWSER"); b != "" {
		name = b
	}
	args := []string{url}
	if run, runArgs, ok := detachScope(name, args); ok {
		// The wrapper can fail where the bare opener works, and a browser that
		// never opens stalls the consent, so retry directly if it dies at once.
		return launch(run, runArgs, func() { _ = launch(name, args, nil) })
	}
	return launch(name, args, nil)
}

// launch starts argv without blocking and reaps it. onFail, if set, runs when
// the process fails within a couple of seconds, i.e. it never got as far as
// handing the URL over.
func launch(name string, args []string, onFail func()) error {
	// G204: opens a fixed browser launcher (or $BROWSER) with a URL we built.
	// noctx: fire-and-forget; the browser must outlive the request context.
	//nolint:gosec,noctx
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		return err
	}
	began := time.Now()
	go func() {
		if err := cmd.Wait(); err != nil && onFail != nil && time.Since(began) < 2*time.Second {
			onFail()
		}
	}()
	return nil
}

// detachScope wraps an opener in a transient systemd --user scope, so the
// browser it spawns leaves our service cgroup -- systemd kills that cgroup
// wholesale on restart, browser included.
func detachScope(name string, args []string) (string, []string, bool) {
	// systemd-run --user talks to the user manager over this socket.
	rt := os.Getenv("XDG_RUNTIME_DIR")
	if rt == "" {
		return "", nil, false
	}
	// G703: the path is only stat'ed, to decide whether a user manager exists.
	//nolint:gosec
	if _, err := os.Stat(filepath.Join(rt, "systemd", "private")); err != nil {
		return "", nil, false
	}
	run, err := exec.LookPath("systemd-run")
	if err != nil {
		return "", nil, false
	}
	return run, append([]string{"--user", "--scope", "--collect", "--quiet", "--", name}, args...), true
}

const callbackPage = `<!doctype html><html><head><meta charset="utf-8">
<title>mcpmux</title><style>
body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;
display:flex;height:100vh;margin:0;align-items:center;justify-content:center}
.card{text-align:center;padding:2rem 3rem;background:#171a21;border-radius:12px}
h1{font-size:1.25rem;margin:0 0 .5rem}p{margin:0;color:#9aa0aa}
</style></head><body><div class="card"><h1>%s</h1><p>%s</p></div>%s</body></html>`

// autoCloseScript tries to close the tab a few seconds after a successful
// authorization. Browsers only honor window.close() for script-opened windows,
// so this is best-effort; the page still tells the user they can close it.
const autoCloseScript = `<script>setTimeout(function(){window.close()},5000)</script>`
