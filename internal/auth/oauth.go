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

	clientName := o.ClientName
	if clientName == "" {
		clientName = "mcpmux"
	}
	meta := &oauthex.ClientRegistrationMetadata{
		RedirectURIs:            []string{ba.redirect},
		ClientName:              clientName,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none", // public client; the AS may override at registration
		Scope:                   strings.Join(o.Scopes, " "),
	}

	cfg := &sdkauth.AuthorizationCodeHandlerConfig{
		DynamicClientRegistrationConfig: &sdkauth.DynamicClientRegistrationConfig{Metadata: meta},
		RedirectURL:              ba.redirect,
		AuthorizationCodeFetcher: ba.fetch,
	}
	h, err := sdkauth.NewAuthorizationCodeHandler(cfg)
	if err != nil {
		return nil, fmt.Errorf("build oauth handler for %q: %w", o.Label, err)
	}
	return h, nil
}

// callbackResult carries the redirect parameters from the loopback handler.
type callbackResult struct {
	code, state, errMsg string
}

// browserAuthorizer runs a loopback HTTP server that captures the OAuth
// redirect, and supplies the AuthorizationCodeFetcher used by the SDK handler.
type browserAuthorizer struct {
	redirect string
	open     bool
	openURL  func(string) error
	log      *slog.Logger
	label    string

	mu      sync.Mutex
	waiting chan callbackResult // non-nil only while a flow is in progress
}

func newBrowserAuthorizer(ctx context.Context, label string, port int, open bool, log *slog.Logger) (*browserAuthorizer, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("reserve oauth callback port for %q: %w", label, err)
	}
	a := &browserAuthorizer{
		redirect: fmt.Sprintf("http://%s/callback", ln.Addr().String()),
		open:     open,
		openURL:  openBrowser,
		log:      log,
		label:    label,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", a.handleCallback)
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	return a, nil
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
		fmt.Fprintf(w, callbackPage, "Authorization failed", html.EscapeString(res.errMsg))
	case delivered:
		fmt.Fprintf(w, callbackPage, "Authorization complete", "You can close this tab and return to mcpmux.")
	default:
		fmt.Fprintf(w, callbackPage, "No authorization in progress", "You can close this tab.")
	}
}

// fetch implements sdkauth.AuthorizationCodeFetcher: it surfaces the auth URL
// (and optionally opens a browser), then blocks until the loopback callback
// fires or ctx is done.
func (a *browserAuthorizer) fetch(ctx context.Context, args *sdkauth.AuthorizationArgs) (*sdkauth.AuthorizationResult, error) {
	ch := make(chan callbackResult, 1)
	a.mu.Lock()
	a.waiting = ch
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.waiting = nil
		a.mu.Unlock()
	}()

	a.log.Info("backend authorization required", "backend", a.label, "url", args.URL)
	fmt.Fprintf(os.Stderr, "\n[mcpmux] authorize %q — open this URL if it does not open automatically:\n  %s\n\n", a.label, args.URL)
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
	return exec.Command(name, args...).Start()
}

const callbackPage = `<!doctype html><html><head><meta charset="utf-8">
<title>mcpmux</title><style>
body{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;
display:flex;height:100vh;margin:0;align-items:center;justify-content:center}
.card{text-align:center;padding:2rem 3rem;background:#171a21;border-radius:12px}
h1{font-size:1.25rem;margin:0 0 .5rem}p{margin:0;color:#9aa0aa}
</style></head><body><div class="card"><h1>%s</h1><p>%s</p></div></body></html>`
