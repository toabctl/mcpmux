// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

// Package config defines and loads the mcpmux configuration: the endpoint the
// proxy exposes to its client, and the set of upstream MCP servers (backends)
// it multiplexes.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Transport identifies how mcpmux talks to a peer (its client or a backend).
type Transport string

const (
	// TransportStdio exposes the proxy over stdin/stdout (listen only).
	TransportStdio Transport = "stdio"
	// TransportCommand launches a backend as a subprocess and speaks over its
	// stdio (backend only).
	TransportCommand Transport = "command"
	// TransportHTTP uses streamable HTTP (valid for both listen and backends).
	TransportHTTP Transport = "http"
)

// AuthType selects how credentials are attached to an HTTP backend's requests.
type AuthType string

const (
	// AuthNone sends no credentials.
	AuthNone AuthType = "none"
	// AuthBearer sends "Authorization: Bearer <token>".
	AuthBearer AuthType = "bearer"
	// AuthHeader sends a caller-defined header and value.
	AuthHeader AuthType = "header"
	// AuthCommand obtains a bearer token by running an external command (a
	// credential helper), re-running it when the token expires. This is the
	// non-interactive path for backends fronted by a CLI that already holds a
	// login, e.g. "chainctl auth token --audience <resource>".
	AuthCommand AuthType = "command"
	// AuthOAuth performs the interactive authorization-code (PKCE) flow in a
	// browser at startup, with dynamic client registration. Tokens (and their
	// refresh, if the server issues one) are held in memory for the daemon's
	// lifetime.
	AuthOAuth AuthType = "oauth"
)

// defaultTokenTTL bounds how long an opaque (non-JWT) credential-helper token
// is cached before the command is re-run.
const defaultTokenTTL = 5 * time.Minute

// Config is the top-level mcpmux configuration.
type Config struct {
	Listen   Listen    `yaml:"listen"`
	Backends []Backend `yaml:"backends"`
}

// Listen configures the single MCP endpoint mcpmux exposes to its client.
type Listen struct {
	// Transport is "stdio" or "http".
	Transport Transport `yaml:"transport"`
	// Address is the host:port to bind when Transport is "http".
	Address string `yaml:"address"`
	// Path is the URL path the MCP endpoint is mounted at when Transport is
	// "http" (e.g. "/mcp"). Clients connect to http://<address><path>.
	Path string `yaml:"path"`
}

// IsLoopback reports whether the listen address binds only the loopback
// interface. An empty host (e.g. ":8080") binds all interfaces and is not
// loopback. mcpmux performs no client-side authentication, so binding a
// non-loopback address exposes every backend's credentials to that network.
func (l Listen) IsLoopback() bool {
	host, _, err := net.SplitHostPort(l.Address)
	if err != nil {
		host = l.Address
	}
	switch host {
	case "":
		return false
	case "localhost":
		return true
	default:
		ip := net.ParseIP(host)
		return ip != nil && ip.IsLoopback()
	}
}

// Backend is a single upstream MCP server that mcpmux proxies to. Its tools are
// re-exposed on the proxy under "<Name>__<tool>".
type Backend struct {
	// Name namespaces the backend's tools and must be unique.
	Name string `yaml:"name"`
	// Description is optional free text about this backend (e.g. which account
	// or environment it targets). mcpmux front-loads it onto each of the
	// backend's tool descriptions and lists it in the server instructions, so a
	// client's model can tell otherwise-identical backends apart.
	Description string `yaml:"description"`
	// Transport is "command" or "http".
	Transport Transport `yaml:"transport"`

	// Command transport: argv of the subprocess to launch, and extra env
	// (merged onto the parent environment) used to pass the backend its secrets.
	Command []string          `yaml:"command"`
	Env     map[string]string `yaml:"env"`

	// HTTP transport: the streamable-HTTP endpoint and its credentials.
	Endpoint string `yaml:"endpoint"`
	Auth     Auth   `yaml:"auth"`
}

// Auth describes credentials for an HTTP backend.
type Auth struct {
	Type AuthType `yaml:"type"`
	// Token is used when Type is "bearer".
	Token string `yaml:"token"`
	// Header and Value are used when Type is "header".
	Header string `yaml:"header"`
	Value  string `yaml:"value"`
	// Command is the credential-helper argv used when Type is "command". Its
	// stdout is taken as the bearer token.
	Command []string `yaml:"command"`
	// TTL optionally caps how long a "command" token is cached (e.g. "5m").
	// Ignored for JWTs, whose "exp" claim is authoritative. Empty uses the
	// default.
	TTL string `yaml:"ttl"`

	// OAuth fields (Type "oauth").
	Scopes       []string `yaml:"scopes"`        // optional requested scopes
	ClientName   string   `yaml:"client_name"`   // DCR client_name (default "mcpmux")
	CallbackPort int      `yaml:"callback_port"` // fixed loopback port; 0 = ephemeral
	// OpenBrowser controls auto-launching the auth URL (default true). The URL
	// is always logged, so headless use works with this set to false.
	OpenBrowser *bool `yaml:"open_browser"`
}

// OpenBrowserEnabled reports whether the OAuth flow should launch a browser,
// defaulting to true when unset.
func (a Auth) OpenBrowserEnabled() bool {
	return a.OpenBrowser == nil || *a.OpenBrowser
}

// TokenTTL returns the parsed cache TTL for a "command" token, or the default
// when unset. Callers should validate the config first.
func (a Auth) TokenTTL() time.Duration {
	if a.TTL == "" {
		return defaultTokenTTL
	}
	d, err := time.ParseDuration(a.TTL)
	if err != nil || d <= 0 {
		return defaultTokenTTL
	}
	return d
}

// HTTPHeader returns the header name and value to attach for this auth config,
// or empty strings when no header should be sent.
func (a Auth) HTTPHeader() (key, value string) {
	switch a.Type {
	case AuthBearer:
		return "Authorization", "Bearer " + a.Token
	case AuthHeader:
		return a.Header, a.Value
	default:
		return "", ""
	}
}

// SearchPaths returns the candidate config locations, in priority order:
// the current directory first (handy for local runs), then the user config
// directory (on Linux, $XDG_CONFIG_HOME or ~/.config).
func SearchPaths() []string {
	paths := []string{"mcpmux.yaml"}
	if dir, err := os.UserConfigDir(); err == nil {
		paths = append(paths,
			filepath.Join(dir, "mcpmux", "config.yaml"),
			filepath.Join(dir, "mcpmux.yaml"),
		)
	}
	return paths
}

// Resolve returns the config path to use. An explicit (flag-provided) path is
// returned unchanged; otherwise the first existing SearchPaths entry is used.
func Resolve(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	paths := SearchPaths()
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no config file found (looked in: %s); use --config to specify one",
		strings.Join(paths, ", "))
}

// Load reads the file at path, expands ${ENV} references against the process
// environment, parses the YAML, applies defaults and validates the result.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is the operator-provided config file location.
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	expanded := os.Expand(string(raw), os.Getenv)

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	cfg.setDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) setDefaults() {
	if c.Listen.Transport == "" {
		c.Listen.Transport = TransportStdio
	}
	if c.Listen.Address == "" {
		// Loopback by default: the client->mcpmux hop is unauthenticated, so we
		// must not expose backend credentials beyond the local host.
		c.Listen.Address = "127.0.0.1:8080"
	}
	if c.Listen.Path == "" {
		c.Listen.Path = "/mcp"
	}
	for i := range c.Backends {
		if c.Backends[i].Auth.Type == "" {
			c.Backends[i].Auth.Type = AuthNone
		}
	}
}

// Validate checks the configuration for internal consistency.
func (c *Config) Validate() error {
	switch c.Listen.Transport {
	case TransportStdio, TransportHTTP:
	default:
		return fmt.Errorf("listen.transport must be %q or %q, got %q",
			TransportStdio, TransportHTTP, c.Listen.Transport)
	}
	if c.Listen.Transport == TransportHTTP && (len(c.Listen.Path) == 0 || c.Listen.Path[0] != '/') {
		return fmt.Errorf("listen.path must start with %q, got %q", "/", c.Listen.Path)
	}
	if len(c.Backends) == 0 {
		return fmt.Errorf("at least one backend is required")
	}

	seen := make(map[string]bool, len(c.Backends))
	for i, b := range c.Backends {
		if b.Name == "" {
			return fmt.Errorf("backends[%d]: name is required", i)
		}
		if seen[b.Name] {
			return fmt.Errorf("backends[%d]: duplicate name %q", i, b.Name)
		}
		seen[b.Name] = true

		switch b.Transport {
		case TransportCommand:
			if len(b.Command) == 0 {
				return fmt.Errorf("backend %q: command is required for %q transport", b.Name, TransportCommand)
			}
		case TransportHTTP:
			if b.Endpoint == "" {
				return fmt.Errorf("backend %q: endpoint is required for %q transport", b.Name, TransportHTTP)
			}
			// A malformed or scheme-less endpoint would otherwise surface as an
			// opaque connect-time failure (and, since credentials are scoped to
			// the parsed host, as a silently unauthenticated request).
			if u, err := url.Parse(b.Endpoint); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("backend %q: endpoint must be an absolute http(s) URL, got %q", b.Name, b.Endpoint)
			}
			if err := b.Auth.validate(b.Name); err != nil {
				return err
			}
		default:
			return fmt.Errorf("backend %q: transport must be %q or %q, got %q",
				b.Name, TransportCommand, TransportHTTP, b.Transport)
		}
	}
	return nil
}

func (a Auth) validate(backend string) error {
	switch a.Type {
	case AuthNone, AuthBearer, AuthHeader:
		// Credential presence (token/header/value) is intentionally not checked
		// here: a credential sourced from an unset ${ENV} var should degrade to
		// a connect-time failure that mcpmux skips, not abort the whole config.
		// Only the header NAME is structural, so require it when set to "header".
		if a.Type == AuthHeader && a.Header == "" {
			return fmt.Errorf("backend %q: auth.header (name) is required for header auth", backend)
		}
		return nil
	case AuthCommand:
		if len(a.Command) == 0 {
			return fmt.Errorf("backend %q: auth.command is required for command auth", backend)
		}
		if a.TTL != "" {
			if _, err := time.ParseDuration(a.TTL); err != nil {
				return fmt.Errorf("backend %q: invalid auth.ttl %q: %w", backend, a.TTL, err)
			}
		}
		return nil
	case AuthOAuth:
		if a.CallbackPort < 0 || a.CallbackPort > 65535 {
			return fmt.Errorf("backend %q: auth.callback_port %d out of range", backend, a.CallbackPort)
		}
		return nil
	default:
		return fmt.Errorf("backend %q: unknown auth.type %q", backend, a.Type)
	}
}
