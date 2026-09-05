// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadExpandsEnvAndDefaults(t *testing.T) {
	t.Setenv("TEST_TOKEN", "secret123")

	path := filepath.Join(t.TempDir(), "mcpmux.yaml")
	content := `
listen:
  transport: http
  address: ":9000"
backends:
  - name: github
    transport: http
    endpoint: https://example.com/mcp
    auth:
      type: bearer
      token: ${TEST_TOKEN}
  - name: local
    transport: command
    command: ["echo", "hi"]
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Listen.Path != "/mcp" {
		t.Errorf("default path = %q, want /mcp", cfg.Listen.Path)
	}
	if got := cfg.Backends[0].Auth.Token; got != "secret123" {
		t.Errorf("token not expanded: %q", got)
	}
	key, value := cfg.Backends[0].Auth.HTTPHeader()
	if key != "Authorization" || value != "Bearer secret123" {
		t.Errorf("HTTPHeader = (%q, %q)", key, value)
	}
	if cfg.Backends[1].Auth.Type != AuthNone {
		t.Errorf("default auth type = %q, want none", cfg.Backends[1].Auth.Type)
	}
}

func TestBackendDescriptionParses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	content := "listen:\n  transport: stdio\nbackends:\n" +
		"  - name: a\n    description: prod AWS account\n    transport: command\n    command: [\"x\"]\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Backends[0].Description; got != "prod AWS account" {
		t.Errorf("Description = %q, want %q", got, "prod AWS account")
	}
}

func TestOAuthClientCredentialsParse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	content := "listen:\n  transport: stdio\nbackends:\n" +
		"  - name: a\n    transport: http\n    endpoint: https://x/mcp\n    auth:\n" +
		"      type: oauth\n      client_id: cid\n" +
		"      client_secret_command: [\"pass\", \"show\", \"x\"]\n      callback_port: 8807\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	a := cfg.Backends[0].Auth
	if a.ClientID != "cid" {
		t.Errorf("ClientID = %q", a.ClientID)
	}
	if len(a.ClientSecretCommand) != 3 || a.ClientSecretCommand[0] != "pass" {
		t.Errorf("ClientSecretCommand = %v", a.ClientSecretCommand)
	}
}

func TestListenIsLoopback(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8080":   true,
		"localhost:8080":   true,
		"[::1]:8080":       true,
		":8080":            false,
		"0.0.0.0:8080":     false,
		"192.168.1.5:8080": false,
	}
	for addr, want := range cases {
		if got := (Listen{Address: addr}).IsLoopback(); got != want {
			t.Errorf("IsLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestDefaultListenAddressIsLoopback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	content := "listen:\n  transport: http\nbackends:\n  - name: a\n    transport: command\n    command: [\"x\"]\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen.Address != "127.0.0.1:8080" {
		t.Errorf("default address = %q, want 127.0.0.1:8080", cfg.Listen.Address)
	}
	if !cfg.Listen.IsLoopback() {
		t.Error("default address must be loopback")
	}
}

// TestValidateEmptyPathNoPanic guards against indexing an empty Path when
// Validate is called without setDefaults.
func TestValidateEmptyPathNoPanic(t *testing.T) {
	c := Config{
		Listen:   Listen{Transport: TransportHTTP, Path: ""},
		Backends: []Backend{{Name: "a", Transport: TransportCommand, Command: []string{"x"}}},
	}
	if err := c.Validate(); err == nil {
		t.Error("expected an error for empty listen.path, got nil")
	}
}

func TestTokenTTL(t *testing.T) {
	if got := (Auth{}).TokenTTL(); got != defaultTokenTTL {
		t.Errorf("empty TTL = %v, want default %v", got, defaultTokenTTL)
	}
	if got := (Auth{TTL: "90s"}).TokenTTL(); got != 90*time.Second {
		t.Errorf("TTL 90s = %v", got)
	}
	if got := (Auth{TTL: "garbage"}).TokenTTL(); got != defaultTokenTTL {
		t.Errorf("invalid TTL should fall back to default, got %v", got)
	}
}

func TestResolve(t *testing.T) {
	// Explicit path wins, even if it does not exist.
	if got, err := Resolve("/explicit/path.yaml"); err != nil || got != "/explicit/path.yaml" {
		t.Fatalf("Resolve(explicit) = (%q, %v)", got, err)
	}

	// With no candidates present, Resolve reports an error listing where it looked.
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Chdir(dir) // empty cwd, so ./mcpmux.yaml is absent too
	if _, err := Resolve(""); err == nil {
		t.Fatal("expected error when no config exists, got nil")
	}

	// Place a config at the XDG location and confirm it is discovered.
	xdgPath := filepath.Join(dir, "mcpmux", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(xdgPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(xdgPath, []byte("listen: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Resolve("")
	if err != nil || got != xdgPath {
		t.Fatalf("Resolve() = (%q, %v), want %q", got, err, xdgPath)
	}
}

func TestValidateRejectsBadConfigs(t *testing.T) {
	tests := map[string]Config{
		"no backends": {
			Listen: Listen{Transport: TransportStdio},
		},
		"duplicate name": {
			Listen: Listen{Transport: TransportStdio},
			Backends: []Backend{
				{Name: "a", Transport: TransportCommand, Command: []string{"x"}},
				{Name: "a", Transport: TransportCommand, Command: []string{"y"}},
			},
		},
		"command without argv": {
			Listen:   Listen{Transport: TransportStdio},
			Backends: []Backend{{Name: "a", Transport: TransportCommand}},
		},
		"http without endpoint": {
			Listen:   Listen{Transport: TransportStdio},
			Backends: []Backend{{Name: "a", Transport: TransportHTTP}},
		},
		"http with scheme-less endpoint": {
			Listen:   Listen{Transport: TransportStdio},
			Backends: []Backend{{Name: "a", Transport: TransportHTTP, Endpoint: "example.com/mcp"}},
		},
		"http with non-http scheme": {
			Listen:   Listen{Transport: TransportStdio},
			Backends: []Backend{{Name: "a", Transport: TransportHTTP, Endpoint: "ftp://example.com/mcp"}},
		},
		"header auth without header name": {
			Listen: Listen{Transport: TransportStdio},
			Backends: []Backend{{
				Name: "a", Transport: TransportHTTP, Endpoint: "https://x",
				Auth: Auth{Type: AuthHeader, Value: "v"},
			}},
		},
		"command auth without command": {
			Listen: Listen{Transport: TransportStdio},
			Backends: []Backend{{
				Name: "a", Transport: TransportHTTP, Endpoint: "https://x",
				Auth: Auth{Type: AuthCommand},
			}},
		},
		"command auth bad ttl": {
			Listen: Listen{Transport: TransportStdio},
			Backends: []Backend{{
				Name: "a", Transport: TransportHTTP, Endpoint: "https://x",
				Auth: Auth{Type: AuthCommand, Command: []string{"x"}, TTL: "not-a-duration"},
			}},
		},
		"oauth client_id literal and command": {
			Listen: Listen{Transport: TransportStdio},
			Backends: []Backend{{
				Name: "a", Transport: TransportHTTP, Endpoint: "https://x",
				Auth: Auth{Type: AuthOAuth, ClientID: "cid", ClientIDCommand: []string{"pass", "show", "x"}},
			}},
		},
		"unknown auth type": {
			Listen: Listen{Transport: TransportStdio},
			Backends: []Backend{{
				Name: "a", Transport: TransportHTTP, Endpoint: "https://x",
				Auth: Auth{Type: "weird"},
			}},
		},
		"bad listen transport": {
			Listen:   Listen{Transport: TransportCommand},
			Backends: []Backend{{Name: "a", Transport: TransportCommand, Command: []string{"x"}}},
		},
	}

	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			c := cfg
			c.setDefaults()
			if err := c.Validate(); err == nil {
				t.Error("expected validation error, got nil")
			}
		})
	}
}

func TestConnectRetryDefaults(t *testing.T) {
	var r ConnectRetry
	if !r.IsEnabled() {
		t.Error("IsEnabled() = false for an unset config, want true (retry is on by default)")
	}
	if got := r.MaxDelayOrDefault(); got != defaultRetryMaxDelay {
		t.Errorf("MaxDelayOrDefault() = %s, want %s", got, defaultRetryMaxDelay)
	}
	if got := r.AttemptTimeoutOrDefault(); got != defaultRetryAttemptTimeout {
		t.Errorf("AttemptTimeoutOrDefault() = %s, want %s", got, defaultRetryAttemptTimeout)
	}

	off := false
	if (ConnectRetry{Enabled: &off}).IsEnabled() {
		t.Error("IsEnabled() = true with enabled: false")
	}
	set := ConnectRetry{MaxDelay: "90s", AttemptTimeout: "5s"}
	if got := set.MaxDelayOrDefault(); got != 90*time.Second {
		t.Errorf("MaxDelayOrDefault() = %s, want 90s", got)
	}
	if got := set.AttemptTimeoutOrDefault(); got != 5*time.Second {
		t.Errorf("AttemptTimeoutOrDefault() = %s, want 5s", got)
	}
}

func TestConnectRetryValidate(t *testing.T) {
	tests := []struct {
		name    string
		retry   ConnectRetry
		wantErr bool
	}{
		{"unset", ConnectRetry{}, false},
		{"valid", ConnectRetry{MaxDelay: "15m", AttemptTimeout: "2m"}, false},
		{"unparseable max_delay", ConnectRetry{MaxDelay: "soon"}, true},
		{"unparseable attempt_timeout", ConnectRetry{AttemptTimeout: "2"}, true},
		{"zero max_delay", ConnectRetry{MaxDelay: "0s"}, true},
		{"negative attempt_timeout", ConnectRetry{AttemptTimeout: "-1m"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.retry.validate(); (err != nil) != tc.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
