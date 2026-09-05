// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package mux

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/toabctl/mcpmux/internal/config"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// helperServerEnv, when set, makes TestHelperMCPServerProcess run a minimal MCP
// stdio server instead of behaving as a normal (no-op) test. It lets the tests
// below spawn a real backend by re-executing the test binary.
const helperServerEnv = "MCPMUX_HELPER_MCP_SERVER"

// helperReadyFileEnv names a file the helper process requires before it will
// serve. It models a backend that is unavailable at startup — a credential
// helper with an expired token, an upstream that is still booting — and becomes
// available later, without the test needing a shell or a network service.
const helperReadyFileEnv = "MCPMUX_HELPER_READY_FILE"

// helperBackend returns a command-transport backend config that runs the test
// binary as a minimal MCP server exposing a single "ping" tool.
func helperBackend(name string) config.Backend {
	return config.Backend{
		Name:      name,
		Transport: config.TransportCommand,
		Command:   []string{os.Args[0], "-test.run=^TestHelperMCPServerProcess$"},
		Env:       map[string]string{helperServerEnv: "1"},
	}
}

// gatedHelperBackend is helperBackend with a gate: the spawned process exits
// non-zero until ready exists, so the backend fails to connect and then starts
// working once the test creates the file.
func gatedHelperBackend(name, ready string) config.Backend {
	b := helperBackend(name)
	b.Env[helperReadyFileEnv] = ready
	return b
}

// TestHelperMCPServerProcess is not a real test: when re-executed with
// helperServerEnv set (see helperBackend) it serves a one-tool MCP server over
// stdio until its stdin is closed, then exits. Under a normal test run the env
// var is unset and it returns immediately.
func TestHelperMCPServerProcess(t *testing.T) {
	if os.Getenv(helperServerEnv) != "1" {
		t.Skip("only runs as a spawned MCP server subprocess (see helperBackend)")
	}
	// Exit before serving when gated on a file that does not exist yet, so the
	// parent sees a failed connect rather than a working backend.
	if f := os.Getenv(helperReadyFileEnv); f != "" {
		if _, err := os.Stat(f); err != nil {
			os.Exit(1)
		}
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "helper", Version: "test"}, nil)
	srv.AddTool(
		&mcp.Tool{Name: "ping", Description: "returns pong", InputSchema: map[string]any{"type": "object"}},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{}, nil
		},
	)
	// Run blocks until the parent closes our stdin (session.Close); ctx is
	// background because the lifetime is bounded by stdin, not a signal here.
	_ = srv.Run(context.Background(), &mcp.StdioTransport{})
	os.Exit(0)
}

func TestPartitionBackends(t *testing.T) {
	in := []config.Backend{
		{Name: "cmd", Transport: config.TransportCommand},
		{Name: "oauth1", Transport: config.TransportHTTP, Auth: config.Auth{Type: config.AuthOAuth}},
		{Name: "bearer", Transport: config.TransportHTTP, Auth: config.Auth{Type: config.AuthBearer}},
		{Name: "oauth2", Transport: config.TransportHTTP, Auth: config.Auth{Type: config.AuthOAuth}},
		{Name: "helper-cmd-auth", Transport: config.TransportHTTP, Auth: config.Auth{Type: config.AuthCommand}},
	}
	names := func(bs []config.Backend) []string {
		out := make([]string, len(bs))
		for i, b := range bs {
			out[i] = b.Name
		}
		return out
	}

	noninteractive, interactive := PartitionBackends(in)

	if got, want := names(interactive), []string{"oauth1", "oauth2"}; !slices.Equal(got, want) {
		t.Errorf("interactive = %v, want %v", got, want)
	}
	// Everything that does not open a browser, in original order.
	if got, want := names(noninteractive), []string{"cmd", "bearer", "helper-cmd-auth"}; !slices.Equal(got, want) {
		t.Errorf("noninteractive = %v, want %v", got, want)
	}
}

// TestConnectRegistersBackendTools verifies the synchronous Connect path: a
// connected backend's tools are namespaced and appear in Catalog.
func TestConnectRegistersBackendTools(t *testing.T) {
	m := NewServer(&config.Config{}, testLogger())
	defer m.Close()

	if n := m.Connect(testCtx(t), []config.Backend{helperBackend("hb")}, ConnectOptions{}); n != 1 {
		t.Fatalf("Connect connected %d backends, want 1", n)
	}

	cat := m.Catalog()
	got := make([]string, len(cat))
	for i, c := range cat {
		got[i] = c.Name
	}
	if !slices.Contains(got, "hb__ping") {
		t.Errorf("Catalog = %v, want it to contain %q", got, "hb__ping")
	}
}

// TestConnectInBackgroundAndClose verifies that backends brought up in the
// background register their tools while the Mux is otherwise live (Catalog read
// concurrently), and that Close waits for the goroutine and returns promptly.
// Run under -race, this exercises the mu-guarded backends slice and the wg.
func TestConnectInBackgroundAndClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := NewServer(&config.Config{}, testLogger())
	m.ConnectInBackground(ctx, []config.Backend{helperBackend("bg")}, ConnectOptions{})

	// Poll Catalog (a concurrent reader) until the background backend registers,
	// bounded so a regression fails fast instead of hanging.
	deadline := time.Now().Add(15 * time.Second)
	registered := false
	for time.Now().Before(deadline) {
		for _, c := range m.Catalog() {
			if c.Name == "bg__ping" {
				registered = true
			}
		}
		if registered {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !registered {
		t.Fatal("background backend never registered its tool")
	}

	// Cancel the context (as shutdown does) and ensure Close waits for the
	// background goroutine and returns without hanging.
	cancel()
	done := make(chan struct{})
	go func() { m.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Close did not return; background goroutine likely not awaited")
	}
}
