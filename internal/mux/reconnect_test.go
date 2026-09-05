// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package mux

import (
	"testing"
	"time"

	"github.com/toabctl/mcpmux/internal/config"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestSupervisorReconnectsDeadSession verifies that when a backend's session
// dies, the supervisor brings up a fresh session (swapped in atomically) and
// that the replacement is usable. The command-transport helper backend is
// re-spawned by its dialer on reconnect.
func TestSupervisorReconnectsDeadSession(t *testing.T) {
	m := NewServer(&config.Config{}, testLogger())
	defer m.Close()

	if n := m.Connect(testCtx(t), []config.Backend{helperBackend("rc")}, ConnectOptions{}); n != 1 {
		t.Fatalf("Connect connected %d backends, want 1", n)
	}

	m.mu.Lock()
	b := m.backends[0]
	m.mu.Unlock()

	old := b.current()
	// Simulate an upstream death: close the live session. The supervisor should
	// observe Wait returning and bring up a fresh session.
	_ = old.Close()

	deadline := time.Now().Add(15 * time.Second)
	cur := old
	for time.Now().Before(deadline) {
		if cur = b.current(); cur != old {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if cur == old {
		t.Fatal("supervisor did not reconnect: session was not replaced")
	}

	// The fresh session must be usable.
	if _, err := cur.CallTool(testCtx(t), &mcp.CallToolParams{Name: "ping"}); err != nil {
		t.Fatalf("CallTool on reconnected session: %v", err)
	}
}

// TestCloseStopsSupervisorWithoutReconnect verifies that closing the Mux does
// not race with a reconnect: a session closed during shutdown is treated as
// intentional, so the supervisor exits rather than re-spawning the backend, and
// Close returns promptly.
func TestCloseStopsSupervisorWithoutReconnect(t *testing.T) {
	m := NewServer(&config.Config{}, testLogger())
	if n := m.Connect(testCtx(t), []config.Backend{helperBackend("cl")}, ConnectOptions{}); n != 1 {
		t.Fatalf("Connect connected %d backends, want 1", n)
	}

	done := make(chan struct{})
	go func() { m.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Close did not return; supervisor likely reconnected or was not awaited")
	}
}
