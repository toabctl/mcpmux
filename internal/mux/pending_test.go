// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package mux

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/toabctl/mcpmux/internal/config"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// testRetry is a retry policy tuned for tests: attempts are bounded loosely
// enough not to be flaky, and the backoff ceiling is short so a test that lets
// the loop run on its own does not wait minutes.
func testRetry() *RetryPolicy {
	return &RetryPolicy{MaxDelay: time.Second, AttemptTimeout: 30 * time.Second}
}

// waitFor polls until cond holds, failing the test if it never does. Used
// instead of a fixed sleep so the tests are neither slow nor timing-fragile.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, what)
}

// touch creates an empty file, opening a gated helper backend's gate.
func touch(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
}

// trackedCount reports how many backends the Mux holds, connected or not.
func (m *Mux) trackedCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.backends)
}

// TestPendingBackendRetriesUntilSuccess is the regression test for the bug this
// machinery exists to fix: a backend that fails its initial connect used to be
// dropped for the daemon's lifetime. It must instead be kept, retried, and
// registered once it works — with its catalog published exactly once.
func TestPendingBackendRetriesUntilSuccess(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	m := NewServer(&config.Config{}, testLogger())
	defer m.Close()

	if n := m.Connect(testCtx(t), []config.Backend{gatedHelperBackend("pb", ready)},
		ConnectOptions{Retry: testRetry()}); n != 0 {
		t.Fatalf("Connect reported %d backends connected, want 0 (the backend is gated)", n)
	}
	if got := m.trackedCount(); got != 1 {
		t.Fatalf("tracked backends = %d, want 1: a pending backend must be kept, not skipped", got)
	}
	if got := m.registeredCount(); got != 0 {
		t.Fatalf("registeredCount = %d, want 0 before the backend works", got)
	}
	if got := len(m.Catalog()); got != 0 {
		t.Fatalf("Catalog has %d tools, want 0 while the backend is pending", got)
	}

	// Open the gate, then kick: only the kick can make registration happen
	// before the (jittered) backoff would have fired on its own.
	touch(t, ready)
	if got := m.RetryPendingNow(); got != 1 {
		t.Fatalf("RetryPendingNow kicked %d backends, want 1", got)
	}
	waitFor(t, 15*time.Second, "the pending backend to register", func() bool {
		return m.registeredCount() == 1
	})

	cat := m.Catalog()
	if len(cat) != 1 || cat[0].Name != "pb__ping" {
		t.Fatalf("Catalog = %+v, want exactly one pb__ping entry (a second registration would duplicate it)", cat)
	}

	m.mu.Lock()
	b := m.backends[0]
	m.mu.Unlock()
	if _, err := b.current().CallTool(testCtx(t), &mcp.CallToolParams{Name: "ping"}); err != nil {
		t.Fatalf("CallTool on the retried session: %v", err)
	}
}

// TestPendingBackendWaitsBeforeRetrying pins that the loop actually waits
// between attempts rather than spinning: with no kick, a gated backend is still
// pending shortly after Connect returns.
func TestPendingBackendWaitsBeforeRetrying(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	m := NewServer(&config.Config{}, testLogger())
	defer m.Close()

	m.Connect(testCtx(t), []config.Backend{gatedHelperBackend("wait", ready)},
		ConnectOptions{Retry: testRetry()})
	touch(t, ready)
	time.Sleep(200 * time.Millisecond) // well below pendingBaseDelay
	if got := m.registeredCount(); got != 0 {
		t.Fatalf("registeredCount = %d, want 0: the loop must wait out its backoff, not spin", got)
	}
}

// TestPendingBackendSkippedWhenRetryDisabled verifies the escape hatch: with no
// retry policy the old behavior stands, so a failed backend is skipped outright
// rather than tracked.
func TestPendingBackendSkippedWhenRetryDisabled(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "never")
	m := NewServer(&config.Config{}, testLogger())
	defer m.Close()

	if n := m.Connect(testCtx(t), []config.Backend{gatedHelperBackend("nr", ready)}, ConnectOptions{}); n != 0 {
		t.Fatalf("Connect reported %d backends connected, want 0", n)
	}
	if got := m.trackedCount(); got != 0 {
		t.Fatalf("tracked backends = %d, want 0 when retry is disabled", got)
	}
}

// TestInteractiveBackendNotRetried is a safety test, not a feature test: a
// backend that can open a browser must never enter the retry loop. Each attempt
// would take the process-wide auth mutex, rebind the fixed callback port, and
// could pop a consent window the user never asked for.
func TestInteractiveBackendNotRetried(t *testing.T) {
	m := NewServer(&config.Config{}, testLogger())
	defer m.Close()

	oauth := config.Backend{
		Name:      "oauth",
		Transport: config.TransportHTTP,
		// Port 1 refuses immediately, so the attempt fails without a browser.
		Endpoint: "http://127.0.0.1:1/mcp",
		Auth:     config.Auth{Type: config.AuthOAuth},
	}
	if n := m.Connect(testCtx(t), []config.Backend{oauth}, ConnectOptions{Retry: testRetry()}); n != 0 {
		t.Fatalf("Connect reported %d backends connected, want 0", n)
	}
	if got := m.trackedCount(); got != 0 {
		t.Fatalf("tracked backends = %d, want 0: an interactive backend must be skipped, never retried", got)
	}
}

// TestRetryPendingNowIgnoresLiveBackends verifies the kick only touches
// backends that have never connected, so a signal cannot disturb live sessions.
func TestRetryPendingNowIgnoresLiveBackends(t *testing.T) {
	m := NewServer(&config.Config{}, testLogger())
	defer m.Close()

	if n := m.Connect(testCtx(t), []config.Backend{helperBackend("live")}, ConnectOptions{Retry: testRetry()}); n != 1 {
		t.Fatalf("Connect connected %d backends, want 1", n)
	}
	if got := m.RetryPendingNow(); got != 0 {
		t.Fatalf("RetryPendingNow kicked %d backends, want 0 when everything is live", got)
	}
}

// TestCloseStopsPendingRetry verifies that shutdown is not held up by a backend
// that never comes up. The bar is deliberately below pendingBaseDelay: Close
// must cancel the loop mid-sleep, not wait out the current backoff (which in
// production reaches the configured ceiling, minutes long).
func TestCloseStopsPendingRetry(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "never")
	m := NewServer(&config.Config{}, testLogger())
	m.Connect(testCtx(t), []config.Backend{gatedHelperBackend("stuck", ready)},
		ConnectOptions{Retry: &RetryPolicy{MaxDelay: time.Hour, AttemptTimeout: 30 * time.Second}})
	if got := m.trackedCount(); got != 1 {
		t.Fatalf("tracked backends = %d, want 1", got)
	}

	done := make(chan struct{})
	go func() { m.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return; the pending retry loop was not cancelled mid-backoff")
	}
}

func TestNextDelay(t *testing.T) {
	const ceiling = 8 * time.Second
	// Doubling, with jitter keeping each step within ±20% of the nominal value.
	for _, tc := range []struct{ cur, nominal time.Duration }{
		{1 * time.Second, 2 * time.Second},
		{2 * time.Second, 4 * time.Second},
		{4 * time.Second, 8 * time.Second},
		{8 * time.Second, 8 * time.Second}, // capped
		{time.Hour, 8 * time.Second},       // capped from above the ceiling
	} {
		lo := tc.nominal - tc.nominal/jitterFraction
		hi := tc.nominal + tc.nominal/jitterFraction
		for range 50 {
			got := nextDelay(tc.cur, ceiling)
			if got < lo || got > hi {
				t.Fatalf("nextDelay(%s, %s) = %s, want within [%s, %s]", tc.cur, ceiling, got, lo, hi)
			}
		}
	}
}

func TestJitterSpreadsAndStaysPositive(t *testing.T) {
	const d = 100 * time.Millisecond
	seen := make(map[time.Duration]bool)
	for range 200 {
		got := jitter(d)
		if got <= 0 {
			t.Fatalf("jitter(%s) = %s, want a positive delay", d, got)
		}
		seen[got] = true
	}
	if len(seen) < 2 {
		t.Error("jitter produced a single value; backends would retry in lockstep")
	}
	// A zero or negative input has no sensible spread and is passed through.
	if got := jitter(0); got != 0 {
		t.Errorf("jitter(0) = %s, want 0", got)
	}
}
