// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package mux

import (
	"context"
	"math/rand/v2"
	"time"
)

// Backoff bounds. A backend that will not come up retries forever with capped
// exponential backoff (a daemon prefers eventual recovery over giving up).
const (
	// reconnectBaseDelay starts the backoff for a backend whose established
	// session dropped — usually a blip, so retry quickly.
	reconnectBaseDelay = 1 * time.Second
	reconnectMaxDelay  = 60 * time.Second
	// pendingBaseDelay starts the backoff for a backend that has never
	// connected. It is longer because the usual cause is a credential that
	// needs human action, not something that fixes itself in a second.
	pendingBaseDelay = 5 * time.Second
)

// Logging volume for a backend that keeps failing: the first few attempts are
// warnings, then the loop drops to debug with a warning heartbeat, so a wedged
// backend stays visible without filling the journal (at a 60s cap, logging
// every attempt is ~1440 lines a day per backend).
const (
	verboseAttempts   = 3
	heartbeatInterval = time.Hour
)

// jitterFraction spreads a delay by ±20%.
const jitterFraction = 5

// run owns a backend for its whole life on a single goroutine. A backend that
// is not yet live first goes through the pending-retry loop; once it is up (or
// if it already was), its session is supervised until shutdown. One goroutine
// per backend means attempts for a given backend are naturally serialized: no
// two dials, credential-helper invocations or registrations can race.
func (m *Mux) run(ctx context.Context, b *backend, opts ConnectOptions, live bool) {
	defer m.svg.Done()

	// Work under a context that Close cancels as well as the caller's, so
	// neither a long backoff sleep nor an in-flight attempt delays shutdown.
	// AfterFunc costs nothing until it fires.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(m.closeCtx, cancel)()

	if !live && !m.awaitFirstConnect(ctx, b, opts) {
		return // shut down before the backend ever came up
	}
	m.supervise(ctx, b, opts)
}

// awaitFirstConnect retries a backend that failed its initial connect until it
// comes up, returning true once its tools are registered, or false if the Mux
// shut down first. A kick from RetryPendingNow short-circuits the wait.
//
// Every attempt re-runs whatever credential helper the backend is configured
// with, so the delay is capped and jittered to keep that cost bounded. The log
// line carries the backend name, attempt, delay and error only — never the
// helper's argv, the endpoint or any credential.
func (m *Mux) awaitFirstConnect(ctx context.Context, b *backend, opts ConnectOptions) bool {
	// Only connectOne starts this loop, and only with a policy, but a daemon
	// must not panic on a future caller's nil: fall back to a fixed delay.
	ceiling := pendingBaseDelay
	if opts.Retry != nil {
		ceiling = opts.Retry.MaxDelay
	}
	delay := jitter(pendingBaseDelay)
	lastLoud := time.Now()
	for attempt := 1; ; attempt++ {
		select {
		case <-time.After(delay):
		case <-b.kick:
			m.log.Info("retrying pending backend on request", "backend", b.name)
		case <-ctx.Done():
			return false
		}
		if m.closing.Load() || ctx.Err() != nil {
			return false
		}

		n, err := m.bringUp(ctx, b, opts)
		if err == nil {
			// Lost the race with shutdown: don't leave a session dangling that
			// Close already iterated past.
			if m.closing.Load() {
				if s := b.current(); s != nil {
					_ = s.Close()
				}
				return false
			}
			m.log.Info("registered backend after retry",
				"backend", b.name, "tools", n, "attempts", attempt)
			return true
		}
		m.logAttempt("backend still down; will retry", b.name, attempt, delay, &lastLoud, err)
		delay = nextDelay(delay, ceiling)
	}
}

// supervise watches one backend's session and reconnects it whenever the
// session dies, until ctx is cancelled or the Mux begins closing.
//
// session.Wait blocks until the upstream connection closes — whether the SSE
// stream gave up reconnecting, a keepalive ping went unanswered, or the server
// hung up. A close we initiated during shutdown is distinguished by m.closing.
func (m *Mux) supervise(ctx context.Context, b *backend, opts ConnectOptions) {
	for {
		err := b.current().Wait()
		if m.closing.Load() || ctx.Err() != nil {
			return // shutdown closed the session; not a failure to recover from
		}
		m.log.Warn("backend session closed; reconnecting", "backend", b.name, "err", err)
		if !m.reconnect(ctx, b, opts) {
			return // ctx cancelled (or Mux closing) before a new session came up
		}
		m.log.Info("backend reconnected", "backend", b.name)
	}
}

// reconnect re-establishes b's session with capped exponential backoff. It
// returns true once a fresh session is live and stored, or false if ctx was
// cancelled (or the Mux began closing) first. The dialer decides whether the
// transport is reused (HTTP: cached, so a valid OAuth token carries over) or
// rebuilt (command: a fresh subprocess), so reconnect itself is transport-
// agnostic. The tool catalog is not re-registered: the proxy's handlers read
// b.current() per call, so they follow the swap.
func (m *Mux) reconnect(ctx context.Context, b *backend, opts ConnectOptions) bool {
	delay := jitter(reconnectBaseDelay)
	lastLoud := time.Now()
	for attempt := 1; ; attempt++ {
		if m.closing.Load() || ctx.Err() != nil {
			return false
		}
		session, err := b.connect(ctx, opts.attemptTimeout())
		if err == nil {
			// Lost the race with shutdown: don't leave a session dangling that
			// Close already iterated past.
			if m.closing.Load() {
				_ = session.Close()
				return false
			}
			b.session.Store(session)
			return true
		}
		m.logAttempt("backend reconnect failed; will retry", b.name, attempt, delay, &lastLoud, err)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return false
		}
		delay = nextDelay(delay, reconnectMaxDelay)
	}
}

// logAttempt logs a failed (re)connect attempt, loudly for the first few and
// then quietly with a periodic warning, so a permanently wedged backend stays
// visible without filling the journal. It reports the backend, attempt, delay
// and error only: a credential helper's stderr reaches us through err, and
// nothing else about the backend's credentials is ever logged.
func (m *Mux) logAttempt(msg, name string, attempt int, delay time.Duration, lastLoud *time.Time, err error) {
	if attempt <= verboseAttempts || time.Since(*lastLoud) >= heartbeatInterval {
		m.log.Warn(msg, "backend", name, "attempt", attempt, "delay", delay, "err", err)
		*lastLoud = time.Now()
		return
	}
	m.log.Debug(msg, "backend", name, "attempt", attempt, "delay", delay, "err", err)
}

// nextDelay doubles cur, capped at ceiling, and re-applies jitter. Jitter
// matters most at startup: every backend fails in the same instant, so without
// it a group of backends would retry in lockstep forever, and a shared
// dependency (one credential helper, one authorization server) would see them
// all arrive together every time.
func nextDelay(cur, ceiling time.Duration) time.Duration {
	next := cur * 2
	if next > ceiling {
		next = ceiling
	}
	return jitter(next)
}

// jitter spreads d by ±20%, never returning a non-positive delay.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	spread := int64(d) / jitterFraction
	if spread == 0 {
		return d
	}
	//nolint:gosec // G404: spreading retry delays needs no cryptographic randomness.
	return d + time.Duration(rand.Int64N(2*spread+1)-spread)
}
