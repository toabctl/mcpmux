// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package mux

import (
	"context"
	"time"
)

// Reconnect backoff bounds. A backend that fails to come back retries forever
// with capped exponential backoff (a daemon prefers eventual recovery over
// giving up), logging each attempt so a wedged backend is visible.
const (
	reconnectBaseDelay = 1 * time.Second
	reconnectMaxDelay  = 60 * time.Second
)

// supervise watches one backend's session and reconnects it whenever the
// session dies, until ctx is cancelled or the Mux begins closing. It runs as a
// single goroutine per backend, so reconnects for a given backend are naturally
// serialized (no concurrent dial/consent for the same backend).
//
// session.Wait blocks until the upstream connection closes — whether the SSE
// stream gave up reconnecting, a keepalive ping went unanswered, or the server
// hung up. A close we initiated during shutdown is distinguished by m.closing.
func (m *Mux) supervise(ctx context.Context, b *backend) {
	defer m.svg.Done()
	for {
		err := b.current().Wait()
		if m.closing.Load() || ctx.Err() != nil {
			return // shutdown closed the session; not a failure to recover from
		}
		m.log.Warn("backend session closed; reconnecting", "backend", b.name, "err", err)
		if !m.reconnect(ctx, b) {
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
// agnostic.
func (m *Mux) reconnect(ctx context.Context, b *backend) bool {
	delay := reconnectBaseDelay
	for attempt := 1; ; attempt++ {
		if m.closing.Load() || ctx.Err() != nil {
			return false
		}
		session, err := b.connect(ctx)
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
		m.log.Warn("backend reconnect failed; will retry",
			"backend", b.name, "attempt", attempt, "delay", delay, "err", err)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return false
		}
		if delay *= 2; delay > reconnectMaxDelay {
			delay = reconnectMaxDelay
		}
	}
}
