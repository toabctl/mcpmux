// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cmd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/toabctl/mcpmux/internal/mux"
)

// retryOnSignal makes SIGUSR1 kick every backend that is still waiting on its
// first successful connect. This is the recovery path when backends were skipped
// or left pending because a credential was unavailable at startup: refresh the
// credential, send one signal, and they come up — no restart, so live client
// sessions survive and interactive OAuth backends are not asked to consent
// again. SIGHUP is deliberately left alone for a future config reload.
//
// The handler returns immediately; the watcher runs until ctx is cancelled.
func retryOnSignal(ctx context.Context, m *mux.Mux, log *slog.Logger) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-ch:
				m.RetryPendingNow()
			case <-ctx.Done():
				return
			}
		}
	}()
	log.Debug("signal handler installed", "signal", "SIGUSR1", "action", "retry pending backends")
}
