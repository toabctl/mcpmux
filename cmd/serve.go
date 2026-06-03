// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"log/slog"
	"net"
	"os/signal"
	"syscall"

	"github.com/toabctl/mcpmux/internal/config"
	"github.com/toabctl/mcpmux/internal/mux"

	"github.com/coreos/go-systemd/v22/activation"
	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/spf13/cobra"
)

// noClientAuthWarning is logged when mcpmux binds a non-loopback address: the
// client->mcpmux hop is unauthenticated, so anyone who can reach it can use
// every backend with its credentials.
const noClientAuthWarning = "listening on a non-loopback address with no client authentication: " +
	"anyone who can reach this address can use every backend with its credentials"

func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the multiplexer",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			log := newLogger()

			cfg, err := loadConfig(log)
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			m := mux.NewServer(cfg, log)
			defer m.Close()

			// Connect non-interactive backends now so their tools are ready
			// immediately. Interactive OAuth backends (which open a browser) are
			// deferred to the background so their consents block neither serving
			// nor the systemd readiness signal — they register their tools via
			// tools/list_changed as each consent completes.
			syncBackends, oauthBackends := mux.PartitionBackends(cfg.Backends)
			m.Connect(ctx, syncBackends, cfg.EagerAuth)

			if cfg.Listen.Transport != config.TransportHTTP {
				m.ConnectInBackground(ctx, oauthBackends, cfg.EagerAuth)
				return m.ServeStdio(ctx)
			}

			// Non-interactive backends are connected; tell systemd we're ready
			// (no-op when not socket-activated / NOTIFY_SOCKET unset), then bring
			// up the interactive OAuth backends in the background.
			_, _ = daemon.SdNotify(false, daemon.SdNotifyReady)
			m.ConnectInBackground(ctx, oauthBackends, cfg.EagerAuth)

			// Prefer a socket passed by systemd (socket activation) over binding
			// the configured address ourselves.
			if ln := firstListener(log); ln != nil {
				log.Info("using socket-activated listener", "address", ln.Addr().String())
				if !listenerIsLoopback(ln) {
					log.Warn(noClientAuthWarning, "address", ln.Addr().String())
				}
				return m.ServeHTTPListener(ctx, ln, cfg.Listen.Path)
			}
			if !cfg.Listen.IsLoopback() {
				log.Warn(noClientAuthWarning, "address", cfg.Listen.Address)
			}
			return m.ServeHTTP(ctx, cfg.Listen.Address, cfg.Listen.Path)
		},
	}
}

// firstListener returns the first usable socket-activated listener, or nil when
// not running under systemd socket activation.
func firstListener(log *slog.Logger) net.Listener {
	listeners, err := activation.Listeners()
	if err != nil {
		log.Warn("could not read socket-activated listeners", "err", err)
		return nil
	}
	for _, l := range listeners {
		if l != nil {
			return l
		}
	}
	return nil
}

// listenerIsLoopback reports whether ln is bound to a loopback address. A
// non-TCP listener (e.g. a unix socket) is treated as local and safe.
func listenerIsLoopback(ln net.Listener) bool {
	if a, ok := ln.Addr().(*net.TCPAddr); ok {
		return a.IP.IsLoopback()
	}
	return true
}
