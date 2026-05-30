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

func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the multiplexer",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			log := newLogger()
			mux.SetVersion(version)

			cfg, err := loadConfig(log)
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			m, err := mux.New(ctx, cfg, log)
			if err != nil {
				return err
			}
			defer m.Close()

			if cfg.Listen.Transport != config.TransportHTTP {
				return m.ServeStdio(ctx)
			}

			// All backends are connected; tell systemd we're ready (no-op when
			// not socket-activated / NOTIFY_SOCKET unset).
			_, _ = daemon.SdNotify(false, daemon.SdNotifyReady)

			// Prefer a socket passed by systemd (socket activation) over binding
			// the configured address ourselves.
			if ln := firstListener(log); ln != nil {
				log.Info("using socket-activated listener", "address", ln.Addr().String())
				return m.ServeHTTPListener(ctx, ln, cfg.Listen.Path)
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
