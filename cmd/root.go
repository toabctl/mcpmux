// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

// Package cmd implements the mcpmux command-line interface.
package cmd

import (
	"log/slog"
	"os"

	"github.com/toabctl/mcpmux/internal/config"

	"github.com/spf13/cobra"
)

var (
	cfgPath  string
	logLevel string
	version  = "dev"
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "mcpmux",
		Short: "Aggregate multiple MCP servers behind a single endpoint",
		Long: "mcpmux is a Model Context Protocol multiplexer.\n\n" +
			"It connects to several upstream MCP servers, merges their tools under\n" +
			"namespaced \"<backend>__<tool>\" names, and re-exposes them through one MCP\n" +
			"endpoint (stdio or streamable HTTP). Clients authenticate once to mcpmux;\n" +
			"mcpmux holds each backend's credentials.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}
	root.PersistentFlags().StringVarP(&cfgPath, "config", "c", "", "config file (default: ./mcpmux.yaml or $XDG_CONFIG_HOME/mcpmux/config.yaml)")
	root.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn, error")

	root.AddCommand(newServeCmd(), newListCmd())
	return root
}

// Execute runs the mcpmux CLI, reporting the given build version.
func Execute(v string) {
	version = v
	if err := newRootCmd().Execute(); err != nil {
		newLogger().Error("mcpmux failed", "err", err)
		os.Exit(1)
	}
}

// loadConfig resolves the config path (flag or search path) and loads it,
// logging which file was chosen.
func loadConfig(log *slog.Logger) (*config.Config, error) {
	path, err := config.Resolve(cfgPath)
	if err != nil {
		return nil, err
	}
	log.Info("using config", "path", path)
	return config.Load(path)
}

// newLogger builds a slog logger writing to stderr, so stdout stays clean for
// the stdio MCP transport.
func newLogger() *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(logLevel)); err != nil {
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
