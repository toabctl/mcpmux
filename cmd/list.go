// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os/signal"
	"strings"
	"syscall"

	"github.com/toabctl/mcpmux/internal/mux"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

func newListCmd() *cobra.Command {
	var (
		descriptions bool
		endpoint     string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "Print the aggregated tool catalog",
		Long: "Print the aggregated tool catalog.\n\n" +
			"By default this connects to the configured backends (authenticating as\n" +
			"needed). Pass --endpoint to instead query a running mcpmux HTTP endpoint,\n" +
			"which already has every backend connected (no re-authentication).",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			if endpoint != "" {
				return listEndpoint(ctx, endpoint, descriptions)
			}

			log := newLogger()
			cfg, err := loadConfig(log)
			if err != nil {
				return err
			}
			m, err := mux.New(ctx, cfg, log)
			if err != nil {
				return err
			}
			defer m.Close()

			for _, t := range m.Catalog() {
				printTool(t.Name, t.Description, descriptions)
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&descriptions, "descriptions", "d", false, "print each tool's description")
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "query a running mcpmux HTTP endpoint instead of the backends")
	return cmd
}

// listEndpoint connects to a running mcpmux (or any MCP) HTTP endpoint and
// prints its aggregated tools, optionally with descriptions.
func listEndpoint(ctx context.Context, endpoint string, descriptions bool) error {
	client := mcp.NewClient(&mcp.Implementation{Name: "mcpmux-list", Version: version}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint}, nil)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", endpoint, err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.ListTools(ctx, nil)
	if err != nil {
		return fmt.Errorf("list tools from %s: %w", endpoint, err)
	}
	for _, t := range res.Tools {
		printTool(t.Name, t.Description, descriptions)
	}
	return nil
}

// printTool renders one tool, optionally with its (whitespace-collapsed) description.
func printTool(name, description string, withDesc bool) {
	if withDesc {
		fmt.Printf("%s\n    %s\n", name, strings.Join(strings.Fields(description), " "))
	} else {
		fmt.Println(name)
	}
}
