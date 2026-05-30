// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

// Command echoserver is a trivial stdio MCP server used to smoke-test mcpmux.
// It exposes a single "echo" tool that returns its "text" argument.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type echoInput struct {
	Text string `json:"text" jsonschema:"the text to echo back"`
}

func echo(_ context.Context, _ *mcp.CallToolRequest, in echoInput) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: in.Text}},
	}, nil, nil
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "echoserver", Version: "v0.1.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "echo back the given text"}, echo)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		slog.Error("echoserver failed", "err", err)
		os.Exit(1)
	}
}
