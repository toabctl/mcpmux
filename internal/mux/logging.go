// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

package mux

import (
	"context"
	"log/slog"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// requestLogger returns receiving middleware that debug-logs every inbound MCP
// request from the client: the JSON-RPC method, the tool name for tools/call,
// the duration, and any error. It short-circuits to a no-op unless debug
// logging is enabled, so it adds no overhead at the default level.
func requestLogger(log *slog.Logger) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if !log.Enabled(ctx, slog.LevelDebug) {
				return next(ctx, method, req)
			}

			attrs := []any{"method", method}
			if ctr, ok := req.(*mcp.CallToolRequest); ok && ctr.Params != nil {
				attrs = append(attrs, "tool", ctr.Params.Name)
			}
			log.Debug("mcp request", attrs...)

			start := time.Now()
			res, err := next(ctx, method, req)
			attrs = append(attrs, "dur", time.Since(start).Round(time.Millisecond).String())
			if err != nil {
				log.Debug("mcp request failed", append(attrs, "err", err)...)
			} else {
				log.Debug("mcp request ok", attrs...)
			}
			return res, err
		}
	}
}
