// SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
// SPDX-License-Identifier: Apache-2.0

// Command mcpmux is a Model Context Protocol multiplexer: it proxies a single
// MCP endpoint onto several backend MCP servers, holding their credentials.
package main

import "github.com/toabctl/mcpmux/cmd"

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cmd.Execute(version)
}
