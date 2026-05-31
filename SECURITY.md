<!--
SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
SPDX-License-Identifier: Apache-2.0
-->

# Security Policy

## Reporting a vulnerability

Please report security issues **privately** via GitHub's
[private vulnerability reporting](https://github.com/toabctl/mcpmux/security/advisories/new)
("Report a vulnerability" under the repository's Security tab). Do not open a
public issue for security problems.

Please include reproduction steps and affected version/commit. You can expect an
initial acknowledgement within a few days.

## Security model

mcpmux is a multiplexer that holds credentials for several backend MCP servers
and exposes them through one endpoint. Operators should be aware:

- **The client→mcpmux hop is not authenticated.** Anyone who can reach the
  listen address can use every backend with its credentials. mcpmux therefore
  defaults to binding `127.0.0.1` and warns if configured otherwise. Do not
  expose it on an untrusted network without your own authenticating proxy.
- **The configuration is trusted input.** It can launch arbitrary commands
  (`transport: command`, `auth: command`); only use configs you control.
- **Backend tokens live in memory** for the daemon's lifetime and are not
  written to disk. They are not logged (tool arguments are never logged).

## Supported versions

This project is pre-1.0; only the latest release/`main` receives fixes.
