<!--
SPDX-FileCopyrightText: 2026 Thomas Bechtold <thomasbechtold@jpberlin.de>
SPDX-License-Identifier: Apache-2.0
-->

# mcpmux

A minimal **Model Context Protocol (MCP) multiplexer**. It connects to several
upstream MCP servers ("backends"), merges their tools under namespaced
`<backend>__<tool>` names, and re-exposes them through a **single MCP endpoint**
(stdio or streamable HTTP).

The client (e.g. Claude Code) authenticates **once to mcpmux**; mcpmux holds each
backend's credentials and forwards calls to the right backend.

```
                       ┌──────────────── mcpmux ────────────────┐
   MCP client  ──────► │  MCP server  ─►  router  ─►  client(s)  │ ─► backend A (command, env secrets)
   (one endpoint)      │                                         │ ─► backend B (http, bearer token)
                       └─────────────────────────────────────────┘ ─► backend C (http, custom header)
```

## Install

```sh
go install github.com/toabctl/mcpmux@latest   # installs `mcpmux`
# or build from a checkout:
make build                                     # produces ./mcpmux
```

## Configure

Copy `mcpmux.example.yaml` to a config file and edit. `${ENV_VAR}` references are
expanded from the environment at load time, so secrets stay out of the file.

`mcpmux` looks for its config in this order (first match wins); override with
`--config/-c`:

1. `./mcpmux.yaml`
2. `$XDG_CONFIG_HOME/mcpmux/config.yaml` (Linux: `~/.config/mcpmux/config.yaml`)
3. `$XDG_CONFIG_HOME/mcpmux.yaml`

- `listen.transport`: `stdio` or `http`.
- `listen.address` / `listen.path`: bind address and URL path for `http`
  (clients connect to `http://<address><path>`, e.g. `http://127.0.0.1:8080/mcp`).
- `backends[]`: each has a unique `name` (used as the tool prefix) and a
  `transport`:
  - `command` — launched as a subprocess; pass secrets via `env`.
  - `http` — a streamable-HTTP endpoint; authenticate with `auth.type` of:
    - `none` — no credentials.
    - `bearer` — static `token` sent as `Authorization: Bearer <token>`.
    - `header` — a custom `header` name + `value`.
    - `command` — run a credential helper (`command: [...]`) whose stdout is
      the bearer token. The token is cached and re-run only when it nears
      expiry (a JWT `exp` claim is honored; `ttl` caps caching for opaque
      tokens) or when the backend returns 401/403. Ideal for CLIs that already
      hold a login, e.g. `chainctl auth token --audience <resource>` — no
      browser, ever.
    - `oauth` — interactive authorization-code + PKCE flow with dynamic client
      registration (RFC 7591). A browser opens **once when the daemon starts**;
      the SDK handles discovery, PKCE, token exchange and in-memory refresh.
      Options: `scopes`, `client_name`, `open_browser` (default true; false
      just logs the URL for headless use), `callback_port` (0 = ephemeral).

## Run

```sh
mcpmux serve -c mcpmux.yaml      # run the proxy
mcpmux list  -c mcpmux.yaml      # debug: print the aggregated tool catalog
```

Logs go to **stderr**, leaving stdout clean for the stdio MCP transport.

## Run as a daemon (systemd user service)

Running mcpmux as a long-lived user service is the intended setup: you
authenticate backends **once when the daemon starts**, and every Claude Code
session reuses the daemon's live tokens instead of re-authenticating per
session.

```sh
make install                                   # binary -> ~/.local/bin, units -> ~/.config/systemd/user
systemctl --user daemon-reload
```

mcpmux ships a **`.service`** and a **`.socket`** (socket activation). systemd
owns the listening socket, so it survives service restarts — clients never get
"connection refused" while mcpmux restarts or re-authenticates. Two modes:

**A) Always-on + socket** (recommended when you have interactive OAuth backends
like Linear — it authenticates once at startup and stays up):

```sh
systemctl --user enable --now mcpmux.socket mcpmux.service
```

**B) On-demand** (only if *all* backends are non-interactive — the service
starts on the first connection):

```sh
systemctl --user enable --now mcpmux.socket
```

```sh
journalctl --user -u mcpmux -f                 # watch logs / OAuth URLs
```

When socket-activated, the **socket's `ListenStream` address is authoritative**
and `listen.address` in the config is ignored (the passed socket is used);
`listen.path` still applies. mcpmux signals readiness via `sd_notify`
(`Type=notify`), and the unit allows 5 minutes for an interactive browser
authorization at startup.

For `oauth` backends to auto-open a browser from the service, make the graphical
session visible to systemd once after login:

```sh
systemctl --user import-environment DISPLAY WAYLAND_DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS
```

Otherwise set `open_browser: false` on those backends and click the URL printed
in the journal.

> Note: mode B (on-demand) is a poor fit for interactive OAuth backends — the
> first connection would block while the browser flow completes and likely time
> out. Use mode A when any backend uses `auth.type: oauth`.

## Use from Claude Code

Start mcpmux, then register the single endpoint with Claude Code:

```sh
mcpmux serve                                                      # uses ~/.config/mcpmux/config.yaml
claude mcp add --transport http mcpmux http://127.0.0.1:8080/mcp
```

Tools appear namespaced, e.g. `github__create_issue`. Remove the individual
servers you configured into mcpmux (`claude mcp remove <name>`) so their tools
don't show up twice.

For `listen.transport: stdio`, let Claude Code launch it instead:

```sh
claude mcp add mcpmux -- /path/to/mcpmux serve -c /path/to/mcpmux.yaml
```

## Scope & limitations

- **Backend auth supported:** env vars for stdio (`command` transport) backends;
  for `http` backends `none`/`bearer`/`header`, the `command` credential helper
  (dynamic bearer token from an external CLI, auto-refreshed), and interactive
  `oauth` (authorization-code + PKCE + dynamic client registration; tokens held
  in memory for the daemon's lifetime).
- **Not yet:** persisting OAuth tokens across restarts (each daemon start
  re-authenticates `oauth` backends), and authenticating the *client→mcpmux* hop
  (run it on localhost or behind your own reverse proxy / auth gateway).
- Tool-name collisions are avoided by the `<backend>__` prefix. Resources and
  prompts are not yet aggregated — tools only.

## Development

```sh
pre-commit install && pre-commit install --hook-type commit-msg
```

Hooks run gofmt/golangci-lint, `go vet`, `govulncheck`, `go mod tidy`, and
Conventional Commits checks; `go test` runs on push. Commit messages must follow
[Conventional Commits](https://www.conventionalcommits.org).

## License

[Apache-2.0](LICENSE) © Thomas Bechtold
