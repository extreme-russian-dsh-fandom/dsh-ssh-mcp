# Changelog

## 1.1.0 — 2026-11-13

Quality release for MCP directories: every tool now carries complete, accurate
annotations, and the test suite covers all seven tools instead of only the lower
layers.

- Every tool declares `title` and all four MCP annotations (`readOnlyHint`,
  `destructiveHint`, `idempotentHint`, `openWorldHint`) as explicit booleans.
  `exec`, `put` and `get` are destructive; `open`, `exec`, `put` and `get` are
  open-world; `put` and `get` are idempotent. A metadata test fails if a hint is
  missing, is not a boolean, or drifts from the documented table.
- Tool descriptions and both READMEs now state that `put` and `get` overwrite an
  existing destination file.
- Tool handlers moved to `server/tools.mjs` with injectable network seams, and
  the JSON-RPC envelope moved to `server/rpc.mjs`; `server/index.mjs` now only
  parses argv, wires the transport, and shuts down.
- Tests: per-tool coverage for `profiles`, `open`, `exec`, `sessions`, `close`,
  `put` and `get`; protocol tests for `initialize`, `tools/list`, `tools/call`,
  parse errors and drain-on-close; a real stdio handshake test.
- CI runs the suite on Node.js 22 and 24.
- Package metadata gains `repository`, `homepage` and `bugs`.

## 1.0.1 — 2026-11-12

File transfer was broken for every target and every path; this release fixes it
and the accounting bug that turned a local error into a durable lockout.

- `put` / `get` passed ssh's `-p <port>` to `scp`, where lowercase `-p` takes no
  argument. The port became the source operand, and scp failed before reaching
  the network with `stat local "<port>": No such file or directory`. scp now
  receives `-P <port>` while ssh keeps `-p <port>`.
- A purely local transfer failure (missing local path, `ssh`/`scp` not
  installed, rejected argument) no longer consumes the per-host fail2ban attempt
  budget, so it cannot halt a reachable host. The same applies when our own
  transfer deadline expires after the connection already worked.
- `connect_halted` reports the failure code that spent the budget instead of
  always blaming authentication; `attempts.lastFailureCode` is included.
- scp operands are preceded by `--`, so a path starting with `-` is not parsed
  as an option, and missing paths get `local_path_missing` / `path_missing`
  instead of the generic `ssh_failed`. An IPv6 host literal is bracketed, so
  `user@[2001:db8::1]:/path` is no longer split at its first colon.
- `open`, `exec` and transfers enable SSH keepalives
  (`ServerAliveInterval=15`, `ServerAliveCountMax=3`), so a dead connection ends
  instead of hanging until the command timeout.
- A spawn that fails synchronously (`ssh`/`scp` missing, sandbox denial) is
  reported as `spawn_failed` instead of an unclassified crash or a session
  error.
- The credentials file may start with a UTF-8 byte-order mark, which Windows
  editors and PowerShell's `Set-Content -Encoding utf8` write; previously it was
  rejected as "not valid JSON".
- Documentation: relative `put`/`get` local paths resolve against the workspace,
  not the remote session's working directory.

## 1.0.0 — 2026-11-09

First public release.

- Seven MCP tools: `profiles`, `open`, `exec`, `sessions`, `close`, `put`, `get`.
- Persistent `ssh -T` session with per-command exit codes and output framing.
- Credential profiles with per-host port, user, key file and fail2ban policy.
- Root detection: `sudo` is rejected in a root session.
- Confirmation gate for `sudo` and destructive commands.
- fail2ban-aware attempt budget: one retry by default, three only when a profile
  declares `"fail2ban": "absent"`.
- Error classification with actionable hints.
- Server instructions plus an optional `remote-ssh` skill.
