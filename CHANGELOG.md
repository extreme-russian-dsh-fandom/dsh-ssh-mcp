# Changelog

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
