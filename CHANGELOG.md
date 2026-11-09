# Changelog

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
