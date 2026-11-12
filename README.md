[English](README.md) · [Русский](README.ru.md)

# dsh-ssh-mcp

Persistent SSH sessions for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness),
exposed as MCP tools. The agent opens one connection per host and keeps using it,
instead of authenticating again for every command.

SSH automation usually fails in three places, and this plugin is built around
them:

- **Re-authentication on every command.** Opening a fresh `ssh` per command is
  slow and noisy. `open` starts one persistent session; `exec` reuses it, keeping
  the working directory and exported environment.
- **fail2ban.** A retry loop against a protected host gets the address banned for
  hours. The plugin counts failed connection attempts per `host:port` and stops
  after one retry.
- **sudo under root.** Many minimal images have no sudo at all, and for a root
  login it fails otherwise valid commands. The plugin detects `uid 0` and refuses
  to use sudo in a root session.

## Features

- One persistent `ssh -T` session per host, with per-command exit codes and
  output framing.
- Credential profiles in a JSON file: host, non-standard port, user, key file,
  fail2ban policy.
- Agent-based or explicit key authentication; password authentication is
  deliberately unsupported (no TTY, no one to answer the prompt).
- Root detection: `is_root` comes back from `open`, and `sudo` is rejected in a
  root session.
- Confirmation gate for `sudo` and for destructive commands (`rm -rf /`,
  `mkfs`, `dd of=/dev/...`, `reboot`, package removal, `DROP DATABASE`, …).
- Error classification with an actionable hint: `auth_failed`,
  `connection_refused`, `network_unreachable`, `dns_failed`,
  `host_key_rejected`, `connect_halted`, plus `local_path_missing`,
  `path_missing`, `spawn_failed` and `transfer_timeout`.
- `put` / `get` for file transfer over scp, with local paths resolved against
  the workspace.
- Server instructions carry the safety rules into the system prompt; an optional
  skill adds the full playbook.

## Requirements

- DeepSeek Harness with MCP client support (`@deepseek-ai/dsh-mcp-client`).
- OpenSSH client (`ssh`, `scp`) available on `PATH`. Windows 10/11 ships it;
  `Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0` enables it.
- A remote host with a POSIX `sh`. Windows remotes are not supported.
- No system Node.js install is needed: the MCP server runs on the same binary as
  the Harness, switched into Node mode.

## Install

### Plugin Manager (Desktop)

Settings → Plugins → install from a package spec, and enter:

```
github:extreme-russian-dsh-fandom/dsh-ssh-mcp
```

### Command line

```sh
dsh plugin --profile <profile> add github:extreme-russian-dsh-fandom/dsh-ssh-mcp
```

Pin a revision when you need reproducibility:

```sh
dsh plugin --profile <profile> add github:extreme-russian-dsh-fandom/dsh-ssh-mcp#v1.0.0
```

`github:` is pnpm's GitHub shorthand, not a DSH-specific scheme: `dsh plugin`
forwards the argument to pnpm, and the Plugin Manager checks the repository with
`git ls-remote` before running `pnpm add`.

After activation the tools appear as `mcp__ssh__<tool>`.

## Tools

| Tool | What it does |
| --- | --- |
| `mcp__ssh__profiles` | Lists credential profiles with host, port, user, auth mode, fail2ban policy. Never returns secrets. Call this first. |
| `mcp__ssh__open` | Opens one persistent session. Returns `session_id`, `is_root`, OS and shell. |
| `mcp__ssh__exec` | Runs a command in the session; returns exit code, stdout and stderr. Optional `sudo` and `confirmed`. |
| `mcp__ssh__sessions` | Lists open sessions with profile, user, root status and age. |
| `mcp__ssh__close` | Closes a session and releases the connection. |
| `mcp__ssh__put` | Copies a local file or directory to the host with scp. |
| `mcp__ssh__get` | Copies a remote file or directory into the workspace with scp. |

`put` and `get` resolve a relative `local_path` against the server's working
directory (the workspace at launch), not against the remote session's working
directory. The parent directory of the destination must already exist, and scp
expands neither `~` nor shell variables; pass absolute paths when in doubt.

## Credentials

The server reads `~/.dsh/ssh-credentials.json` (override with `--credentials`,
`SSH_MCP_CREDENTIALS`, or a `ssh-credentials.json` in the working directory).
The file is created by the user; the plugin never writes it.

```json
{
  "defaults": {
    "port": 22,
    "user": "root",
    "fail2ban": "unknown",
    "strictHostKey": "accept-new",
    "connectTimeoutMs": 15000
  },
  "hosts": {
    "prod-web": {
      "host": "203.0.113.10",
      "port": 22222,
      "user": "deploy",
      "auth": "agent",
      "fail2ban": "present",
      "description": "sshd on a non-standard port; the agent holds the key"
    },
    "prod-db": {
      "host": "db.internal.example",
      "port": 4242,
      "user": "root",
      "auth": "key",
      "identityFile": "C:\\Users\\me\\.ssh\\id_ed25519",
      "fail2ban": "present",
      "sudo": "none"
    }
  }
}
```

A complete example lives in
[`examples/ssh-credentials.example.json`](examples/ssh-credentials.example.json).

| Field | Values | Meaning |
| --- | --- | --- |
| `host` | string | Address or DNS name. Required. |
| `port` | 1–65535 | sshd port; high ports are normal for hardened hosts. |
| `user` | string | Login user. Defaults to the `defaults` block. |
| `auth` | `auto`, `agent`, `key` | `auto` uses `identityFile` when present, otherwise the agent/default keys. |
| `identityFile` | path | Private key for `auth: key`. |
| `fail2ban` | `unknown`, `present`, `absent` | Attempt budget: 2 by default, 3 only when explicitly `absent`. |
| `sudo` | `nopasswd`, `none` | Whether passwordless sudo is expected on this host. |
| `strictHostKey` | `accept-new`, `yes`, `no` | `accept-new` trusts a host on first contact; `yes` requires known_hosts. |
| `connectTimeoutMs` | 1000–120000 | TCP/auth timeout for one attempt. |

Keep the file private (`chmod 600` on POSIX). It must never be committed; the
repository `.gitignore` already excludes it.

Password authentication is not supported: the MCP server has no terminal, so
`ssh` cannot answer a password prompt. Install the public key on the remote host
or use an ssh-agent. A profile that declares `passwordFile` fails with
`password_auth_unsupported` on purpose.

## Safety model

| Rule | Behaviour |
| --- | --- |
| fail2ban awareness | Failed connections are counted per `host:port`. After the budget is spent, the host is halted for the life of the process and the tool tells the agent to stop and ask the user. Purely local failures (a missing local path, a missing OpenSSH client) are not counted, because they never reach the host. |
| Root sessions | `open` reports `is_root`. `exec` with `sudo: true` in a root session returns `sudo_not_applicable`; the command must be repeated without sudo. |
| Confirmations | `sudo` and destructive commands require `confirmed: true`, which the agent may set only after the user explicitly agrees. |
| Secrets | The credentials file path is the only thing the model sees; it never receives key material or passwords. |

Server instructions embed these rules in the system prompt, so they apply even
without the skill.

## Optional skill

The plugin ships a ready playbook at
[`skill/remote-ssh/SKILL.md`](skill/remote-ssh/SKILL.md). Copy it to your skills
directory for the full troubleshooting guide:

```sh
mkdir -p ~/.dsh/skills/remote-ssh
cp skill/remote-ssh/SKILL.md ~/.dsh/skills/remote-ssh/
```

## Configuration

| Variable | Purpose |
| --- | --- |
| `DSH_SSH_MCP_SERVER` | Absolute path to `server/index.mjs`, if the package is not under `<cwd>/node_modules/dsh-ssh-mcp`. |
| `DSH_SSH_MCP_NODE` | Binary used to run the server. Defaults to the running Harness binary. |
| `DSH_SSH_MCP_TIMEOUT_MS` | Per-call timeout for MCP tools. Defaults to 600000. |
| `SSH_MCP_CREDENTIALS` | Alternative credentials file path. |

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| No `mcp__ssh__*` tools | The MCP server failed to start. Check that `ssh.exe`/`ssh` is on `PATH` and that the hostname is correct. |
| `credential_missing` | Create `~/.dsh/ssh-credentials.json`; `mcp__ssh__profiles` returns a template. |
| `auth_failed` | The remote host does not accept the key. Add the public key to `authorized_keys`; the plugin allows one retry only. |
| `connect_halted` | The attempt budget for this host is spent. Fix connectivity, then restart the harness process. The hint names the failure code that consumed it. |
| `local_path_missing`, `path_missing` | One side of a `put`/`get` has no such path; nothing was copied and no attempt was charged. Check both paths (relative local paths resolve against the workspace). |
| `spawn_failed` | `ssh` or `scp` could not be started. Install the OpenSSH client or add it to `PATH`; this local failure does not consume the attempt budget. |
| `sudo_requires_password` | Passwordless sudo is not configured. Add a `NOPASSWD` rule or run the command manually. |
| `host_key_rejected` | The host key changed. Verify the host and update `known_hosts`; the plugin never weakens host key checking. |

## Uninstall

```sh
dsh plugin --profile <profile> remove dsh-ssh-mcp
```

## License

MIT. See [LICENSE](LICENSE).
