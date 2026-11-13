import { randomBytes } from 'node:crypto'
import { existsSync } from 'node:fs'
import { isAbsolute, resolve } from 'node:path'

import { CREDENTIALS_TEMPLATE, CredentialsError, loadCredentials, publicProfiles, resolveProfile } from './credentials.mjs'
import { AttemptBudget, chargesBudget, classifyCommand, failureHint } from './policy.mjs'
import { scpTransfer, SshError, SshSession, probe, sudoExec } from './ssh.mjs'

export const SERVER_INFO = { name: 'ssh-mcp', version: '1.1.0' }
export const DEFAULT_TIMEOUT_MS = 60000
export const MAX_TIMEOUT_MS = 600000
export const MAX_OUTPUT_BYTES = 192 * 1024

export const INSTRUCTIONS = [
  'Remote SSH rules for this workspace (they override convenience):',
  '',
  '1. fail2ban: a rejected login can ban this address for hours. Never retry with other users, keys, ports, or guessed credentials. A failed connection gets at most one retry per host; purely local errors (a bad local path, a missing OpenSSH client) are not counted. After that, stop and ask the user to repair connectivity before doing anything else.',
  '2. Root logins: when a session reports is_root true, sudo is unavailable on many systems and would fail otherwise valid commands. Never call exec with sudo=true in a root session.',
  '3. Confirmation: ask the user before sudo and before any destructive command, then repeat the call with confirmed=true. Never confirm on the user\'s behalf.',
  '4. Credentials live in ssh-credentials.json in this workspace. Never ask the user to paste a password or private key into chat; ask them to edit that file instead.',
  '5. Reuse one session for many commands instead of reopening it for each call.',
].join('\n')

/**
 * Tool metadata sent by `tools/list`.
 *
 * Every tool declares all four MCP annotations explicitly, even where a hint
 * equals its protocol default. Directories such as OpenAI's reject a tool when
 * any hint is missing or is not a boolean, so none may be inferred.
 *
 * The hints describe what the handler actually does, not what a particular
 * call happens to do:
 * - readOnlyHint: the handler changes no data on either side.
 * - destructiveHint: the handler may overwrite or remove data (exec runs an
 *   arbitrary command; put and get overwrite an existing destination).
 * - idempotentHint: repeating the call with the same arguments adds no further
 *   effect to the world, even if the second call reports an error.
 * - openWorldHint: the handler talks to a remote host chosen by the caller.
 */
export const TOOLS = [
  {
    name: 'profiles',
    title: 'List SSH profiles',
    description: 'List the SSH profiles defined in the workspace credentials file. Returns each alias with host, port, user, authentication mode, fail2ban policy, and whether a key file is configured; secrets are never returned. Call this first. When the list is empty, the user must fill the credentials file, whose path and template are included in the result.',
    annotations: {
      title: 'List SSH profiles',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'open',
    title: 'Open SSH session',
    description: 'Open one persistent SSH session and keep it for later exec calls. Returns a session id, the remote OS and shell, and whether the login user is root. Connection failures are counted per host: after the allowed attempts the host is halted until the process restarts, and the result says so.',
    annotations: {
      title: 'Open SSH session',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
    inputSchema: {
      type: 'object',
      properties: {
        profile: { type: 'string', description: 'Profile alias from the credentials file.' },
      },
      required: ['profile'],
      additionalProperties: false,
    },
  },
  {
    name: 'exec',
    title: 'Run remote command',
    description: 'Run one command inside an open session and return its exit code, stdout and stderr. The working directory and exported environment persist between calls. Large output is truncated with an explicit marker.',
    annotations: {
      title: 'Run remote command',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
    inputSchema: {
      type: 'object',
      properties: {
        session_id: { type: 'string', description: 'Session id returned by open.' },
        command: { type: 'string', description: 'Shell command to run on the remote host. Runs through sh, so POSIX syntax is expected.' },
        timeout_ms: { type: 'integer', description: 'Command deadline in milliseconds, 1000 to 600000. Defaults to 60000.' },
        sudo: { type: 'boolean', description: 'Run through passwordless sudo. Set only when the task needs root and the session is not root; requires confirmed=true.' },
        confirmed: { type: 'boolean', description: 'True only after the user explicitly approved this sudo or destructive command.' },
      },
      required: ['session_id', 'command'],
      additionalProperties: false,
    },
  },
  {
    name: 'sessions',
    title: 'List SSH sessions',
    description: 'List open sessions with their profile, user, root status and age.',
    annotations: {
      title: 'List SSH sessions',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'close',
    title: 'Close SSH session',
    description: 'Close one session and release the remote connection.',
    annotations: {
      title: 'Close SSH session',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    inputSchema: {
      type: 'object',
      properties: { session_id: { type: 'string' } },
      required: ['session_id'],
      additionalProperties: false,
    },
  },
  {
    name: 'put',
    title: 'Upload file to remote host',
    description: 'Copy a local file or directory to the remote host with scp, reusing a profile. An existing destination file is overwritten. Connection failures count against the same per-host connection budget as open; purely local failures (a missing local path, a missing OpenSSH client) are reported without charging that budget.',
    annotations: {
      title: 'Upload file to remote host',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    inputSchema: {
      type: 'object',
      properties: {
        profile: { type: 'string' },
        local_path: { type: 'string', description: 'Absolute local path, or a path relative to the server workspace directory. The path must already exist; ~ is not expanded.' },
        remote_path: { type: 'string', description: 'Destination path on the remote host. Its parent directory must exist; scp does not create it. An existing file at this path is overwritten.' },
        recursive: { type: 'boolean', description: 'Copy a directory tree; required when local_path is a directory.' },
      },
      required: ['profile', 'local_path', 'remote_path'],
      additionalProperties: false,
    },
  },
  {
    name: 'get',
    title: 'Download file from remote host',
    description: 'Copy a remote file or directory to the local workspace with scp, reusing a profile. An existing local destination file is overwritten. Connection failures count against the same per-host connection budget as open; purely local failures are reported without charging that budget.',
    annotations: {
      title: 'Download file from remote host',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    inputSchema: {
      type: 'object',
      properties: {
        profile: { type: 'string' },
        remote_path: { type: 'string', description: 'Source path on the remote host.' },
        local_path: { type: 'string', description: 'Destination path, absolute or relative to the server workspace directory. Its parent directory must exist. An existing file at this path is overwritten.' },
        recursive: { type: 'boolean', description: 'Copy a directory tree; required when remote_path is a directory.' },
      },
      required: ['profile', 'remote_path', 'local_path'],
      additionalProperties: false,
    },
  },
]

function truncate(text) {
  const value = String(text ?? '')
  const bytes = Buffer.byteLength(value, 'utf8')
  if (bytes <= MAX_OUTPUT_BYTES) return { text: value, truncated: false, bytes }
  const buffer = Buffer.from(value, 'utf8')
  const head = buffer.subarray(0, 128 * 1024).toString('utf8')
  const tail = buffer.subarray(buffer.length - 64 * 1024).toString('utf8')
  return {
    text: head + '\n...[truncated ' + String(bytes - MAX_OUTPUT_BYTES) + ' bytes]...\n' + tail,
    truncated: true,
    bytes,
  }
}

function ok(value) {
  return { content: [{ type: 'text', text: JSON.stringify({ ok: true, ...value }) }] }
}

function refuse(value) {
  return { content: [{ type: 'text', text: JSON.stringify({ ok: false, ...value }) }] }
}

function budgetKey(profile) {
  return profile.host + ':' + String(profile.port)
}

/**
 * Builds the tool handlers for one server instance. The transport in
 * `index.mjs` owns the JSON-RPC loop and passes in the workspace and the
 * credentials path; everything that reaches the network is injectable, so the
 * handlers can be tested without an SSH host.
 */
export function createToolset({
  workspace,
  credentialsPath,
  sessions = new Map(),
  budget = new AttemptBudget(),
  probe: probeImpl = probe,
  createSession = (id, alias, profile) => new SshSession(id, alias, profile),
  scpTransfer: scpTransferImpl = scpTransfer,
  sudoExec: sudoExecImpl = sudoExec,
}) {
  function credentials() {
    return loadCredentials(credentialsPath)
  }

  /**
   * Local transfer paths are resolved against the server's working directory,
   * which is the workspace at launch. scp expands neither `~` nor shell
   * variables, so the path is passed exactly as resolved.
   */
  function resolveLocalPath(value) {
    const text = String(value)
    return isAbsolute(text) ? text : resolve(workspace, text)
  }

  async function toolProfiles() {
    const loaded = credentials()
    const result = {
      credentials_path: credentialsPath,
      exists: loaded.exists,
      profiles: publicProfiles(loaded),
    }
    if (loaded.error !== undefined) result.credentials_error = loaded.error
    if (!loaded.exists || result.profiles.length === 0) {
      result.template = CREDENTIALS_TEMPLATE
      result.hint = loaded.exists
        ? 'The credentials file exists but defines no usable host. Ask the user to add a host entry; never ask for passwords in chat.'
        : 'No credentials file yet. Ask the user to create it from the template below. A profile name is the JSON key; port is per host, so a non-standard sshd port belongs there.'
    }
    return ok(result)
  }

  async function toolOpen(args) {
    const loaded = credentials()
    if (!loaded.exists) {
      return refuse({
        error: { code: 'credentials_missing', message: 'No credentials file at ' + credentialsPath },
        template: CREDENTIALS_TEMPLATE,
      })
    }
    if (loaded.error !== undefined && Object.keys(loaded.hosts).length === 0) {
      return refuse({ error: { code: 'credentials_invalid', message: loaded.error } })
    }

    let profile
    try {
      profile = resolveProfile(loaded, args.profile)
    } catch (error) {
      if (error instanceof CredentialsError) return refuse({ error: { code: error.code, message: error.message, ...error.details } })
      throw error
    }

    const key = budgetKey(profile)
    const state = budget.check(key, profile.fail2ban)
    if (!state.allowed) {
      return refuse({
        error: {
          code: 'connect_halted',
          message: 'Connection attempts to ' + key + ' are exhausted for this process. Do not try again.',
        },
        attempts: state,
        hint: failureHint(state.lastFailureCode ?? 'ssh_failed', state.remaining),
      })
    }

    const probeResult = await probeImpl(profile, profile.connectTimeoutMs + 5000)
    if (!probeResult.ok) {
      const code = probeResult.code ?? 'ssh_failed'
      const snapshot = budget.snapshot(key, profile.fail2ban)
      if (!chargesBudget(code)) {
        return refuse({
          error: { code, message: probeResult.stderr || 'Connection failed' },
          attempts: snapshot,
          hint: failureHint(code, snapshot.remaining),
        })
      }
      const after = budget.recordFailure(key, profile.fail2ban, code)
      return refuse({
        error: { code, message: probeResult.stderr || 'Connection failed' },
        attempts: after,
        hint: failureHint(code, after.remaining),
      })
    }
    budget.recordSuccess(key)

    const id = 'ssh_' + randomBytes(4).toString('hex')
    const session = createSession(id, profile.alias, profile)
    try {
      await session.open()
    } catch (error) {
      const code = error instanceof SshError ? error.code : 'ssh_failed'
      if (!chargesBudget(code)) {
        const snapshot = budget.snapshot(key, profile.fail2ban)
        return refuse({ error: { code, message: error.message }, attempts: snapshot, hint: failureHint(code, snapshot.remaining) })
      }
      const after = budget.recordFailure(key, profile.fail2ban, code)
      return refuse({ error: { code, message: error.message }, attempts: after, hint: failureHint(code, after.remaining) })
    }

    const meta = { id, profile, session, isRoot: false, shell: undefined, os: undefined, createdAt: Date.now() }
    try {
      const uid = await session.exec('id -u', { timeoutMs: 15000 })
      meta.isRoot = uid.stdout.trim() === '0'
      const os = await session.exec('uname -s 2>/dev/null || echo unknown', { timeoutMs: 15000 })
      meta.os = os.stdout.trim() || 'unknown'
      const shell = await session.exec('printf %s "$SHELL"', { timeoutMs: 15000 })
      meta.shell = shell.stdout.trim() || 'unknown'
    } catch {
      // Detection is best effort; the session stays usable.
    }
    sessions.set(id, meta)

    return ok({
      session_id: id,
      profile: profile.alias,
      host: profile.host,
      port: profile.port,
      user: profile.user,
      is_root: meta.isRoot,
      os: meta.os,
      shell: meta.shell,
      attempts_remaining: budget.snapshot(key, profile.fail2ban).remaining,
      note: meta.isRoot
        ? 'The login user is root. sudo is not available; run privileged commands directly.'
        : 'The login user is not root. Use sudo=true with confirmed=true only after the user approves.',
    })
  }

  async function toolExec(args) {
    const entry = sessions.get(String(args.session_id))
    if (entry === undefined) {
      return refuse({ error: { code: 'unknown_session', message: 'No session "' + String(args.session_id) + '". Call open first.' } })
    }
    if (entry.session.closed) {
      return refuse({ error: { code: 'session_dead', message: 'Session "' + entry.profile.alias + '" is closed: ' + String(entry.session.closeReason) } })
    }

    const timeoutMs = Math.min(Math.max(Number(args.timeout_ms ?? DEFAULT_TIMEOUT_MS), 1000), MAX_TIMEOUT_MS)
    const wantsSudo = args.sudo === true
    const confirmed = args.confirmed === true

    if (wantsSudo && entry.isRoot) {
      return refuse({
        error: {
          code: 'sudo_not_applicable',
          message: 'The session user is root, so sudo must not be used: many systems lack sudo or reject it for root. Repeat the command without sudo.',
        },
      })
    }
    if (wantsSudo && !confirmed) {
      return refuse({
        confirmation_required: true,
        error: { code: 'confirmation_required', message: 'sudo requires the user\'s approval. Ask the user, then repeat with confirmed=true.' },
        command: args.command,
      })
    }
    const danger = classifyCommand(args.command)
    if (danger !== null && !confirmed) {
      return refuse({
        confirmation_required: true,
        error: { code: 'confirmation_required', message: 'This command is destructive (' + danger + '). Ask the user, then repeat with confirmed=true.' },
        command: args.command,
      })
    }

    try {
      const result = wantsSudo
        ? await sudoExecImpl(entry.profile, args.command, timeoutMs)
        : await entry.session.exec(args.command, { timeoutMs })
      const stdout = truncate(result.stdout)
      const stderr = truncate(result.stderr ?? '')
      return ok({
        session_id: entry.id,
        exit_code: result.exitCode,
        stdout: stdout.text,
        stderr: stderr.text,
        truncated: stdout.truncated || stderr.truncated,
      })
    } catch (error) {
      const code = error instanceof SshError ? error.code : 'exec_failed'
      return refuse({ error: { code, message: error.message } })
    }
  }

  async function toolSessions() {
    return ok({
      sessions: [...sessions.values()].map((entry) => ({
        session_id: entry.id,
        profile: entry.profile.alias,
        host: entry.profile.host,
        user: entry.profile.user,
        is_root: entry.isRoot,
        os: entry.os,
        shell: entry.shell,
        alive: !entry.session.closed,
        age_seconds: Math.round((Date.now() - entry.createdAt) / 1000),
      })),
    })
  }

  async function toolClose(args) {
    const id = String(args.session_id)
    const entry = sessions.get(id)
    if (entry === undefined) return refuse({ error: { code: 'unknown_session', message: 'No session "' + id + '"' } })
    await entry.session.close('closed by client')
    sessions.delete(id)
    return ok({ session_id: id, closed: true })
  }

  async function transfer(args, direction) {
    const loaded = credentials()
    if (!loaded.exists) {
      return refuse({ error: { code: 'credentials_missing', message: 'No credentials file at ' + credentialsPath } })
    }
    let profile
    try {
      profile = resolveProfile(loaded, args.profile)
    } catch (error) {
      if (error instanceof CredentialsError) return refuse({ error: { code: error.code, message: error.message } })
      throw error
    }
    if (typeof args.local_path !== 'string' || args.local_path.trim() === '') {
      return refuse({ error: { code: 'invalid_argument', message: 'local_path must be a non-empty string' } })
    }
    if (typeof args.remote_path !== 'string' || args.remote_path.trim() === '') {
      return refuse({ error: { code: 'invalid_argument', message: 'remote_path must be a non-empty string' } })
    }
    const localPath = resolveLocalPath(args.local_path)
    const key = budgetKey(profile)
    const snapshot = budget.snapshot(key, profile.fail2ban)
    if (direction === 'put' && !existsSync(localPath)) {
      return refuse({
        error: { code: 'local_path_missing', message: 'Local path does not exist: ' + localPath },
        attempts: snapshot,
        hint: failureHint('local_path_missing', snapshot.remaining),
      })
    }
    const state = budget.check(key, profile.fail2ban)
    if (!state.allowed) {
      return refuse({
        error: { code: 'connect_halted', message: 'Connection attempts to ' + key + ' are exhausted for this process.' },
        attempts: state,
        hint: failureHint(state.lastFailureCode ?? 'ssh_failed', state.remaining),
      })
    }
    try {
      await scpTransferImpl({
        target: profile,
        direction,
        localPath,
        remotePath: args.remote_path,
        recursive: args.recursive === true,
      })
      budget.recordSuccess(key)
      return ok({ direction, profile: profile.alias, local_path: localPath, remote_path: args.remote_path })
    } catch (error) {
      const code = error instanceof SshError ? error.code : 'transfer_failed'
      if (!chargesBudget(code)) {
        // A purely local failure must not consume a fail2ban attempt: nothing was
        // sent to the host, and a missing local path is not a rejected login.
        const afterLocal = budget.snapshot(key, profile.fail2ban)
        return refuse({ error: { code, message: error.message }, attempts: afterLocal, hint: failureHint(code, afterLocal.remaining) })
      }
      const after = budget.recordFailure(key, profile.fail2ban, code)
      return refuse({ error: { code, message: error.message }, attempts: after, hint: failureHint(code, after.remaining) })
    }
  }

  async function dispatch(method, params) {
    switch (method) {
      case 'profiles':
        return toolProfiles()
      case 'open':
        return toolOpen(params)
      case 'exec':
        return toolExec(params)
      case 'sessions':
        return toolSessions()
      case 'close':
        return toolClose(params)
      case 'put':
        return transfer(params, 'put')
      case 'get':
        return transfer(params, 'get')
      default:
        return refuse({ error: { code: 'unknown_tool', message: 'Unknown tool "' + method + '"' } })
    }
  }

  return { dispatch, sessions, budget }
}
