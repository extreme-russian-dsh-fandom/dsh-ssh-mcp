#!/usr/bin/env node
import { createInterface } from 'node:readline'
import { randomBytes } from 'node:crypto'
import { existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { isAbsolute, join, resolve } from 'node:path'

import { CREDENTIALS_TEMPLATE, CredentialsError, loadCredentials, publicProfiles, resolveProfile } from './credentials.mjs'
import { AttemptBudget, classifyCommand } from './policy.mjs'
import { scpTransfer, SshError, SshSession, probe, sudoExec } from './ssh.mjs'

const SERVER_INFO = { name: 'ssh-mcp', version: '1.0.0' }
const PROTOCOL_FALLBACK = '2025-06-18'
const DEFAULT_TIMEOUT_MS = 60000
const MAX_TIMEOUT_MS = 600000
const MAX_OUTPUT_BYTES = 192 * 1024

const INSTRUCTIONS = [
  'Remote SSH rules for this workspace (they override convenience):',
  '',
  '1. fail2ban: a rejected login can ban this address for hours. Never retry with other users, keys, ports, or guessed credentials. A failed connection gets at most one retry per host; after that, stop and ask the user to repair connectivity before doing anything else.',
  '2. Root logins: when a session reports is_root true, sudo is unavailable on many systems and would fail otherwise valid commands. Never call exec with sudo=true in a root session.',
  '3. Confirmation: ask the user before sudo and before any destructive command, then repeat the call with confirmed=true. Never confirm on the user\'s behalf.',
  '4. Credentials live in ssh-credentials.json in this workspace. Never ask the user to paste a password or private key into chat; ask them to edit that file instead.',
  '5. Reuse one session for many commands instead of reopening it for each call.',
].join('\n')

const TOOLS = [
  {
    name: 'profiles',
    description: 'List the SSH profiles defined in the workspace credentials file. Returns each alias with host, port, user, authentication mode, fail2ban policy, and whether a key file is configured; secrets are never returned. Call this first. When the list is empty, the user must fill the credentials file, whose path and template are included in the result.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'open',
    description: 'Open one persistent SSH session and keep it for later exec calls. Returns a session id, the remote OS and shell, and whether the login user is root. Connection failures are counted per host: after the allowed attempts the host is halted until the process restarts, and the result says so.',
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
    description: 'Run one command inside an open session and return its exit code, stdout and stderr. The working directory and exported environment persist between calls. Large output is truncated with an explicit marker.',
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
    description: 'List open sessions with their profile, user, root status and age.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'close',
    description: 'Close one session and release the remote connection.',
    inputSchema: {
      type: 'object',
      properties: { session_id: { type: 'string' } },
      required: ['session_id'],
      additionalProperties: false,
    },
  },
  {
    name: 'put',
    description: 'Copy a local file or directory to the remote host with scp, reusing a profile. Counts against the same per-host connection budget as open.',
    inputSchema: {
      type: 'object',
      properties: {
        profile: { type: 'string' },
        local_path: { type: 'string', description: 'Absolute local path inside the workspace, or a path relative to the session working directory.' },
        remote_path: { type: 'string', description: 'Destination path on the remote host.' },
        recursive: { type: 'boolean', description: 'Copy a directory tree.' },
      },
      required: ['profile', 'local_path', 'remote_path'],
      additionalProperties: false,
    },
  },
  {
    name: 'get',
    description: 'Copy a remote file or directory to the local workspace with scp, reusing a profile. Counts against the same per-host connection budget as open.',
    inputSchema: {
      type: 'object',
      properties: {
        profile: { type: 'string' },
        remote_path: { type: 'string', description: 'Source path on the remote host.' },
        local_path: { type: 'string', description: 'Destination path, absolute or relative to the workspace.' },
        recursive: { type: 'boolean', description: 'Copy a directory tree.' },
      },
      required: ['profile', 'remote_path', 'local_path'],
      additionalProperties: false,
    },
  },
]

function parseArgv(argv) {
  const options = { credentials: process.env.SSH_MCP_CREDENTIALS ?? '' }
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--credentials' && argv[index + 1] !== undefined) {
      options.credentials = argv[index + 1]
      index += 1
    } else if (argv[index] === '--workspace' && argv[index + 1] !== undefined) {
      options.workspace = argv[index + 1]
      index += 1
    }
  }
  return options
}

const options = parseArgv(process.argv.slice(2))
const workspace = options.workspace ?? process.cwd()

function resolveCredentialsPath() {
  if (options.credentials !== '') {
    return isAbsolute(options.credentials) ? options.credentials : resolve(workspace, options.credentials)
  }
  const home = join(homedir(), '.dsh', 'ssh-credentials.json')
  if (existsSync(home)) return home
  const local = resolve(workspace, 'ssh-credentials.json')
  if (existsSync(local)) return local
  return home
}

const credentialsPath = resolveCredentialsPath()

const sessions = new Map()
const budget = new AttemptBudget()

function credentials() {
  return loadCredentials(credentialsPath)
}

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

function failureHint(code, remaining) {
  const base = remaining > 0
    ? 'One retry is allowed. Do not try other users, keys or ports.'
    : 'No attempts left for this host. Stop here and ask the user to repair SSH connectivity (authorized_keys, port, fail2ban, network) before continuing.'
  switch (code) {
    case 'auth_failed':
      return 'The remote host rejected authentication. ' + base + ' The user must add the public key to authorized_keys or fix the ssh-agent.'
    case 'connection_refused':
      return 'Nothing accepted the connection on this host and port. ' + base + ' The port may be wrong or sshd may be listening elsewhere.'
    case 'network_unreachable':
    case 'timeout':
      return 'The host did not answer in time. ' + base + ' Check the address, port, firewall and network path.'
    case 'dns_failed':
      return 'The host name did not resolve. ' + base + ' Ask the user for the correct address.'
    case 'host_key_rejected':
      return 'The host key does not match known_hosts. Stop and ask the user; do not weaken host key checking.'
    default:
      return base
  }
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
      hint: failureHint('auth_failed', state.remaining),
    })
  }

  const probeResult = await probe(profile, profile.connectTimeoutMs + 5000)
  if (!probeResult.ok) {
    const after = budget.recordFailure(key, profile.fail2ban)
    return refuse({
      error: { code: probeResult.code, message: probeResult.stderr || 'Connection failed' },
      attempts: after,
      hint: failureHint(probeResult.code, after.remaining),
    })
  }
  budget.recordSuccess(key)

  const id = 'ssh_' + randomBytes(4).toString('hex')
  const session = new SshSession(id, profile.alias, profile)
  try {
    await session.open()
  } catch (error) {
    const after = budget.recordFailure(key, profile.fail2ban)
    const code = error instanceof SshError ? error.code : 'ssh_failed'
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
      ? await sudoExec(entry.profile, args.command, timeoutMs)
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
  const localPath = isAbsolute(args.local_path) ? args.local_path : resolve(workspace, args.local_path)
  if (direction === 'put' && !existsSync(localPath)) {
    return refuse({ error: { code: 'local_missing', message: 'Local path does not exist: ' + localPath } })
  }
  const key = budgetKey(profile)
  const state = budget.check(key, profile.fail2ban)
  if (!state.allowed) {
    return refuse({
      error: { code: 'connect_halted', message: 'Connection attempts to ' + key + ' are exhausted for this process.' },
      attempts: state,
    })
  }
  try {
    await scpTransfer({
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
    const after = budget.recordFailure(key, profile.fail2ban)
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

function send(message) {
  process.stdout.write(JSON.stringify(message) + '\n')
}

let inflight = 0
let closing = false
let down = false

async function shutdown(exitCode = 0) {
  if (down) return
  down = true
  await Promise.allSettled([...sessions.values()].map((entry) => entry.session.close('harness shutting down')))
  sessions.clear()
  process.exit(exitCode)
}

function maybeExit() {
  if (closing && inflight === 0) void shutdown(0)
}

async function handleLine(line) {
  const text = line.trim()
  if (text === '') return
  let message
  try {
    message = JSON.parse(text)
  } catch {
    send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } })
    return
  }
  if (message === null || typeof message !== 'object') return
  const { id, method, params } = message
  const isRequest = id !== undefined && id !== null

  if (method === 'initialize') {
    const requested = params !== null && typeof params === 'object' ? params.protocolVersion : undefined
    send({
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: typeof requested === 'string' && requested !== '' ? requested : PROTOCOL_FALLBACK,
        capabilities: { tools: { listChanged: false } },
        serverInfo: SERVER_INFO,
        instructions: INSTRUCTIONS,
      },
    })
    return
  }
  if (method === 'ping') {
    if (isRequest) send({ jsonrpc: '2.0', id, result: {} })
    return
  }
  if (method === 'tools/list') {
    send({ jsonrpc: '2.0', id, result: { tools: TOOLS } })
    return
  }
  if (method === 'resources/list') {
    if (isRequest) send({ jsonrpc: '2.0', id, result: { resources: [] } })
    return
  }
  if (method === 'shutdown') {
    if (isRequest) send({ jsonrpc: '2.0', id, result: null })
    return
  }
  if (method === 'tools/call') {
    const name = params !== null && typeof params === 'object' ? params.name : undefined
    const args = params !== null && typeof params === 'object' && params.arguments !== null && typeof params.arguments === 'object'
      ? params.arguments
      : {}
    inflight += 1
    try {
      let result
      try {
        result = await dispatch(String(name), args)
      } catch (error) {
        result = {
          content: [{ type: 'text', text: JSON.stringify({ ok: false, error: { code: 'internal_error', message: String(error?.message ?? error) } }) }],
          isError: true,
        }
      }
      send({ jsonrpc: '2.0', id, result })
    } finally {
      inflight -= 1
      maybeExit()
    }
    return
  }
  if (!isRequest) return
  send({ jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found: ' + String(method) } })
}

const reader = createInterface({ input: process.stdin, crlfDelay: Infinity })
reader.on('line', (line) => {
  void handleLine(line)
})
reader.on('close', () => {
  closing = true
  maybeExit()
})

process.on('SIGTERM', () => void shutdown(0))
process.on('SIGINT', () => void shutdown(0))
process.on('uncaughtException', (error) => {
  process.stderr.write('[ssh-mcp] fatal: ' + String(error?.stack ?? error) + '\n')
  void shutdown(1)
})
process.on('unhandledRejection', (error) => {
  process.stderr.write('[ssh-mcp] unhandled rejection: ' + String(error?.stack ?? error) + '\n')
})
