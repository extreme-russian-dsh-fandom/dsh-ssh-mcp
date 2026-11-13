import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { createToolset } from '../tools.mjs'

const HOST = Object.freeze({ host: 'example.test', port: 2222, user: 'deploy', fail2ban: 'present' })

function workspaceWith(document) {
  const workspace = mkdtempSync(join(tmpdir(), 'ssh-mcp-tools-'))
  const credentialsPath = join(workspace, 'ssh-credentials.json')
  if (document !== undefined) writeFileSync(credentialsPath, JSON.stringify(document))
  return { workspace, credentialsPath }
}

/** Every tool answers with one JSON text block; this unwraps it. */
function payload(result) {
  assert.equal(result.content.length, 1)
  assert.equal(result.content[0].type, 'text')
  return JSON.parse(result.content[0].text)
}

function fakeSessions({ uid = '1000', os = 'Linux', shell = '/bin/sh', openError } = {}) {
  const created = []
  const createSession = (id, alias, profile) => {
    const session = {
      id,
      alias,
      target: profile,
      closed: false,
      closeReason: null,
      opened: false,
      commands: [],
      async open() {
        if (openError !== undefined) throw openError
        this.opened = true
      },
      async exec(command) {
        this.commands.push(command)
        if (command === 'id -u') return { exitCode: 0, stdout: uid + '\n', stderr: '' }
        if (command.startsWith('uname')) return { exitCode: 0, stdout: os + '\n', stderr: '' }
        if (command.startsWith('printf')) return { exitCode: 0, stdout: shell, stderr: '' }
        return { exitCode: 0, stdout: 'ran: ' + command + '\n', stderr: '' }
      },
      async close(reason) {
        this.closed = true
        this.closeReason = reason
      },
    }
    created.push(session)
    return session
  }
  return { createSession, created }
}

/** Toolset with the network seams replaced by recorders. */
function build({ session, probe, ...overrides } = {}) {
  const { workspace, credentialsPath } = workspaceWith({ hosts: { prod: HOST } })
  const fake = fakeSessions(session)
  const transfers = []
  const sudoCalls = []
  const toolset = createToolset({
    workspace,
    credentialsPath,
    probe: probe ?? (async () => ({ ok: true })),
    createSession: fake.createSession,
    scpTransfer: async (options) => {
      transfers.push(options)
    },
    sudoExec: async (profile, command, timeoutMs) => {
      sudoCalls.push({ profile, command, timeoutMs })
      return { exitCode: 0, stdout: 'sudo: ' + command, stderr: '' }
    },
    ...overrides,
  })
  return { toolset, workspace, credentialsPath, transfers, sudoCalls, ...fake }
}

async function openSession(toolset) {
  const body = payload(await toolset.dispatch('open', { profile: 'prod' }))
  assert.equal(body.ok, true, JSON.stringify(body))
  return body
}

test('profiles lists credential profiles without exposing secrets', async () => {
  const { workspace, credentialsPath } = workspaceWith({
    hosts: { prod: { host: 'example.test', auth: 'key', identityFile: 'C:\\keys\\id_ed25519' } },
  })
  const { dispatch } = createToolset({ workspace, credentialsPath })
  const body = payload(await dispatch('profiles', {}))

  assert.equal(body.ok, true)
  assert.equal(body.credentials_path, credentialsPath)
  assert.equal(body.exists, true)
  assert.equal(body.profiles.length, 1)
  assert.equal(body.profiles[0].profile, 'prod')
  assert.equal(body.profiles[0].hasKeyFile, true)
  assert.equal(JSON.stringify(body).includes('id_ed25519'), false)
})

test('profiles returns the template when no credentials file exists', async () => {
  const { workspace, credentialsPath } = workspaceWith()
  const { dispatch } = createToolset({ workspace, credentialsPath })
  const body = payload(await dispatch('profiles', {}))

  assert.equal(body.ok, true)
  assert.equal(body.exists, false)
  assert.equal(body.profiles.length, 0)
  assert.equal(body.template.hosts.example.host, '203.0.113.10')
  assert.match(body.hint, /No credentials file yet/)
})

test('open starts a session and reports the detected user, OS and shell', async () => {
  const { toolset, created } = build({ session: { uid: '0', os: 'FreeBSD', shell: '/bin/csh' } })
  const body = await openSession(toolset)

  assert.match(body.session_id, /^ssh_[0-9a-f]{8}$/)
  assert.equal(body.profile, 'prod')
  assert.equal(body.host, 'example.test')
  assert.equal(body.port, 2222)
  assert.equal(body.user, 'deploy')
  assert.equal(body.is_root, true)
  assert.equal(body.os, 'FreeBSD')
  assert.equal(body.shell, '/bin/csh')
  assert.match(body.note, /login user is root/)
  assert.equal(created[0].opened, true)
  assert.deepEqual(created[0].commands, ['id -u', 'uname -s 2>/dev/null || echo unknown', 'printf %s "$SHELL"'])
})

test('open halts a host after the fail2ban attempt budget is spent', async () => {
  let probes = 0
  const { toolset } = build({
    probe: async () => {
      probes += 1
      return { ok: false, code: 'auth_failed', stderr: 'Permission denied (publickey).' }
    },
  })

  const first = payload(await toolset.dispatch('open', { profile: 'prod' }))
  assert.equal(first.ok, false)
  assert.equal(first.error.code, 'auth_failed')
  assert.equal(first.attempts.remaining, 1)

  const second = payload(await toolset.dispatch('open', { profile: 'prod' }))
  assert.equal(second.ok, false)
  assert.equal(second.attempts.remaining, 0)

  const halted = payload(await toolset.dispatch('open', { profile: 'prod' }))
  assert.equal(halted.ok, false)
  assert.equal(halted.error.code, 'connect_halted')
  assert.equal(halted.attempts.halted, true)
  assert.equal(probes, 2, 'a halted host must not be probed again')
})

test('exec runs a command in the open session and returns its exit code', async () => {
  const { toolset } = build()
  const opened = await openSession(toolset)

  const body = payload(await toolset.dispatch('exec', { session_id: opened.session_id, command: 'uptime' }))

  assert.equal(body.ok, true)
  assert.equal(body.session_id, opened.session_id)
  assert.equal(body.exit_code, 0)
  assert.equal(body.stdout, 'ran: uptime\n')
  assert.equal(body.truncated, false)
  const session = toolset.sessions.get(opened.session_id).session
  assert.deepEqual(session.commands.at(-1), 'uptime')
})

test('exec requires confirmation for a destructive command', async () => {
  const { toolset } = build()
  const opened = await openSession(toolset)

  const refused = payload(await toolset.dispatch('exec', { session_id: opened.session_id, command: 'rm -rf /' }))
  assert.equal(refused.ok, false)
  assert.equal(refused.confirmation_required, true)
  assert.equal(refused.error.code, 'confirmation_required')
  assert.equal(refused.command, 'rm -rf /')

  const session = toolset.sessions.get(opened.session_id).session
  assert.equal(session.commands.includes('rm -rf /'), false, 'an unconfirmed command must not reach the host')

  const approved = payload(await toolset.dispatch('exec', { session_id: opened.session_id, command: 'rm -rf /', confirmed: true }))
  assert.equal(approved.ok, true)
})

test('exec refuses sudo in a root session', async () => {
  const { toolset } = build({ session: { uid: '0' } })
  const opened = await openSession(toolset)
  assert.equal(opened.is_root, true)

  const body = payload(await toolset.dispatch('exec', {
    session_id: opened.session_id,
    command: 'id',
    sudo: true,
    confirmed: true,
  }))

  assert.equal(body.ok, false)
  assert.equal(body.error.code, 'sudo_not_applicable')
})

test('exec gates sudo behind confirmation and then uses the sudo channel', async () => {
  const { toolset, sudoCalls } = build()
  const opened = await openSession(toolset)
  assert.equal(opened.is_root, false)

  const pending = payload(await toolset.dispatch('exec', { session_id: opened.session_id, command: 'id', sudo: true }))
  assert.equal(pending.confirmation_required, true)
  assert.equal(sudoCalls.length, 0)

  const approved = payload(await toolset.dispatch('exec', {
    session_id: opened.session_id,
    command: 'id',
    sudo: true,
    confirmed: true,
  }))
  assert.equal(approved.ok, true)
  assert.equal(approved.stdout, 'sudo: id')
  assert.equal(sudoCalls.length, 1)
  assert.equal(sudoCalls[0].command, 'id')
})

test('exec reports an unknown session', async () => {
  const { toolset } = build()
  const body = payload(await toolset.dispatch('exec', { session_id: 'ssh_missing', command: 'true' }))

  assert.equal(body.ok, false)
  assert.equal(body.error.code, 'unknown_session')
})

test('exec truncates large output with an explicit marker', async () => {
  const { toolset } = build()
  const opened = await openSession(toolset)
  const session = toolset.sessions.get(opened.session_id).session
  session.exec = async () => ({ exitCode: 0, stdout: 'x'.repeat(200 * 1024), stderr: '' })

  const body = payload(await toolset.dispatch('exec', { session_id: opened.session_id, command: 'cat big.log' }))

  assert.equal(body.truncated, true)
  assert.match(body.stdout, /\.\.\.\[truncated \d+ bytes\]\.\.\./)
})

test('sessions lists the sessions opened by open', async () => {
  const { toolset } = build()
  const opened = await openSession(toolset)

  const body = payload(await toolset.dispatch('sessions', {}))

  assert.equal(body.ok, true)
  assert.equal(body.sessions.length, 1)
  assert.equal(body.sessions[0].session_id, opened.session_id)
  assert.equal(body.sessions[0].profile, 'prod')
  assert.equal(body.sessions[0].alive, true)
  assert.equal(typeof body.sessions[0].age_seconds, 'number')
})

test('close releases the session and forgets it', async () => {
  const { toolset, created } = build()
  const opened = await openSession(toolset)

  const closed = payload(await toolset.dispatch('close', { session_id: opened.session_id }))
  assert.equal(closed.ok, true)
  assert.equal(closed.closed, true)
  assert.equal(created[0].closed, true)
  assert.equal(created[0].closeReason, 'closed by client')
  assert.equal(payload(await toolset.dispatch('sessions', {})).sessions.length, 0)

  const again = payload(await toolset.dispatch('close', { session_id: opened.session_id }))
  assert.equal(again.ok, false)
  assert.equal(again.error.code, 'unknown_session')
})

test('put copies a local file to the remote host', async () => {
  const { toolset, workspace, transfers } = build()
  writeFileSync(join(workspace, 'payload.txt'), 'hello')

  const body = payload(await toolset.dispatch('put', {
    profile: 'prod',
    local_path: 'payload.txt',
    remote_path: '/srv/payload.txt',
  }))

  assert.equal(body.ok, true)
  assert.equal(body.direction, 'put')
  assert.equal(transfers.length, 1)
  assert.equal(transfers[0].direction, 'put')
  assert.equal(transfers[0].localPath, join(workspace, 'payload.txt'))
  assert.equal(transfers[0].remotePath, '/srv/payload.txt')
  assert.equal(transfers[0].target.alias, 'prod')
  assert.equal(transfers[0].recursive, false)
})

test('put rejects a missing local path without charging the attempt budget', async () => {
  const { toolset, transfers } = build()

  const body = payload(await toolset.dispatch('put', {
    profile: 'prod',
    local_path: 'missing.txt',
    remote_path: '/srv/missing.txt',
  }))

  assert.equal(body.ok, false)
  assert.equal(body.error.code, 'local_path_missing')
  assert.equal(transfers.length, 0)
  assert.equal(toolset.budget.snapshot('example.test:2222', 'present').remaining, 2)
})

test('get copies a remote file into the workspace', async () => {
  const { toolset, workspace, transfers } = build()

  const body = payload(await toolset.dispatch('get', {
    profile: 'prod',
    remote_path: '/srv/report.csv',
    local_path: 'report.csv',
  }))

  assert.equal(body.ok, true)
  assert.equal(body.direction, 'get')
  assert.equal(transfers.length, 1)
  assert.equal(transfers[0].direction, 'get')
  assert.equal(transfers[0].localPath, join(workspace, 'report.csv'))
  assert.equal(transfers[0].remotePath, '/srv/report.csv')
})

test('an unknown tool name is refused', async () => {
  const { toolset } = build()
  const body = payload(await toolset.dispatch('reload', {}))

  assert.equal(body.ok, false)
  assert.equal(body.error.code, 'unknown_tool')
})
