import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'

const SERVER = fileURLToPath(new URL('../index.mjs', import.meta.url))

/** One stdio run: write every request, close stdin, collect the replies. */
function exchange(workspace, requests) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [
      SERVER,
      '--workspace', workspace,
      '--credentials', join(workspace, 'ssh-credentials.json'),
    ], {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    })
    let stdout = ''
    let stderr = ''
    const timer = setTimeout(() => {
      child.kill()
      reject(new Error('server did not exit; stderr: ' + stderr))
    }, 15000)
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    child.stdout.on('data', (chunk) => {
      stdout += chunk
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk
    })
    child.on('error', (error) => {
      clearTimeout(timer)
      reject(error)
    })
    child.on('close', (code) => {
      clearTimeout(timer)
      resolve({ code, stdout, stderr })
    })
    child.stdin.end(requests.map((request) => JSON.stringify(request)).join('\n') + '\n')
  })
}

test('the stdio server answers initialize and tools/call with annotated tools', async (t) => {
  const workspace = mkdtempSync(join(tmpdir(), 'ssh-mcp-stdio-'))
  let result
  try {
    result = await exchange(workspace, [
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1.0.0' } } },
      { jsonrpc: '2.0', id: 2, method: 'tools/list' },
      { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'profiles', arguments: {} } },
      { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'sessions', arguments: {} } },
      { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'exec', arguments: { session_id: 'ssh_missing', command: 'true' } } },
    ])
  } catch (error) {
    // The DSH Windows sandbox denies child processes with piped stdio. The
    // protocol itself is covered in-process by rpc.test.mjs; here the real
    // stdio handshake is the extra check, so skip only when spawning is denied.
    if (error.code === 'EPERM' || error.code === 'EACCES' || error.code === 'ENOENT') {
      t.skip('this environment cannot spawn a child process (' + error.code + ')')
      return
    }
    throw error
  }
  const { code, stdout, stderr } = result
  assert.equal(code, 0, stderr)

  const replies = new Map()
  for (const line of stdout.trim().split('\n')) {
    const message = JSON.parse(line)
    assert.equal(message.jsonrpc, '2.0')
    replies.set(message.id, message)
  }

  const init = replies.get(1).result
  assert.equal(init.protocolVersion, '2025-06-18')
  assert.equal(init.serverInfo.name, 'ssh-mcp')
  assert.match(init.instructions, /fail2ban/)

  const tools = replies.get(2).result.tools
  assert.equal(tools.length, 7)
  assert.deepEqual(
    tools.map((tool) => tool.name).sort(),
    ['close', 'exec', 'get', 'open', 'profiles', 'put', 'sessions'],
  )
  for (const tool of tools) {
    for (const hint of ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint']) {
      assert.equal(typeof tool.annotations[hint], 'boolean', tool.name + ' lost ' + hint + ' on the wire')
    }
  }

  const profiles = JSON.parse(replies.get(3).result.content[0].text)
  assert.equal(profiles.ok, true)
  assert.equal(profiles.exists, false)
  assert.ok(profiles.template !== undefined)

  const sessions = JSON.parse(replies.get(4).result.content[0].text)
  assert.equal(sessions.ok, true)
  assert.deepEqual(sessions.sessions, [])

  const exec = JSON.parse(replies.get(5).result.content[0].text)
  assert.equal(exec.ok, false)
  assert.equal(exec.error.code, 'unknown_session')
})
