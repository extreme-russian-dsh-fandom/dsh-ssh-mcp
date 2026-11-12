import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { test } from 'node:test'

import { classifyStderr, connectionOptions, scpArgs, scpTransfer, SshError } from '../ssh.mjs'

const TARGET = Object.freeze({
  alias: 'test',
  host: 'example.invalid',
  port: 7022,
  user: 'root',
  connectTimeoutMs: 1000,
  strictHostKey: 'accept-new',
})

const LOCAL_PATH = 'C:\\tmp\\payload.png'
const REMOTE_PATH = '/tmp/payload.png'

test('ssh gets lowercase -p <port>', () => {
  const args = connectionOptions(TARGET)
  assert.equal(args[args.indexOf('-p') + 1], '7022')
  assert.equal(args.includes('-P'), false)
})

test('scp gets uppercase -P <port>, never ssh\'s lowercase -p', () => {
  // Regression: `scp -p 7022 file host:/x` parses -p as a boolean and turns the
  // port into the source operand, so scp fails with `stat local "7022"`.
  const args = scpArgs({ target: TARGET, direction: 'put', localPath: LOCAL_PATH, remotePath: REMOTE_PATH })
  assert.ok(args.includes('-P'))
  assert.equal(args[args.indexOf('-P') + 1], '7022')
  assert.equal(args.includes('-p'), false)
})

test('scp operands follow -- so a path may begin with a dash', () => {
  const args = scpArgs({ target: TARGET, direction: 'put', localPath: '-payload.png', remotePath: REMOTE_PATH })
  assert.deepEqual(args.slice(-3), ['--', '-payload.png', 'root@example.invalid:' + REMOTE_PATH])
  assert.ok(args.indexOf('--') > args.indexOf('-P'))
})

test('get swaps source and sink but keeps the remote spec intact', () => {
  const args = scpArgs({ target: TARGET, direction: 'get', localPath: LOCAL_PATH, remotePath: REMOTE_PATH })
  assert.deepEqual(args.slice(-3), ['--', 'root@example.invalid:' + REMOTE_PATH, LOCAL_PATH])
  assert.equal(args[args.indexOf('-P') + 1], '7022')
})

test('recursive mode passes -r as an option, before the operands', () => {
  const args = scpArgs({ target: TARGET, direction: 'put', localPath: LOCAL_PATH, remotePath: REMOTE_PATH, recursive: true })
  assert.ok(args.includes('-r'))
  assert.ok(args.indexOf('-r') < args.indexOf('--'))
})

test('key auth adds -i and IdentitiesOnly for both ssh and scp', () => {
  const profile = { ...TARGET, identityFile: 'C:\\keys\\id_ed25519', identityOnly: true }
  for (const args of [connectionOptions(profile), scpArgs({ target: profile, direction: 'put', localPath: LOCAL_PATH, remotePath: REMOTE_PATH })]) {
    assert.equal(args[args.indexOf('-i') + 1], 'C:\\keys\\id_ed25519')
    assert.ok(args.includes('IdentitiesOnly=yes'))
  }
})

test('keepalives are enabled so a dead connection ends instead of hanging', () => {
  const args = connectionOptions(TARGET)
  assert.ok(args.includes('ServerAliveInterval=15'))
  assert.ok(args.includes('ServerAliveCountMax=3'))
})

test('an IPv6 host is bracketed so scp does not split it at a colon', () => {
  const ipv6 = { ...TARGET, host: '2001:db8::10' }
  const args = scpArgs({ target: ipv6, direction: 'put', localPath: LOCAL_PATH, remotePath: REMOTE_PATH })
  assert.equal(args.at(-1), 'root@[2001:db8::10]:' + REMOTE_PATH)
  const bracketed = scpArgs({ target: { ...TARGET, host: '[2001:db8::10]' }, direction: 'put', localPath: LOCAL_PATH, remotePath: REMOTE_PATH })
  assert.equal(bracketed.at(-1), 'root@[2001:db8::10]:' + REMOTE_PATH)
})

test('an empty operand is rejected before scp is spawned', () => {
  assert.throws(
    () => scpArgs({ target: TARGET, direction: 'put', localPath: '', remotePath: REMOTE_PATH }),
    (error) => error instanceof SshError && error.code === 'invalid_argument',
  )
  assert.throws(
    () => scpArgs({ target: TARGET, direction: 'get', localPath: LOCAL_PATH, remotePath: '' }),
    (error) => error instanceof SshError && error.code === 'invalid_argument',
  )
})

test('scp-only stderr is classified as a local or path failure', () => {
  assert.equal(classifyStderr('scp: stat local "7022": No such file or directory', { scp: true }), 'local_path_missing')
  assert.equal(classifyStderr('scp: /var/log/missing: No such file or directory', { scp: true }), 'path_missing')
  assert.equal(classifyStderr('scp: /var/log: not a regular file', { scp: true }), 'path_missing')
  assert.equal(classifyStderr('scp: stat local "7022": No such file or directory'), 'ssh_failed')
})

test('connection failures keep their specific codes', () => {
  assert.equal(classifyStderr('Permission denied (publickey).'), 'auth_failed')
  assert.equal(classifyStderr('ssh: connect to host h port 22: Connection refused'), 'connection_refused')
  assert.equal(classifyStderr('ssh: Could not resolve hostname h'), 'dns_failed')
  assert.equal(classifyStderr('Host key verification failed.'), 'host_key_rejected')
})

function scpIsAvailable() {
  const probe = spawnSync('scp', ['--'], { encoding: 'utf8', timeout: 5000 })
  return probe.error === undefined
}

test('scpTransfer reports a missing local source as a local failure, not a connection failure', async (t) => {
  if (!scpIsAvailable()) {
    t.skip('OpenSSH scp cannot be spawned in this environment')
    return
  }
  const localPath = join(tmpdir(), 'dsh-ssh-mcp-missing-' + randomBytes(4).toString('hex') + '.png')
  await assert.rejects(
    scpTransfer({ target: TARGET, direction: 'put', localPath, remotePath: REMOTE_PATH }),
    (error) => {
      assert.equal(error instanceof SshError, true)
      assert.equal(error.code, 'local_path_missing', 'stderr was: ' + error.message)
      // The port must not appear as an operand; with the old argv scp read it
      // as the source file and said `stat local "7022"`.
      assert.doesNotMatch(error.message, /stat local "7022"/)
      assert.match(error.message, /dsh-ssh-mcp-missing-/)
      return true
    },
  )
})
