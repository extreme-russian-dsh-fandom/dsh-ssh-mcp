import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { CredentialsError, loadCredentials, publicProfiles, resolveProfile } from '../credentials.mjs'

function writeCredentials(document) {
  const directory = mkdtempSync(join(tmpdir(), 'ssh-mcp-'))
  const path = join(directory, 'ssh-credentials.json')
  writeFileSync(path, JSON.stringify(document))
  return path
}

test('a missing file is an empty catalogue, not a crash', () => {
  const loaded = loadCredentials(join(tmpdir(), 'definitely-missing-ssh-credentials.json'))
  assert.equal(loaded.exists, false)
  assert.deepEqual(loaded.hosts, {})
})

test('per-host port overrides the default', () => {
  const path = writeCredentials({
    defaults: { port: 22, user: 'root' },
    hosts: { custom: { host: 'h.example', port: 22222, user: 'deploy' } },
  })
  const profile = resolveProfile(loadCredentials(path), 'custom')
  assert.equal(profile.port, 22222)
  assert.equal(profile.user, 'deploy')
  assert.equal(profile.auth, 'agent')
})

test('auto auth picks key when identityFile is present', () => {
  const path = writeCredentials({ hosts: { k: { host: 'h', identityFile: 'C:\\keys\\id_ed25519' } } })
  assert.equal(resolveProfile(loadCredentials(path), 'k').auth, 'key')
})

test('password auth is refused with a clear code', () => {
  const path = writeCredentials({ hosts: { p: { host: 'h', passwordFile: 'pw.txt' } } })
  assert.throws(() => resolveProfile(loadCredentials(path), 'p'), (error) => {
    assert.equal(error instanceof CredentialsError, true)
    assert.equal(error.code, 'password_auth_unsupported')
    return true
  })
})

test('an invalid port is reported, not silently accepted', () => {
  const path = writeCredentials({ hosts: { bad: { host: 'h', port: 70000 } } })
  const loaded = loadCredentials(path)
  assert.match(loaded.error, /invalid "port"/)
  assert.equal(loaded.hosts.bad, undefined)
})

test('the public projection never exposes secrets', () => {
  const path = writeCredentials({ hosts: { k: { host: 'h', identityFile: 'C:\\keys\\id_ed25519' } } })
  const view = publicProfiles(loadCredentials(path))
  assert.equal(view.length, 1)
  assert.equal(JSON.stringify(view).includes('id_ed25519'), false)
  assert.equal(view[0].hasKeyFile, true)
})

test('a UTF-8 byte-order mark does not make the file look corrupt', () => {
  const directory = mkdtempSync(join(tmpdir(), 'ssh-mcp-bom-'))
  const path = join(directory, 'ssh-credentials.json')
  writeFileSync(path, '\uFEFF' + JSON.stringify({ hosts: { bom: { host: 'h.example' } } }))
  const loaded = loadCredentials(path)
  assert.equal(loaded.error, undefined)
  assert.equal(resolveProfile(loaded, 'bom').host, 'h.example')
})
