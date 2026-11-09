import assert from 'node:assert/strict'
import { test } from 'node:test'

import { createMarker, takeResult, wrapCommand } from '../frame.mjs'

test('a complete frame yields output, exit code and the remainder', () => {
  const marker = createMarker()
  const result = takeResult('hello\nworld\n' + marker + '0\nleftover', marker)
  assert.equal(result.done, true)
  assert.equal(result.output, 'hello\nworld')
  assert.equal(result.exitCode, 0)
  assert.equal(result.rest, 'leftover')
})

test('a non-zero exit code is preserved', () => {
  const marker = createMarker()
  assert.equal(takeResult('boom\n' + marker + '127\n', marker).exitCode, 127)
})

test('an incomplete frame is not consumed', () => {
  const marker = createMarker()
  const partial = 'partial output\n' + marker + '0'
  const result = takeResult(partial, marker)
  assert.equal(result.done, false)
  assert.equal(result.rest, partial)
})

test('the trailing newline before the marker is not part of the output', () => {
  const marker = createMarker()
  assert.equal(takeResult(marker + '0\n', marker).output, '')
})

test('commands are single-quote escaped for the remote shell', () => {
  const { payload, marker } = wrapCommand("echo 'quoted' && exit 0")
  assert.ok(payload.includes("'\\''"))
  assert.ok(payload.includes(marker))
  assert.ok(payload.startsWith('sh -c '))
  assert.ok(payload.endsWith('\n'))
})

test('an empty command becomes a no-op instead of a syntax error', () => {
  const { payload } = wrapCommand('   ')
  assert.ok(payload.includes('true'))
})

test('multi-line commands stay inside one frame', () => {
  const { payload, marker } = wrapCommand('cd /tmp\npwd')
  assert.ok(payload.includes('cd /tmp\npwd'))
  const lines = payload.trimEnd().split('\n')
  assert.equal(lines.length, 2)
  assert.ok(lines[1].includes(marker))
})
