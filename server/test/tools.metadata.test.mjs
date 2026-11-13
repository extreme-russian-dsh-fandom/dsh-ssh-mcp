import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { SERVER_INFO, TOOLS } from '../tools.mjs'

// The exact hints M8ven and OpenAI-style directories expect. Any drift here
// must be a deliberate edit of both the table and the tool definition.
const EXPECTED = {
  profiles: [true, false, true, false],
  open: [false, false, false, true],
  exec: [false, true, false, true],
  sessions: [true, false, true, false],
  close: [false, false, true, false],
  put: [false, true, true, true],
  get: [false, true, true, true],
}

const HINTS = ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint']

test('every tool declares all four MCP annotations as explicit booleans', () => {
  assert.equal(TOOLS.length, 7)
  assert.deepEqual(TOOLS.map((tool) => tool.name).sort(), Object.keys(EXPECTED).sort())

  for (const tool of TOOLS) {
    assert.equal(typeof tool.title, 'string', tool.name + ' has no title')
    assert.ok(tool.title.length > 0, tool.name + ' has an empty title')
    assert.equal(typeof tool.description, 'string', tool.name + ' has no description')
    assert.ok(tool.description.length > 40, tool.name + ' description is too short')
    assert.ok(tool.annotations !== null && typeof tool.annotations === 'object', tool.name + ' has no annotations')
    assert.equal(tool.annotations.title, tool.title)

    for (const hint of HINTS) {
      assert.equal(typeof tool.annotations[hint], 'boolean', tool.name + ' needs a boolean ' + hint)
    }
    assert.deepEqual(
      HINTS.map((hint) => tool.annotations[hint]),
      EXPECTED[tool.name],
      tool.name + ' annotations changed without updating the expectation',
    )
  }
})

test('every tool has a closed object input schema', () => {
  for (const tool of TOOLS) {
    assert.equal(tool.inputSchema.type, 'object', tool.name)
    assert.equal(tool.inputSchema.additionalProperties, false, tool.name)
    assert.equal(typeof tool.inputSchema.properties, 'object', tool.name)
    assert.ok(Array.isArray(tool.inputSchema.required) || tool.inputSchema.required === undefined, tool.name)
  }
})

test('the server advertises the package version', () => {
  const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'))
  assert.equal(SERVER_INFO.version, pkg.version)
})
