import assert from 'node:assert/strict'
import { test } from 'node:test'

import { createRpcHandler } from '../rpc.mjs'
import { INSTRUCTIONS, SERVER_INFO, TOOLS } from '../tools.mjs'

function handlerWith(dispatch, { onDrained = () => {} } = {}) {
  const sent = []
  const handler = createRpcHandler({
    dispatch,
    tools: TOOLS,
    serverInfo: SERVER_INFO,
    instructions: INSTRUCTIONS,
    send: (message) => {
      sent.push(message)
    },
    onDrained,
  })
  return { handler, sent }
}

function line(message) {
  return JSON.stringify(message)
}

test('initialize echoes the requested protocol and advertises the tools capability', async () => {
  const { handler, sent } = handlerWith(async () => assert.fail('no tool must run'))
  await handler.handleLine(line({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1.0.0' } },
  }))

  assert.equal(sent.length, 1)
  assert.equal(sent[0].jsonrpc, '2.0')
  assert.equal(sent[0].id, 1)
  assert.equal(sent[0].result.protocolVersion, '2025-06-18')
  assert.deepEqual(sent[0].result.capabilities, { tools: { listChanged: false } })
  assert.deepEqual(sent[0].result.serverInfo, SERVER_INFO)
  assert.equal(sent[0].result.instructions, INSTRUCTIONS)
})

test('tools/list returns the complete annotated catalogue', async () => {
  const { handler, sent } = handlerWith(async () => assert.fail('no tool must run'))
  await handler.handleLine(line({ jsonrpc: '2.0', id: 2, method: 'tools/list' }))

  assert.deepEqual(sent[0].result.tools, TOOLS)
  for (const tool of sent[0].result.tools) {
    for (const hint of ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint']) {
      assert.equal(typeof tool.annotations[hint], 'boolean', tool.name + ' lost ' + hint)
    }
  }
})

test('tools/call dispatches every advertised tool by name', async () => {
  const calls = []
  const { handler, sent } = handlerWith(async (name, args) => {
    calls.push(name)
    return { content: [{ type: 'text', text: JSON.stringify({ ok: true, name, args }) }] }
  })

  const names = ['profiles', 'open', 'exec', 'sessions', 'close', 'put', 'get']
  for (const [index, name] of names.entries()) {
    await handler.handleLine(line({
      jsonrpc: '2.0',
      id: index + 1,
      method: 'tools/call',
      params: { name, arguments: { step: index } },
    }))
  }

  assert.deepEqual(calls, names)
  assert.equal(sent.length, names.length)
  for (const [index, name] of names.entries()) {
    assert.equal(sent[index].id, index + 1)
    const body = JSON.parse(sent[index].result.content[0].text)
    assert.equal(body.name, name)
    assert.deepEqual(body.args, { step: index })
  }
})

test('tools/call wraps a handler crash as an internal error result', async () => {
  const { handler, sent } = handlerWith(async () => {
    throw new Error('boom')
  })
  await handler.handleLine(line({
    jsonrpc: '2.0',
    id: 7,
    method: 'tools/call',
    params: { name: 'exec', arguments: {} },
  }))

  assert.equal(sent[0].result.isError, true)
  assert.equal(JSON.parse(sent[0].result.content[0].text).error.code, 'internal_error')
})

test('a closed input drains an in-flight tool call before shutting down', async () => {
  let release
  const gate = new Promise((resolve) => {
    release = resolve
  })
  let drained = 0
  const { handler, sent } = handlerWith(() => gate.then(() => ({ content: [] })), {
    onDrained: () => {
      drained += 1
    },
  })

  const pending = handler.handleLine(line({
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: { name: 'exec', arguments: { session_id: 'ssh_x', command: 'true' } },
  }))
  assert.equal(handler.inflight, 1)

  handler.markInputClosed()
  assert.equal(drained, 0, 'shutdown must wait for the running call')

  release()
  await pending
  assert.equal(sent.length, 1)
  assert.equal(drained, 1)

  handler.markInputClosed()
  assert.equal(drained, 1, 'drain is reported only once')
})

test('malformed JSON is a parse error, not a crash', async () => {
  const { handler, sent } = handlerWith(async () => assert.fail('no tool must run'))
  await handler.handleLine('{not json')
  await handler.handleLine('   ')

  assert.equal(sent.length, 1)
  assert.deepEqual(sent[0], { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } })
})

test('an unknown request method is answered, an unknown notification is ignored', async () => {
  const { handler, sent } = handlerWith(async () => assert.fail('no tool must run'))

  await handler.handleLine(line({ jsonrpc: '2.0', id: 8, method: 'unknown/method' }))
  assert.equal(sent.length, 1)
  assert.equal(sent[0].error.code, -32601)

  await handler.handleLine(line({ jsonrpc: '2.0', method: 'unknown/notification' }))
  assert.equal(sent.length, 1)

  await handler.handleLine(line({ jsonrpc: '2.0', id: 9, method: 'ping' }))
  assert.deepEqual(sent.at(-1), { jsonrpc: '2.0', id: 9, result: {} })
})
