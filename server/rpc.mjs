/**
 * JSON-RPC transport for the MCP server. Kept separate from `index.mjs` so the
 * protocol envelope can be tested without a child process: the handler receives
 * the tool catalogue and the dispatch function, and reports when the input is
 * closed and no call is in flight.
 */

export const PROTOCOL_FALLBACK = '2025-06-18'

export function createRpcHandler({
  dispatch,
  tools,
  serverInfo,
  instructions,
  send,
  onDrained = () => {},
}) {
  let inflight = 0
  let closing = false
  let drained = false

  function maybeDrain() {
    if (closing && inflight === 0 && !drained) {
      drained = true
      onDrained()
    }
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
          serverInfo,
          instructions,
        },
      })
      return
    }
    if (method === 'ping') {
      if (isRequest) send({ jsonrpc: '2.0', id, result: {} })
      return
    }
    if (method === 'tools/list') {
      send({ jsonrpc: '2.0', id, result: { tools } })
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
        maybeDrain()
      }
      return
    }
    if (!isRequest) return
    send({ jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found: ' + String(method) } })
  }

  return {
    handleLine,
    /** Called when stdin ended: drain in-flight calls, then report once. */
    markInputClosed() {
      closing = true
      maybeDrain()
    },
    get inflight() {
      return inflight
    },
  }
}
