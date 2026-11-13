#!/usr/bin/env node
import { createInterface } from 'node:readline'
import { existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { isAbsolute, join, resolve } from 'node:path'

import { createRpcHandler } from './rpc.mjs'
import { INSTRUCTIONS, SERVER_INFO, TOOLS, createToolset } from './tools.mjs'

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
const { dispatch, sessions } = createToolset({ workspace, credentialsPath })

let down = false

async function shutdown(exitCode = 0) {
  if (down) return
  down = true
  await Promise.allSettled([...sessions.values()].map((entry) => entry.session.close('harness shutting down')))
  sessions.clear()
  process.exit(exitCode)
}

const handler = createRpcHandler({
  dispatch,
  tools: TOOLS,
  serverInfo: SERVER_INFO,
  instructions: INSTRUCTIONS,
  send(message) {
    process.stdout.write(JSON.stringify(message) + '\n')
  },
  onDrained() {
    void shutdown(0)
  },
})

const reader = createInterface({ input: process.stdin, crlfDelay: Infinity })
reader.on('line', (line) => {
  void handler.handleLine(line)
})
reader.on('close', () => {
  handler.markInputClosed()
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
