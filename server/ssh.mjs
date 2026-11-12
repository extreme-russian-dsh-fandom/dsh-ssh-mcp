import { spawn } from 'node:child_process'
import { StringDecoder } from 'node:string_decoder'

import { takeResult, wrapCommand } from './frame.mjs'

const STDERR_CAP = 64 * 1024
const PIPE_BUFFER_CAP = 8 * 1024 * 1024

export class SshError extends Error {
  constructor(code, message, details = {}) {
    super(message)
    this.name = 'SshError'
    this.code = code
    this.details = details
  }
}

/**
 * Maps process stderr to a stable error code. The `scp` variant is separate on
 * purpose: `stat local` and a missing path only exist in scp output, and both
 * mean the transfer never reached the network, so they must not be reported as
 * a connection failure.
 */
export function classifyStderr(text, { scp = false } = {}) {
  const value = String(text ?? '')
  if (/Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED/i.test(value)) return 'host_key_rejected'
  if (/Permission denied \(|no supported authentication methods|Authentication failed/i.test(value)) return 'auth_failed'
  if (/Connection refused/i.test(value)) return 'connection_refused'
  if (/Connection timed out|Operation timed out|No route to host|Network is unreachable/i.test(value)) return 'network_unreachable'
  if (/Could not resolve hostname|Name or service not known|nodename nor servname/i.test(value)) return 'dns_failed'
  if (/sudo: a password is required|a terminal is required|no tty present/i.test(value)) return 'sudo_requires_password'
  if (scp) {
    if (/\bstat local\b/i.test(value)) return 'local_path_missing'
    if (/No such file or directory|Not a directory|does not exist|not a regular file/i.test(value)) return 'path_missing'
  }
  return 'ssh_failed'
}

const SERVER_ALIVE_INTERVAL_S = 15
const SERVER_ALIVE_COUNT_MAX = 3

/**
 * Options shared by ssh and scp. The port flag differs: ssh takes `-p <port>`,
 * scp takes `-P <port>` — lowercase `-p` in scp means "preserve times" and
 * consumes no argument, which silently shifts every following operand by one.
 * Callers must therefore pass the flag explicitly; scp passes '-P'.
 */
export function connectionOptions(target, portFlag = '-p') {
  const options = [
    '-o', 'BatchMode=yes',
    '-o', 'ConnectTimeout=' + Math.max(1, Math.ceil((target.connectTimeoutMs ?? 15000) / 1000)),
    '-o', 'StrictHostKeyChecking=' + (target.strictHostKey ?? 'accept-new'),
    // Keepalives turn a silently dead connection into a prompt exit instead of
    // letting a persistent session or a transfer hang until its own timeout.
    '-o', 'ServerAliveInterval=' + String(SERVER_ALIVE_INTERVAL_S),
    '-o', 'ServerAliveCountMax=' + String(SERVER_ALIVE_COUNT_MAX),
    portFlag, String(target.port),
  ]
  if (target.identityFile !== undefined) {
    options.push('-i', target.identityFile)
    if (target.identityOnly !== false) options.push('-o', 'IdentitiesOnly=yes')
  }
  return options
}

function remoteSpec(target) {
  // scp splits its operand at the first colon, so an IPv6 literal must be
  // bracketed or the address is mistaken for a host:path pair.
  const host = target.host.includes(':') && !target.host.startsWith('[')
    ? '[' + target.host + ']'
    : target.host
  return target.user + '@' + host
}

/** One short-lived `ssh true` that proves reachability and authentication. */
export function probe(target, timeoutMs = 20000) {
  return new Promise((resolve) => {
    let stderr = ''
    let child
    try {
      child = spawn('ssh', [...connectionOptions(target), '-T', remoteSpec(target), 'true'], {
        windowsHide: true,
        stdio: ['ignore', 'ignore', 'pipe'],
      })
    } catch (error) {
      resolve({ ok: false, code: 'spawn_failed', stderr: String(error) })
      return
    }
    const timer = setTimeout(() => {
      child.kill()
      resolve({ ok: false, code: 'timeout', stderr: stderr.trim() })
    }, timeoutMs)
    child.stderr?.setEncoding('utf8')
    child.stderr?.on('data', (chunk) => {
      stderr = (stderr + chunk).slice(-STDERR_CAP)
    })
    child.on('error', (error) => {
      clearTimeout(timer)
      resolve({ ok: false, code: 'spawn_failed', stderr: String(error.message ?? error) })
    })
    child.on('close', (code) => {
      clearTimeout(timer)
      if (code === 0) resolve({ ok: true })
      else resolve({ ok: false, code: classifyStderr(stderr), stderr: stderr.trim() })
    })
  })
}

/**
 * One long-lived `ssh -T` shell. Commands are framed by a random marker, so
 * working directory and exported environment persist across calls while each
 * call still reports its own exit code and output.
 */
export class SshSession {
  constructor(id, alias, target) {
    this.id = id
    this.alias = alias
    this.target = target
    this.child = null
    this.decoder = new StringDecoder('utf8')
    this.buffer = ''
    this.stderrTail = ''
    this.pending = null
    this.queue = Promise.resolve()
    this.startupError = null
    this.closed = false
    this.closeReason = null
    this.openedAt = Date.now()
  }

  async open(timeoutMs = 25000) {
    try {
      this.child = spawn('ssh', [...connectionOptions(this.target), '-T', remoteSpec(this.target)], {
        windowsHide: true,
        stdio: ['pipe', 'pipe', 'pipe'],
      })
    } catch (error) {
      throw new SshError('spawn_failed', 'ssh could not start: ' + String(error.message ?? error))
    }
    this.child.stdout?.on('data', (chunk) => this.#onStdout(chunk))
    this.child.stderr?.setEncoding('utf8')
    this.child.stderr?.on('data', (chunk) => {
      this.stderrTail = (this.stderrTail + chunk).slice(-STDERR_CAP)
    })
    this.child.on('error', (error) => {
      this.startupError = new SshError('spawn_failed', 'ssh could not start: ' + String(error.message ?? error))
      this.#fail(this.startupError)
    })
    this.child.on('close', (code) => {
      this.#fail(new SshError(
        code === 0 ? 'session_closed' : classifyStderr(this.stderrTail),
        'SSH session closed (exit ' + String(code) + '): ' + this.stderrTail.trim(),
      ))
    })
    try {
      await this.exec('true', { timeoutMs })
    } catch (error) {
      throw this.startupError ?? error
    }
    return this
  }

  exec(command, { timeoutMs = 60000 } = {}) {
    const run = () => new Promise((resolve, reject) => {
      if (this.closed) {
        reject(this.startupError ?? new SshError('session_dead', 'SSH session "' + this.alias + '" is closed'))
        return
      }
      if (this.child === null || this.child.stdin === null || this.child.stdin === undefined) {
        reject(this.startupError ?? new SshError('spawn_failed', 'ssh did not provide a writable stdin'))
        return
      }
      const { marker, payload } = wrapCommand(command)
      const timer = setTimeout(() => {
        this.pending = null
        const error = new SshError('exec_timeout', 'Command exceeded ' + timeoutMs + ' ms; the session was closed because its output framing is out of sync')
        this.#fail(error)
        reject(error)
      }, timeoutMs)
      this.pending = { marker, resolve, reject, timer }
      this.child.stdin.write(payload, (error) => {
        if (error === null || error === undefined) return
        clearTimeout(timer)
        this.pending = null
        reject(new SshError('write_failed', 'Could not send the command: ' + error.message))
      })
    })
    const task = this.queue.then(run, run)
    this.queue = task.then(() => undefined, () => undefined)
    return task
  }

  async close(reason = 'closed by client') {
    if (this.closed) return
    this.closed = true
    this.closeReason = reason
    if (this.pending !== null && this.pending !== undefined) {
      clearTimeout(this.pending.timer)
      this.pending.reject(new SshError('session_closed', reason))
      this.pending = null
    }
    if (this.child === null) return
    try {
      this.child.stdin.write('exit\n')
    } catch {
      // The pipe may already be gone; the kill below settles the process.
    }
    await new Promise((resolve) => {
      const timer = setTimeout(() => {
        try { this.child.kill() } catch { /* already gone */ }
        resolve()
      }, 1500)
      this.child.once('close', () => {
        clearTimeout(timer)
        resolve()
      })
      if (this.child.exitCode !== null) {
        clearTimeout(timer)
        resolve()
      }
    })
  }

  #onStdout(chunk) {
    this.buffer += this.decoder.write(chunk)
    const pending = this.pending
    if (pending === null || pending === undefined) {
      if (this.buffer.length > PIPE_BUFFER_CAP) this.buffer = this.buffer.slice(-PIPE_BUFFER_CAP)
      return
    }
    const result = takeResult(this.buffer, pending.marker)
    if (!result.done) return
    this.buffer = result.rest
    this.pending = null
    clearTimeout(pending.timer)
    pending.resolve({ exitCode: result.exitCode, stdout: result.output, stderr: '' })
  }

  #fail(error) {
    if (!this.closed) {
      this.closed = true
      this.closeReason = error.message
    }
    const pending = this.pending
    if (pending !== null && pending !== undefined) {
      this.pending = null
      clearTimeout(pending.timer)
      pending.reject(error)
    }
  }
}

/** sudo is a separate one-shot channel: no TTY, so only passwordless sudo can work. */
export function sudoExec(target, command, timeoutMs = 60000) {
  return new Promise((resolve, reject) => {
    let stdout = ''
    let stderr = ''
    let settled = false
    let child
    try {
      child = spawn('ssh', [...connectionOptions(target), '-T', remoteSpec(target), 'sudo', '-n', '--', 'sh', '-s'], {
        windowsHide: true,
        stdio: ['pipe', 'pipe', 'pipe'],
      })
    } catch (error) {
      reject(new SshError('spawn_failed', 'ssh could not start: ' + String(error.message ?? error)))
      return
    }
    const finish = (error, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (error !== undefined) reject(error)
      else resolve(value)
    }
    const timer = setTimeout(() => {
      try { child.kill() } catch { /* already gone */ }
      finish(new SshError('exec_timeout', 'sudo command exceeded ' + timeoutMs + ' ms'))
    }, timeoutMs)
    child.stdout?.setEncoding('utf8')
    child.stderr?.setEncoding('utf8')
    child.stdout?.on('data', (chunk) => {
      stdout += chunk
    })
    child.stderr?.on('data', (chunk) => {
      stderr = (stderr + chunk).slice(-STDERR_CAP)
    })
    child.on('error', (error) => finish(new SshError('spawn_failed', String(error.message ?? error))))
    child.on('close', (code) => {
      if (/sudo: a password is required|a terminal is required|no tty present/i.test(stderr)) {
        finish(new SshError('sudo_requires_password', 'sudo needs a password or a terminal on the remote host; ask the user to configure passwordless sudo for this command or to run it manually'))
        return
      }
      if (code !== 0 && /^sudo: /m.test(stderr) && stdout === '') {
        finish(new SshError('sudo_failed', stderr.trim()))
        return
      }
      finish(undefined, { exitCode: code ?? -1, stdout, stderr })
    })
    child.stdin?.end(String(command ?? '') + '\n')
  })
}

/**
 * Builds the full scp argument vector. Kept separate from the spawn so the
 * exact argv can be asserted in tests: scp must receive `-P <port>`, never
 * ssh's `-p <port>`, and `--` keeps a local path that begins with `-` from
 * being read as an option.
 */
export function scpArgs({ target, direction, localPath, remotePath, recursive = false }) {
  if (direction !== 'put' && direction !== 'get') {
    throw new SshError('invalid_argument', 'Transfer direction must be "put" or "get"')
  }
  if (typeof localPath !== 'string' || localPath === '') {
    throw new SshError('invalid_argument', 'A local path is required')
  }
  if (typeof remotePath !== 'string' || remotePath === '') {
    throw new SshError('invalid_argument', 'A remote path is required')
  }
  const destination = remoteSpec(target) + ':' + remotePath
  const source = direction === 'put' ? localPath : destination
  const sink = direction === 'put' ? destination : localPath
  const args = ['-q', ...connectionOptions(target, '-P')]
  if (recursive) args.push('-r')
  args.push('--', source, sink)
  return args
}

/** Copies one path with scp. Direction is 'put' (local to remote) or 'get'. */
export function scpTransfer({ target, direction, localPath, remotePath, recursive = false, timeoutMs = 120000 }) {
  return new Promise((resolve, reject) => {
    const args = scpArgs({ target, direction, localPath, remotePath, recursive })
    let stderr = ''
    let settled = false
    let timer
    let child
    const finish = (error, value) => {
      if (settled) return
      settled = true
      if (timer !== undefined) clearTimeout(timer)
      if (error !== undefined) reject(error)
      else resolve(value)
    }
    try {
      child = spawn('scp', args, { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] })
    } catch (error) {
      finish(new SshError('spawn_failed', 'scp could not start: ' + String(error.message ?? error)))
      return
    }
    timer = setTimeout(() => {
      try { child.kill() } catch { /* already gone */ }
      finish(new SshError('transfer_timeout', 'Transfer exceeded ' + timeoutMs + ' ms'))
    }, timeoutMs)
    child.stderr?.setEncoding('utf8')
    child.stderr?.on('data', (chunk) => {
      stderr = (stderr + chunk).slice(-STDERR_CAP)
    })
    child.on('error', (error) => {
      finish(new SshError('spawn_failed', 'scp could not start: ' + String(error.message ?? error)))
    })
    child.on('close', (code) => {
      if (code === 0) {
        finish(undefined, { bytesHint: null })
        return
      }
      const classified = classifyStderr(stderr, { scp: true })
      finish(new SshError(classified, 'scp failed (exit ' + String(code) + '): ' + stderr.trim().slice(-2000)))
    })
  })
}
