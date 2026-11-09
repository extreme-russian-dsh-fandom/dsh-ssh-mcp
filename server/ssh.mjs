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

export function classifyStderr(text) {
  const value = String(text ?? '')
  if (/Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED/i.test(value)) return 'host_key_rejected'
  if (/Permission denied \(|no supported authentication methods|Authentication failed/i.test(value)) return 'auth_failed'
  if (/Connection refused/i.test(value)) return 'connection_refused'
  if (/Connection timed out|Operation timed out|No route to host|Network is unreachable/i.test(value)) return 'network_unreachable'
  if (/Could not resolve hostname|Name or service not known|nodename nor servname/i.test(value)) return 'dns_failed'
  if (/sudo: a password is required|a terminal is required|no tty present/i.test(value)) return 'sudo_requires_password'
  return 'ssh_failed'
}

function connectionOptions(target) {
  const options = [
    '-o', 'BatchMode=yes',
    '-o', 'ConnectTimeout=' + Math.max(1, Math.ceil((target.connectTimeoutMs ?? 15000) / 1000)),
    '-o', 'StrictHostKeyChecking=' + (target.strictHostKey ?? 'accept-new'),
    '-p', String(target.port),
  ]
  if (target.identityFile !== undefined) {
    options.push('-i', target.identityFile)
    if (target.identityOnly !== false) options.push('-o', 'IdentitiesOnly=yes')
  }
  return options
}

function remoteSpec(target) {
  return target.user + '@' + target.host
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
    child.stderr.setEncoding('utf8')
    child.stderr.on('data', (chunk) => {
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
    this.closed = false
    this.closeReason = null
    this.openedAt = Date.now()
  }

  async open(timeoutMs = 25000) {
    this.child = spawn('ssh', [...connectionOptions(this.target), '-T', remoteSpec(this.target)], {
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    this.child.stdout.on('data', (chunk) => this.#onStdout(chunk))
    this.child.stderr.setEncoding('utf8')
    this.child.stderr.on('data', (chunk) => {
      this.stderrTail = (this.stderrTail + chunk).slice(-STDERR_CAP)
    })
    this.child.on('error', (error) => {
      this.#fail(new SshError('spawn_failed', 'ssh could not start: ' + String(error.message ?? error)))
    })
    this.child.on('close', (code) => {
      this.#fail(new SshError(
        code === 0 ? 'session_closed' : classifyStderr(this.stderrTail),
        'SSH session closed (exit ' + String(code) + '): ' + this.stderrTail.trim(),
      ))
    })
    await this.exec('true', { timeoutMs })
    return this
  }

  exec(command, { timeoutMs = 60000 } = {}) {
    const run = () => new Promise((resolve, reject) => {
      if (this.closed) {
        reject(new SshError('session_dead', 'SSH session "' + this.alias + '" is closed'))
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
    const child = spawn('ssh', [...connectionOptions(target), '-T', remoteSpec(target), 'sudo', '-n', '--', 'sh', '-s'], {
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    })
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
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    child.stdout.on('data', (chunk) => {
      stdout += chunk
    })
    child.stderr.on('data', (chunk) => {
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
    child.stdin.end(String(command ?? '') + '\n')
  })
}

/** Copies one path with scp. Direction is 'put' (local to remote) or 'get'. */
export function scpTransfer({ target, direction, localPath, remotePath, recursive = false, timeoutMs = 120000 }) {
  return new Promise((resolve, reject) => {
    const destination = remoteSpec(target) + ':' + remotePath
    const source = direction === 'put' ? localPath : destination
    const sink = direction === 'put' ? destination : localPath
    const args = ['-q', ...connectionOptions(target)]
    if (recursive) args.push('-r')
    args.push(source, sink)
    let stderr = ''
    let settled = false
    const child = spawn('scp', args, { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] })
    const finish = (error, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (error !== undefined) reject(error)
      else resolve(value)
    }
    const timer = setTimeout(() => {
      try { child.kill() } catch { /* already gone */ }
      finish(new SshError('transfer_timeout', 'Transfer exceeded ' + timeoutMs + ' ms'))
    }, timeoutMs)
    child.stderr.setEncoding('utf8')
    child.stderr.on('data', (chunk) => {
      stderr = (stderr + chunk).slice(-STDERR_CAP)
    })
    child.on('error', (error) => finish(new SshError('spawn_failed', 'scp could not start: ' + String(error.message ?? error))))
    child.on('close', (code) => {
      if (code === 0) {
        finish(undefined, { bytesHint: null })
        return
      }
      const classified = classifyStderr(stderr)
      finish(new SshError(classified, 'scp failed (exit ' + String(code) + '): ' + stderr.trim()))
    })
  })
}
