import { randomBytes } from 'node:crypto'

/**
 * Framing for the persistent shell. Each command runs inside `sh -c` and is
 * followed by a random marker line carrying the exit status, so output and
 * status always belong to exactly one command even though the session keeps
 * its working directory and environment.
 */

export function createMarker() {
  return '__DSH_SSH_END_' + randomBytes(8).toString('hex') + '__'
}

/** Builds the single line written to the remote shell's stdin. */
export function wrapCommand(command) {
  const marker = createMarker()
  const text = String(command ?? '').trim() === '' ? 'true' : String(command)
  const quoted = text.replace(/'/g, "'\\''")
  const payload = "sh -c '{ " + quoted + " ; } </dev/null 2>&1; printf \"\\n" + marker + "%s\\n\" \"$?\"'\n"
  return { marker, payload }
}

/**
 * Removes one completed result from the front of `buffer`. Returns done:false
 * while the marker line is still incomplete so the caller can keep buffering.
 */
export function takeResult(buffer, marker) {
  const index = buffer.indexOf(marker)
  if (index === -1) return { done: false, rest: buffer }
  const afterMarker = buffer.slice(index + marker.length)
  const newline = afterMarker.indexOf('\n')
  if (newline === -1) return { done: false, rest: buffer }

  const exitCode = Number.parseInt(afterMarker.slice(0, newline).trim(), 10)
  let output = buffer.slice(0, index)
  if (output.endsWith('\n')) output = output.slice(0, -1)
  return {
    done: true,
    output,
    exitCode: Number.isFinite(exitCode) ? exitCode : -1,
    rest: afterMarker.slice(newline + 1),
  }
}
