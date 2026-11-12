/**
 * Connection-attempt budget. A remote host may run fail2ban, so failures are
 * counted per host:port and never reset by simply asking again. One retry is
 * allowed by default; only a profile that explicitly declares
 * `"fail2ban": "absent"` gets a third attempt.
 */

const MAX_ATTEMPTS_DEFAULT = 2
const MAX_ATTEMPTS_NO_FAIL2BAN = 3

/**
 * Failure codes that do not prove the host rejected a connection: a bad local
 * path, a missing scp/ssh binary, a rejected argument, or our own transfer
 * deadline expiring after the connection already worked. Charging them to the
 * per-host budget would halt a host that is perfectly reachable, so they are
 * deliberately free.
 */
const FREE_FAILURE_CODES = new Set(['spawn_failed', 'local_path_missing', 'path_missing', 'invalid_argument', 'transfer_timeout'])

/** Whether a failure code counts as a connection attempt against fail2ban. */
export function chargesBudget(code) {
  return !FREE_FAILURE_CODES.has(String(code ?? 'ssh_failed'))
}

/**
 * Human hint for an error code. The code that actually spent the budget must be
 * passed in: describing a refused connection as a rejected key sends the agent
 * and the user to repair credentials that were never broken.
 */
export function failureHint(code, remaining = 0) {
  const base = remaining > 0
    ? 'One retry is allowed. Do not try other users, keys or ports.'
    : 'No attempts left for this host. Stop here and ask the user to repair SSH connectivity (port, keys, fail2ban, network) before continuing.'
  switch (code) {
    case 'auth_failed':
      return 'The remote host rejected authentication. ' + base + ' The user must add the public key to authorized_keys or fix the ssh-agent.'
    case 'connection_refused':
      return 'Nothing accepted the connection on this host and port. ' + base + ' The port may be wrong or sshd may be listening elsewhere.'
    case 'network_unreachable':
    case 'timeout':
      return 'The host did not answer in time. ' + base + ' Check the address, port, firewall and network path.'
    case 'dns_failed':
      return 'The host name did not resolve. ' + base + ' Ask the user for the correct address.'
    case 'host_key_rejected':
      return 'The host key does not match known_hosts. Stop and ask the user; do not weaken host key checking.'
    case 'local_path_missing':
      return 'The local path does not exist, so nothing was sent and no connection was attempted. Correct the path and retry; the attempt budget was not charged.'
    case 'path_missing':
      return 'A path on one side of the transfer is missing or is not a regular file, so nothing was copied and the attempt budget was not charged. Check both paths; for a directory pass recursive=true.'
    case 'spawn_failed':
      return 'ssh or scp could not be started. Ask the user to install the OpenSSH client or add it to PATH. This is a local failure; the attempt budget was not charged.'
    case 'transfer_timeout':
      return 'The transfer exceeded its deadline and was stopped; the attempt budget was not charged. Retry only after checking the link, and remove any partial file on the destination first.'
    default:
      return base
  }
}

export class AttemptBudget {
  constructor() {
    this.hosts = new Map()
  }

  maxAttempts(fail2ban) {
    return fail2ban === 'absent' ? MAX_ATTEMPTS_NO_FAIL2BAN : MAX_ATTEMPTS_DEFAULT
  }

  snapshot(key, fail2ban) {
    const state = this.hosts.get(key)
    const failures = state === undefined ? 0 : state.failures
    const max = this.maxAttempts(fail2ban)
    const lastFailureAt = state === undefined ? undefined : state.lastFailureAt
    const lastFailureCode = state === undefined ? undefined : state.lastFailureCode
    return {
      used: failures,
      max,
      remaining: Math.max(0, max - failures),
      halted: failures >= max,
      lastFailureAt,
      lastFailureCode,
    }
  }

  /** Returns whether another connection attempt may be made right now. */
  check(key, fail2ban) {
    const snapshot = this.snapshot(key, fail2ban)
    if (snapshot.halted) {
      return { ...snapshot, allowed: false, reason: 'halted' }
    }
    return { ...snapshot, allowed: true }
  }

  recordFailure(key, fail2ban, code = 'ssh_failed') {
    const state = this.hosts.get(key) ?? { failures: 0 }
    state.failures += 1
    state.lastFailureAt = Date.now()
    state.lastFailureCode = code
    this.hosts.set(key, state)
    return this.snapshot(key, fail2ban)
  }

  recordSuccess(key) {
    this.hosts.delete(key)
  }
}

const DESTRUCTIVE_PATTERNS = [
  [/\brm\s+-[A-Za-z]*r[A-Za-z]*f?[A-Za-z]*\s+(\/|~|\$HOME)(\s|$|\/)/, 'recursive delete of a root or home path'],
  [/\bmkfs(\.[a-z0-9]+)?\b/i, 'filesystem format'],
  [/\bdd\b[^\n]*\bof=\/dev\//, 'raw write to a block device'],
  [/\b(shutdown|reboot|poweroff|halt)\b/, 'host shutdown or reboot'],
  [/\b(userdel|groupdel)\b/, 'account or group removal'],
  [/\b(iptables|ip6tables|nft)\b[^|\n]*\s(-F\b|\bflush\b)/, 'firewall flush'],
  [/\bufw\s+disable\b/, 'firewall disable'],
  [/\b(apt|apt-get|yum|dnf|zypper)\b[^\n]*\b(remove|purge|autoremove)\b/, 'package removal'],
  [/\bsystemctl\s+(disable|mask)\b/, 'service disable'],
  [/\btruncate\s+-s\s*0\b/, 'file truncation'],
  [/\bchmod\s+-R\s+777\s+\//, 'permissions change on /'],
  [/\bDROP\s+(DATABASE|TABLE)\b/i, 'database drop'],
  [/\bkubectl\s+delete\b/, 'cluster resource deletion'],
  [/\bterraform\s+destroy\b/, 'infrastructure destruction'],
  [/\bgit\s+push\b[^\n]*--force\b/, 'forced push'],
]

/** Returns a human label when the command needs explicit user confirmation. */
export function classifyCommand(command) {
  const text = String(command ?? '')
  for (const [pattern, label] of DESTRUCTIVE_PATTERNS) {
    if (pattern.test(text)) return label
  }
  return null
}
