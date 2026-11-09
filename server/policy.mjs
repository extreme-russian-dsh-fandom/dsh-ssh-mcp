/**
 * Connection-attempt budget. A remote host may run fail2ban, so failures are
 * counted per host:port and never reset by simply asking again. One retry is
 * allowed by default; only a profile that explicitly declares
 * `"fail2ban": "absent"` gets a third attempt.
 */

const MAX_ATTEMPTS_DEFAULT = 2
const MAX_ATTEMPTS_NO_FAIL2BAN = 3

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
    return {
      used: failures,
      max,
      remaining: Math.max(0, max - failures),
      halted: failures >= max,
      lastFailureAt,
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

  recordFailure(key, fail2ban) {
    const state = this.hosts.get(key) ?? { failures: 0 }
    state.failures += 1
    state.lastFailureAt = Date.now()
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
