import { readFileSync } from 'node:fs'
import { dirname, isAbsolute, resolve } from 'node:path'

const AUTH_MODES = new Set(['auto', 'agent', 'key', 'password'])
const FAIL2BAN_VALUES = new Set(['unknown', 'present', 'absent'])
const STRICT_HOST_KEY = new Set(['accept-new', 'yes', 'no'])

export class CredentialsError extends Error {
  constructor(code, message, details = {}) {
    super(message)
    this.name = 'CredentialsError'
    this.code = code
    this.details = details
  }
}

export const DEFAULT_PROFILE = Object.freeze({
  port: 22,
  user: 'root',
  auth: 'auto',
  fail2ban: 'unknown',
  sudo: 'nopasswd',
  connectTimeoutMs: 15000,
  strictHostKey: 'accept-new',
})

function normaliseHost(raw, alias, index, baseDir) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new CredentialsError('invalid_credentials', 'Host "' + alias + '" must be an object')
  }
  const host = typeof raw.host === 'string' ? raw.host.trim() : ''
  if (host === '') {
    throw new CredentialsError('invalid_credentials', 'Host "' + alias + '" is missing "host"')
  }
  const port = raw.port === undefined ? index.port : raw.port
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new CredentialsError('invalid_credentials', 'Host "' + alias + '" has an invalid "port": ' + String(raw.port))
  }
  const user = typeof raw.user === 'string' && raw.user.trim() !== '' ? raw.user.trim() : index.user
  const auth = raw.auth === undefined ? index.auth : raw.auth
  if (!AUTH_MODES.has(auth)) {
    throw new CredentialsError('invalid_credentials', 'Host "' + alias + '" has an invalid "auth" (auto, agent, key, password)')
  }
  const fail2ban = raw.fail2ban === undefined ? index.fail2ban : raw.fail2ban
  if (!FAIL2BAN_VALUES.has(fail2ban)) {
    throw new CredentialsError('invalid_credentials', 'Host "' + alias + '" has an invalid "fail2ban" (unknown, present, absent)')
  }
  const strictHostKey = raw.strictHostKey === undefined ? index.strictHostKey : raw.strictHostKey
  if (!STRICT_HOST_KEY.has(strictHostKey)) {
    throw new CredentialsError('invalid_credentials', 'Host "' + alias + '" has an invalid "strictHostKey" (accept-new, yes, no)')
  }
  const connectTimeoutMs = raw.connectTimeoutMs === undefined ? index.connectTimeoutMs : raw.connectTimeoutMs
  if (!Number.isInteger(connectTimeoutMs) || connectTimeoutMs < 1000 || connectTimeoutMs > 120000) {
    throw new CredentialsError('invalid_credentials', 'Host "' + alias + '" has an invalid "connectTimeoutMs" (1000..120000)')
  }
  const identityFile = typeof raw.identityFile === 'string' && raw.identityFile.trim() !== ''
    ? absolutise(raw.identityFile.trim(), baseDir)
    : undefined
  const passwordFile = typeof raw.passwordFile === 'string' && raw.passwordFile.trim() !== ''
    ? absolutise(raw.passwordFile.trim(), baseDir)
    : undefined

  return {
    alias,
    host,
    port,
    user,
    auth,
    fail2ban,
    sudo: raw.sudo === 'none' ? 'none' : 'nopasswd',
    strictHostKey,
    connectTimeoutMs,
    identityFile,
    passwordFile,
    description: typeof raw.description === 'string' ? raw.description : undefined,
  }
}

function absolutise(value, baseDir) {
  return isAbsolute(value) ? value : resolve(baseDir, value)
}

/**
 * Reads and validates the credentials file. A missing file is reported as an
 * empty, valid catalogue; a malformed file is reported with an error message
 * so the model can ask the user to fix it instead of guessing.
 */
export function loadCredentials(path) {
  let text
  try {
    text = readFileSync(path, 'utf8')
  } catch (error) {
    if (error.code === 'ENOENT') {
      return { path, exists: false, hosts: {}, defaults: DEFAULT_PROFILE }
    }
    return { path, exists: false, hosts: {}, defaults: DEFAULT_PROFILE, error: 'cannot read credentials file: ' + error.message }
  }

  let document
  try {
    // Windows editors and PowerShell's `Set-Content -Encoding utf8` prepend a
    // byte-order mark; JSON.parse rejects it, which would look like a corrupt
    // file even though the content is valid.
    document = JSON.parse(text.replace(/^\uFEFF/, ''))
  } catch (error) {
    return { path, exists: true, hosts: {}, defaults: DEFAULT_PROFILE, error: 'credentials file is not valid JSON: ' + error.message }
  }
  if (document === null || typeof document !== 'object' || Array.isArray(document)) {
    return { path, exists: true, hosts: {}, defaults: DEFAULT_PROFILE, error: 'credentials file must contain a JSON object' }
  }

  const baseDir = dirname(path)
  let index
  try {
    const declared = document.defaults === undefined ? {} : document.defaults
    index = normaliseHost(
      { ...DEFAULT_PROFILE, ...declared, host: 'defaults-placeholder' },
      '$defaults',
      DEFAULT_PROFILE,
      baseDir,
    )
  } catch (error) {
    return { path, exists: true, hosts: {}, defaults: DEFAULT_PROFILE, error: 'invalid "defaults": ' + error.message }
  }

  const rawHosts = document.hosts === undefined ? {} : document.hosts
  if (rawHosts === null || typeof rawHosts !== 'object' || Array.isArray(rawHosts)) {
    return { path, exists: true, hosts: {}, defaults: index, error: '"hosts" must be an object keyed by profile alias' }
  }

  const hosts = {}
  const problems = []
  for (const [alias, raw] of Object.entries(rawHosts)) {
    if (!/^[A-Za-z0-9._-]+$/.test(alias)) {
      problems.push('profile alias "' + alias + '" may only contain letters, digits, dot, dash and underscore')
      continue
    }
    try {
      hosts[alias] = normaliseHost(raw, alias, index, baseDir)
    } catch (error) {
      problems.push(error.message)
    }
  }

  return {
    path,
    exists: true,
    hosts,
    defaults: index,
    error: problems.length > 0 ? problems.join('; ') : undefined,
  }
}

export function resolveProfile(credentials, alias) {
  if (typeof alias !== 'string' || alias.trim() === '') {
    throw new CredentialsError('invalid_argument', 'A profile alias is required')
  }
  const profile = credentials.hosts[alias.trim()]
  if (profile === undefined) {
    throw new CredentialsError('unknown_profile', 'Unknown SSH profile "' + alias + '". Available profiles: ' + (Object.keys(credentials.hosts).join(', ') || '(none)'), {
      available: Object.keys(credentials.hosts),
    })
  }
  const auth = profile.auth === 'auto'
    ? (profile.passwordFile !== undefined ? 'password' : profile.identityFile !== undefined ? 'key' : 'agent')
    : profile.auth
  if (auth === 'password') {
    throw new CredentialsError('password_auth_unsupported', 'Password SSH authentication is not supported: the server runs without an interactive terminal, so ssh cannot answer a password prompt. Ask the user to install the public key on the remote host or configure an ssh-agent.', { profile: profile.alias })
  }
  if (auth === 'key' && profile.identityFile === undefined) {
    throw new CredentialsError('missing_identity_file', 'Profile "' + profile.alias + '" uses key authentication but has no "identityFile"')
  }
  return {
    ...profile,
    auth,
    identityOnly: auth === 'key',
  }
}

/** Non-secret projection shown to the model. */
export function publicProfiles(credentials) {
  return Object.values(credentials.hosts)
    .map((profile) => ({
      profile: profile.alias,
      host: profile.host,
      port: profile.port,
      user: profile.user,
      auth: profile.auth === 'auto'
        ? (profile.passwordFile !== undefined ? 'password' : profile.identityFile !== undefined ? 'key' : 'agent')
        : profile.auth,
      fail2ban: profile.fail2ban,
      sudo: profile.sudo,
      hasKeyFile: profile.identityFile !== undefined,
      description: profile.description,
    }))
    .sort((a, b) => a.profile.localeCompare(b.profile))
}

export const CREDENTIALS_TEMPLATE = {
  defaults: {
    port: 22,
    user: 'root',
    fail2ban: 'unknown',
    strictHostKey: 'accept-new',
  },
  hosts: {
    example: {
      host: '203.0.113.10',
      port: 22222,
      user: 'deploy',
      auth: 'agent',
      fail2ban: 'unknown',
      description: 'replace this example with real hosts; the key is the profile alias',
    },
  },
}
