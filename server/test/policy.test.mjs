import assert from 'node:assert/strict'
import { test } from 'node:test'

import { AttemptBudget, chargesBudget, classifyCommand, failureHint } from '../policy.mjs'

test('recognises destructive commands', () => {
  assert.notEqual(classifyCommand('rm -rf /'), null)
  assert.notEqual(classifyCommand('rm -rf ~/data'), null)
  assert.notEqual(classifyCommand('reboot'), null)
  assert.notEqual(classifyCommand('mkfs.ext4 /dev/sdb1'), null)
  assert.notEqual(classifyCommand('apt-get remove nginx'), null)
  assert.notEqual(classifyCommand('DROP DATABASE app'), null)
})

test('leaves ordinary commands alone', () => {
  assert.equal(classifyCommand('ls -la /var/log'), null)
  assert.equal(classifyCommand('systemctl status nginx'), null)
  assert.equal(classifyCommand('rm /tmp/one-file.txt'), null)
  assert.equal(classifyCommand('docker system df'), null)
})

test('does not flag grep -F inside a read-only firewall inspection', () => {
  assert.equal(classifyCommand("iptables -S | grep -F '192.0.2.1'"), null)
  assert.notEqual(classifyCommand('iptables -F INPUT'), null)
  assert.notEqual(classifyCommand('ip6tables -F'), null)
})

test('default policy allows one retry and then halts', () => {
  const budget = new AttemptBudget()
  const key = 'example:22'
  assert.equal(budget.check(key, 'present').remaining, 2)
  budget.recordFailure(key, 'present')
  assert.equal(budget.snapshot(key, 'present').remaining, 1)
  budget.recordFailure(key, 'present')
  const halted = budget.check(key, 'present')
  assert.equal(halted.allowed, false)
  assert.equal(halted.reason, 'halted')
})

test('a profile without fail2ban gets a third attempt', () => {
  const budget = new AttemptBudget()
  const key = 'example:22'
  budget.recordFailure(key, 'absent')
  budget.recordFailure(key, 'absent')
  const state = budget.check(key, 'absent')
  assert.equal(state.allowed, true)
  assert.equal(state.remaining, 1)
  budget.recordFailure(key, 'absent')
  assert.equal(budget.check(key, 'absent').allowed, false)
})

test('a success clears the failure history', () => {
  const budget = new AttemptBudget()
  budget.recordFailure('example:22', 'present')
  budget.recordSuccess('example:22')
  assert.equal(budget.snapshot('example:22', 'present').remaining, 2)
})

test('failures that do not prove a rejected connection are not charged', () => {
  assert.equal(chargesBudget('spawn_failed'), false)
  assert.equal(chargesBudget('local_path_missing'), false)
  assert.equal(chargesBudget('path_missing'), false)
  assert.equal(chargesBudget('invalid_argument'), false)
  assert.equal(chargesBudget('transfer_timeout'), false)
  assert.equal(chargesBudget('auth_failed'), true)
  assert.equal(chargesBudget('connection_refused'), true)
  assert.equal(chargesBudget('network_unreachable'), true)
  assert.equal(chargesBudget('host_key_rejected'), true)
  assert.equal(chargesBudget('timeout'), true)
  assert.equal(chargesBudget('ssh_failed'), true)
  assert.equal(chargesBudget(undefined), true)
})

test('the halt keeps the code that exhausted the budget', () => {
  const budget = new AttemptBudget()
  budget.recordFailure('example:22', 'present', 'connection_refused')
  budget.recordFailure('example:22', 'present', 'connection_refused')
  const state = budget.check('example:22', 'present')
  assert.equal(state.halted, true)
  assert.equal(state.lastFailureCode, 'connection_refused')
})

test('a halt names the failure that spent the budget, not credentials', () => {
  const refused = failureHint('connection_refused', 0)
  assert.match(refused, /Nothing accepted the connection/)
  assert.doesNotMatch(refused, /authorized_keys/)
  assert.match(failureHint('auth_failed', 0), /authorized_keys/)
  assert.match(failureHint('dns_failed', 1), /did not resolve/)
  assert.match(failureHint('spawn_failed', 2), /budget was not charged/)
})
