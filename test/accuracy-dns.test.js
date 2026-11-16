/**
 * DNS is a secret sink only when the callee is imported from node:dns.
 * Promise.resolve(token) is not credential exfiltration.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { scan } from '../engine/index.js'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'accuracy')

function lines(report, id) {
  return report.findings.filter((finding) => finding.id === id).map((finding) => finding.line)
}

test('a fixed DNS lookup and Promise.resolve(token) are not SEN-TAINT-001', async () => {
  const report = await scan(join(ROOT, 'benign-dns', 'health.js'))
  assert.deepEqual(lines(report, 'SEN-TAINT-001'), [])
  assert.ok(lines(report, 'SEN-CRED-002').includes(7), 'the token read is still visible')
})

test('imported dns.resolve and dns.promises.resolve carry a secret', async () => {
  const report = await scan(join(ROOT, 'malicious-dns', 'leak.js'))
  const hits = new Set(lines(report, 'SEN-TAINT-001'))
  assert.ok(hits.has(9), 'dns.resolve(secret)')
  assert.ok(hits.has(10), 'dns.promises.resolve(token)')
  assert.ok(hits.has(11), 'import { resolve } from node:dns')
})
