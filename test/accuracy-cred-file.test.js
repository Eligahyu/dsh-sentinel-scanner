/**
 * SEN-CRED-001: project credentials.json is not a credential store.
 * ~/.aws/credentials, joined .aws + credentials, .ssh/id_rsa, and .npmrc stay critical.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { scan } from '../engine/index.js'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'accuracy')

function lines(report) {
  return new Set(
    report.findings.filter((finding) => finding.id === 'SEN-CRED-001').map((finding) => finding.line),
  )
}

test('a project credentials.json is not SEN-CRED-001', async () => {
  const report = await scan(join(ROOT, 'benign-cred-file', 'load.js'))
  assert.equal(lines(report).size, 0)
})

test('aws, ssh, and npmrc reads stay SEN-CRED-001', async () => {
  const report = await scan(join(ROOT, 'malicious-cred-file', 'steal.js'))
  const hits = lines(report)
  assert.ok(hits.has(8), '.aws/credentials')
  assert.ok(hits.has(9), "join(homedir(), '.aws', 'credentials')")
  assert.ok(hits.has(10), '.ssh/id_rsa')
  assert.ok(hits.has(11), '.npmrc')
})
