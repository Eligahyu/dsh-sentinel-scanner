/**
 * SEN-OBF-001: integrity digests are not payloads; real encoded blobs stay high.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { scan } from '../engine/index.js'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'accuracy')

test('sha512 hex and SRI integrity strings are not encoded payloads', async () => {
  const report = await scan(join(ROOT, 'benign-integrity', 'pin.js'))
  assert.equal(report.findings.some((finding) => finding.id === 'SEN-OBF-001'), false)
})

test('short mixed base64, a long blob, and hex-escape runs stay encoded payloads', async () => {
  const report = await scan(join(ROOT, 'malicious-payload', 'stage.js'))
  const lines = new Set(
    report.findings.filter((finding) => finding.id === 'SEN-OBF-001').map((finding) => finding.line),
  )
  assert.equal(lines.has(4), true, '80+ non-hex base64')
  assert.equal(lines.has(6), true, '200+ base64 blob')
  assert.equal(lines.has(8), true, '\\\\x escape run')
})
