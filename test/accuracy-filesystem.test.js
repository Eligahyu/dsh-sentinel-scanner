/**
 * SEN-FS-001 accuracy: benign build cleanup versus critical path wipes.
 * Fixtures are static. The scanner must not execute them.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { scan } from '../engine/index.js'

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'accuracy')

const fsHits = (report) => report.findings.filter((finding) => finding.id === 'SEN-FS-001')

test('benign build cleanup does not raise SEN-FS-001', async () => {
  const report = await scan(join(FIXTURES, 'benign-build-clean'))
  const hits = fsHits(report)
  assert.deepEqual(hits.map((finding) => finding.file), [], 'relative, temp, and workspace deletes are not critical wipes')
  assert.ok(report.findings.some((finding) => finding.id === 'SEN-EXEC-002'), 'shell cleanup is still visible as shell execution')
  assert.ok(report.findings.some((finding) => finding.id === 'SEN-INST-001'), 'prepare script is still reported')
})

test('critical delete targets still raise SEN-FS-001', async () => {
  const report = await scan(join(FIXTURES, 'malicious-wipe'))
  const files = new Set(fsHits(report).map((finding) => finding.file))
  assert.ok(files.has('scripts/wipe.js'), 'js wipe fixture')
  assert.ok(files.has('scripts/wipe.sh'), 'shell wipe fixture')
  assert.ok(files.has('scripts/wipe.ps1'), 'powershell wipe fixture')

  const jsLines = new Set(fsHits(report).filter((finding) => finding.file === 'scripts/wipe.js').map((finding) => finding.line))
  // Comment-only line 13 must not count. The string sample on line 14 must.
  assert.equal(jsLines.has(13), false, 'comment-only rm -rf / is not executable')
  assert.equal(jsLines.has(14), true, '$(rm -rf /) inside a string is still a wipe')
  assert.ok(jsLines.has(6), 'rm -rf /')
  assert.ok(jsLines.has(7), 'rm -rf "$HOME"')
  assert.ok(jsLines.has(9), 'rm -rf /Users/victim')
  assert.ok(jsLines.has(15), 'separate -r -f flags')
})
