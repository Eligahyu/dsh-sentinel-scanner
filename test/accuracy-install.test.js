/**
 * Install-script and shell-downloader accuracy.
 * Documentation URLs must not be critical. Encoded cradles and shell
 * `curl | bash` / `base64 -d | sh` must be. Fixtures are static.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { scan } from '../engine/index.js'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'accuracy')
const ids = (report) => new Set(report.findings.map((finding) => finding.id))

test('documentation URLs in lifecycle scripts are not SEN-INST-002', async () => {
  const report = await scan(join(ROOT, 'benign-install-notice', 'package.json'))
  const found = ids(report)
  assert.equal(found.has('SEN-INST-002'), false, 'echo/printf documentation URLs are not downloaders')
  assert.equal(found.has('SEN-INST-001'), true, 'the lifecycle script is still visible')
})

test('shell comments and documentation URLs are not download-and-exec', async () => {
  const report = await scan(join(ROOT, 'benign-install-notice', 'scripts', 'notice.sh'))
  const found = ids(report)
  assert.equal(found.has('SEN-EXEC-001'), false)
  assert.equal(found.has('SEN-EXEC-004'), false)
  assert.equal(found.has('SEN-FS-001'), false, 'rm -rf ./dist stays a build cleanup')
})

test('encoded and base64 install scripts are SEN-INST-002', async () => {
  const encoded = await scan(join(ROOT, 'malicious-install', 'encoded', 'package.json'))
  assert.equal(ids(encoded).has('SEN-INST-002'), true, 'powershell -EncodedCommand')

  const decoded = await scan(join(ROOT, 'malicious-install', 'base64', 'package.json'))
  assert.equal(ids(decoded).has('SEN-INST-002'), true, 'base64 -d | sh')

  const hidden = await scan(join(ROOT, 'malicious-install', 'echo-and-curl', 'package.json'))
  assert.equal(ids(hidden).has('SEN-INST-002'), true, 'echo does not hide curl | sh')
})

test('shell and quoted downloaders are remote-code or decode-then-exec', async () => {
  const shell = await scan(join(ROOT, 'malicious-install', 'scripts', 'dropper.sh'))
  const shellIds = ids(shell)
  assert.equal(shellIds.has('SEN-EXEC-001'), true, 'curl | bash in a shell script')
  assert.equal(shellIds.has('SEN-EXEC-004'), true, 'base64 decode piped to a shell')

  const quoted = await scan(join(ROOT, 'malicious-install', 'scripts', 'quoted.js'))
  assert.equal(ids(quoted).has('SEN-EXEC-001'), true, 'curl | bash inside a quoted command')
})
