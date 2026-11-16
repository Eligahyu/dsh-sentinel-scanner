/**
 * SEN-TAINT-003: indirect eval, Function constructor, vm.Script, and decoder aliases.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { scan } from '../engine/index.js'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'accuracy')

function taintLines(report) {
  return report.findings
    .filter((finding) => finding.id === 'SEN-TAINT-003')
    .map((finding) => finding.line)
}

test('eval and Function aliases of a decoded payload are SEN-TAINT-003', async () => {
  const alias = await scan(join(ROOT, 'malicious-indirect', 'alias-eval.js'))
  assert.ok(taintLines(alias).includes(5), 'const run = eval; run(decoded)')

  const ctor = await scan(join(ROOT, 'malicious-indirect', 'function-ctor.js'))
  assert.ok(taintLines(ctor).includes(4), 'Function.prototype.constructor')
})

test('vm.Script and an atob alias still reach dynamic execution', async () => {
  const script = await scan(join(ROOT, 'malicious-indirect', 'vm-script.js'))
  assert.ok(taintLines(script).includes(5), 'new vm.Script(decoded)')

  const decoded = await scan(join(ROOT, 'malicious-indirect', 'decode-alias.js'))
  assert.ok(taintLines(decoded).includes(4), 'eval(decode(blob))')
})

test('a globalThis polyfill and a display decoder are not decode-to-exec', async () => {
  const report = await scan(join(ROOT, 'benign-indirect', 'helpers.js'))
  assert.deepEqual(taintLines(report), [])
})
