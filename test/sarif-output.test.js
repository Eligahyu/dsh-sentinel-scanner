import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { main } from '../bin/sentinel.mjs'
import { toSarif } from '../engine/output/sarif.js'

function capture() {
  const buf = { out: '', err: '' }
  return {
    buf,
    stdout: { write(s) { buf.out += s }, isTTY: false },
    stderr: { write(s) { buf.err += s }, isTTY: false },
  }
}

function finding(extra = {}) {
  return {
    id: 'SEN-NET-001',
    severity: 'medium',
    message: 'outbound request',
    file: extra.file ?? 'src/a.js',
    line: 2,
    fingerprint: 'a'.repeat(64),
    ...extra,
  }
}

test('SARIF marks a completed scan successful and keeps the fingerprint off partialFingerprints', () => {
  const sarif = toSarif({
    summary: { scanComplete: true, findingsTruncated: false },
    findings: [finding()],
  })
  const run = sarif.runs[0]
  assert.equal(run.invocations[0].executionSuccessful, true)
  assert.equal(run.invocations[0].toolExecutionNotifications, undefined)
  const result = run.results[0]
  assert.equal(result.partialFingerprints, undefined)
  assert.equal(result.properties.dshFingerprint, 'a'.repeat(64))
  assert.equal(result.locations[0].physicalLocation.region.startLine, 2)
})

test('SARIF reports an incomplete scan as an unsuccessful invocation', () => {
  const sarif = toSarif({
    summary: { scanComplete: false, incompleteReasons: ['scan', 'max-files'] },
    findings: [finding({ line: 0, startColumn: 0, endLine: 0, endColumn: 0 })],
  })
  const invocation = sarif.runs[0].invocations[0]
  assert.equal(invocation.executionSuccessful, false)
  assert.equal(invocation.toolExecutionNotifications.length, 1)
  const note = invocation.toolExecutionNotifications[0]
  assert.equal(note.descriptor.id, 'dsh-scan-incomplete')
  assert.equal(note.level, 'error')
  assert.match(note.message.text, /scan, max-files/)
  const region = sarif.runs[0].results[0].locations[0].physicalLocation.region
  assert.equal(region.startLine, 1)
  assert.equal(region.startColumn, 1)
  assert.equal(region.endLine, 1)
  assert.equal(region.endColumn, 1)
  assert.equal(sarif.runs[0].results[0].partialFingerprints, undefined)
})

test('SARIF warns when findings are truncated without failing the invocation', () => {
  const sarif = toSarif({
    summary: { scanComplete: true, findingsTruncated: true, findingsReturned: 1, findingsTotal: 4 },
    findings: [finding({ startColumn: 8, endColumn: 2 })],
  })
  const invocation = sarif.runs[0].invocations[0]
  assert.equal(invocation.executionSuccessful, true)
  assert.equal(invocation.toolExecutionNotifications.length, 1)
  const note = invocation.toolExecutionNotifications[0]
  assert.equal(note.descriptor.id, 'dsh-findings-truncated')
  assert.equal(note.level, 'warning')
  assert.match(note.message.text, /1 of 4 returned/)
  const region = sarif.runs[0].results[0].locations[0].physicalLocation.region
  assert.equal(region.startColumn, 8)
  assert.equal(region.endColumn, 8)
})

test('SARIF keeps an earlier endLine from preceding the start line', () => {
  const sarif = toSarif({
    findings: [finding({ line: 5, endLine: 2, startColumn: 3, endColumn: 1 })],
  })
  const region = sarif.runs[0].results[0].locations[0].physicalLocation.region
  assert.deepEqual(region, { startLine: 5, startColumn: 3, endLine: 5, endColumn: 3 })
  assert.equal(sarif.runs[0].invocations[0].executionSuccessful, true)
})

test('SARIF relativizes a file base path and never emits an empty uri', () => {
  const root = mkdtempSync(join(tmpdir(), 'sarif-uri-'))
  const file = join(root, 'only.js')
  writeFileSync(file, 'const x = 1\n')
  try {
    const sarif = toSarif({ findings: [finding({ file })] }, { basePath: file })
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'only.js')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }

  const missing = join(tmpdir(), 'sarif-missing-base', 'only.js')
  const missingSarif = toSarif({ findings: [finding({ file: missing })] }, { basePath: missing })
  assert.equal(missingSarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'only.js')

  const blank = toSarif({ findings: [finding({ file: '' })] })
  assert.equal(blank.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'file')
})

test('CLI SARIF uses the file name for a single-file target', async () => {
  const root = mkdtempSync(join(tmpdir(), 'sarif-cli-'))
  const file = join(root, 'net.js')
  writeFileSync(file, "fetch('https://api.example.com/x')\n")
  try {
    const io = capture()
    const code = await main([file, '--format', 'sarif', '--fail-on', 'critical'], io)
    assert.equal(code, 0)
    const sarif = JSON.parse(io.buf.out)
    const result = sarif.runs[0].results.find((item) => item.ruleId === 'SEN-NET-001')
    assert.ok(result)
    assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, 'net.js')
    assert.equal(result.partialFingerprints, undefined)
    assert.match(result.properties.dshFingerprint, /^[0-9a-f]{64}$/)
    assert.equal(sarif.runs[0].invocations[0].executionSuccessful, true)
    assert.ok(result.locations[0].physicalLocation.region.startLine >= 1)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('CLI SARIF marks a max-files cutoff as an unsuccessful invocation', async () => {
  const root = mkdtempSync(join(tmpdir(), 'sarif-incomplete-'))
  writeFileSync(join(root, 'a.js'), 'const a = 1\n')
  writeFileSync(join(root, 'b.js'), 'const b = 1\n')
  try {
    const io = capture()
    const code = await main([root, '--format', 'sarif', '--max-files', '1', '--fail-on', 'critical'], io)
    assert.equal(code, 0)
    const sarif = JSON.parse(io.buf.out)
    const invocation = sarif.runs[0].invocations[0]
    assert.equal(invocation.executionSuccessful, false)
    assert.equal(invocation.toolExecutionNotifications[0].descriptor.id, 'dsh-scan-incomplete')
    for (const result of sarif.runs[0].results) {
      const uri = result.locations[0].physicalLocation.artifactLocation.uri
      assert.notEqual(uri, '')
      assert.equal(result.partialFingerprints, undefined)
    }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
