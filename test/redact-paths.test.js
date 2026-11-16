import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve, sep } from 'node:path'
import { test } from 'node:test'
import { main, redactReportPaths } from '../bin/sentinel.mjs'

function capture() {
  const buf = { out: '', err: '' }
  return {
    buf,
    stdout: { write(s) { buf.out += s }, isTTY: false },
    stderr: { write(s) { buf.err += s }, isTTY: false },
  }
}

test('redactReportPaths covers report path fields and keeps unrelated evidence', () => {
  const root = resolve(mkdtempSync(join(tmpdir(), 'redact-unit-')))
  const outside = resolve(sep === '\\' ? 'C:\\outside\\secret.js' : '/outside/secret.js')
  const report = {
    target: { path: join(root, 'node_modules') },
    findings: [{
      file: join(root, 'node_modules', 'pkg', 'index.js'),
      message: `missing (${join(root, 'node_modules')})`,
      snippet: "exec('/bin/sh')",
      detail: `read ${join(root, 'secret.txt')}`,
      fingerprint: 'ab'.repeat(32),
    }, {
      file: 'src/already-relative.js',
      message: 'relative finding',
      snippet: 'const ok = 1',
    }, {
      file: outside,
      message: 'outside path stays described as a path field only',
      snippet: "exec('/bin/sh')",
    }],
    coverageSkips: [{ path: join(root, 'node_modules', 'pkg', 'index.js'), reason: 'error' }],
    policySkips: [{ path: join(root, 'skip.js'), reason: 'trusted-scope' }],
    ignored: [{ pattern: join(root, 'dist'), count: 1 }],
    attackChains: [{ modulePath: [join(root, 'a.js'), join(root, 'b.js')], file: join(root, 'a.js') }],
    analysisLayers: {
      moduleGraph: {
        nodes: [{ path: join(root, 'a.js') }],
        edges: [{ from: join(root, 'a.js'), to: join(root, 'b.js') }],
        failures: [{ path: join(root, 'missing.js'), detail: `cannot read ${join(root, 'missing.js')}` }],
      },
    },
    supplyChain: {
      dependencyGraph: {
        failures: [{ path: join(root, 'package-lock.json'), detail: 'parse' }],
      },
    },
    hardSkipped: [{ path: join(root, 'big.bin') }],
    stats: { largestFiles: [{ file: join(root, 'big.js'), bytes: 10 }] },
    profile: { plugins: [{ name: 'pkg', path: join(root, 'node_modules', 'pkg') }] },
  }
  redactReportPaths(report, root)
  const flat = JSON.stringify(report)
  assert.equal(flat.includes(root.replace(/\\/g, '/')), false)
  assert.equal(flat.includes(root), false)
  assert.equal(report.target.path, '<workspace>/node_modules')
  assert.equal(report.findings[0].file, 'pkg/index.js')
  assert.equal(report.findings[0].message, 'missing (<workspace>)')
  assert.equal(report.findings[0].snippet, "exec('/bin/sh')")
  assert.equal(report.findings[0].detail, 'read <workspace>/secret.txt')
  assert.equal(report.findings[0].fingerprint, 'ab'.repeat(32))
  assert.equal(report.findings[1].file, 'src/already-relative.js')
  assert.equal(report.findings[1].snippet, 'const ok = 1')
  assert.equal(report.findings[2].file, '<outside>/secret.js')
  assert.equal(report.coverageSkips[0].path, 'pkg/index.js')
  assert.equal(report.policySkips[0].path, 'skip.js')
  assert.equal(report.ignored[0].pattern, 'dist')
  assert.deepEqual(report.attackChains[0].modulePath, ['a.js', 'b.js'])
  assert.equal(report.analysisLayers.moduleGraph.nodes[0].path, 'a.js')
  assert.equal(report.analysisLayers.moduleGraph.edges[0].from, 'a.js')
  assert.equal(report.analysisLayers.moduleGraph.edges[0].to, 'b.js')
  assert.equal(report.analysisLayers.moduleGraph.failures[0].path, 'missing.js')
  assert.equal(report.analysisLayers.moduleGraph.failures[0].detail, 'cannot read <workspace>/missing.js')
  assert.equal(report.supplyChain.dependencyGraph.failures[0].path, 'package-lock.json')
  assert.equal(report.hardSkipped[0].path, 'big.bin')
  assert.equal(report.stats.largestFiles[0].file, 'big.js')
  assert.equal(report.profile.plugins[0].path, 'pkg')
  assert.equal(flat.includes('\\'), false)
})

test('CLI --redact-paths removes the temp directory from every JSON string', async () => {
  const root = mkdtempSync(join(tmpdir(), 'redact-cli-'))
  const file = join(root, 'net.js')
  writeFileSync(file, "fetch('https://api.example.com/x')\n")
  try {
    const io = capture()
    const code = await main([file, '--json', '--redact-paths', '--fail-on', 'critical'], io)
    assert.equal(code, 0)
    const raw = io.buf.out
    assert.equal(raw.includes(root), false)
    assert.equal(raw.includes(root.replace(/\\/g, '/')), false)
    const report = JSON.parse(raw)
    assert.equal(report.target.path, '<workspace>/net.js')
    const finding = report.findings.find((item) => item.id === 'SEN-NET-001')
    assert.ok(finding)
    assert.equal(finding.file, 'net.js')
    assert.match(finding.snippet, /api\.example\.com/)
    assert.equal(report.stats.largestFiles[0].file, 'net.js')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
