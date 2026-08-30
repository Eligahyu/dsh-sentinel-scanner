import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { buildModuleGraph } from '../engine/semantic/module-graph.js'
import { analyzeCrossFileTaint } from '../engine/semantic/cross-file-taint.js'
import { scan } from '../engine/index.js'

function writeFixture({ safe = false } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'dsh-cross-file-'))
  mkdirSync(join(root, 'plugin'), { recursive: true })
  mkdirSync(join(root, 'lib'), { recursive: true })
  writeFileSync(join(root, 'plugin', 'index.js'), safe
    ? `import { run } from '../lib/runner.js'\nexport function apply(ctx) {\n  ctx.tools.register(defineTool({ name: 'safe', async execute(args) { run('fixed') } }))\n}\n`
    : `import { run } from '../lib/runner.js'\nexport function apply(ctx) {\n  ctx.tools.register(defineTool({ name: 'danger', async execute(args) { run(args.command) } }))\n}\n`)
  writeFileSync(join(root, 'lib', 'runner.js'), `import { exec } from 'node:child_process'\nexport function run(command) { exec(command) }\n`)
  return root
}

function writeCommonJsFixture({ safe = false } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'dsh-cross-file-cjs-'))
  mkdirSync(join(root, 'plugin'), { recursive: true })
  mkdirSync(join(root, 'lib'), { recursive: true })
  writeFileSync(join(root, 'plugin', 'index.cjs'), [
    "const { run } = require('../lib/runner.cjs')",
    'module.exports.apply = function apply(ctx) {',
    `  ctx.tools.register(defineTool({ name: 'cjs', async execute(args) { run(${safe ? "'fixed'" : 'args.command'}) } }))`,
    '}',
  ].join('\n'))
  writeFileSync(join(root, 'lib', 'runner.cjs'), [
    "const { exec } = require('node:child_process')",
    'exports.run = function run(command) { exec(command) }',
  ].join('\n'))
  return root
}

test('cross-file taint connects tool args to an imported shell sink', () => {
  const root = writeFixture()
  try {
    const graph = buildModuleGraph(root, ['plugin/index.js'])
    const result = analyzeCrossFileTaint(root, graph)
    const finding = result.findings.find((f) => f.ruleId === 'SEN-AGENT-001')
    assert.ok(finding)
    assert.equal(finding.crossFile, true)
    assert.deepEqual(finding.modulePath, ['plugin/index.js', 'lib/runner.js'])
    assert.deepEqual(finding.flowSteps, ['args.command', 'run(command)', 'exec'])
    assert.equal(result.attackChains.length, 1)
    assert.equal(result.complete, true)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('cross-file taint does not flag a fixed argument as model-controlled', () => {
  const root = writeFixture({ safe: true })
  try {
    const graph = buildModuleGraph(root, ['plugin/index.js'])
    const result = analyzeCrossFileTaint(root, graph)
    assert.equal(result.findings.length, 0)
    assert.equal(result.attackChains.length, 0)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('cross-file taint connects CommonJS destructuring to an exported shell sink', () => {
  const root = writeCommonJsFixture()
  try {
    const graph = buildModuleGraph(root, ['plugin/index.cjs'])
    const result = analyzeCrossFileTaint(root, graph)
    const finding = result.findings.find((item) => item.ruleId === 'SEN-AGENT-001')

    assert.ok(finding)
    assert.equal(finding.crossFile, true)
    assert.deepEqual(finding.modulePath, ['plugin/index.cjs', 'lib/runner.cjs'])
    assert.deepEqual(finding.flowSteps, ['args.command', 'run(command)', 'exec'])
    assert.equal(result.attackChains.length, 1)
    assert.equal(result.complete, true)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('cross-file taint does not flag a fixed CommonJS argument as model-controlled', () => {
  const root = writeCommonJsFixture({ safe: true })
  try {
    const graph = buildModuleGraph(root, ['plugin/index.cjs'])
    const result = analyzeCrossFileTaint(root, graph)

    assert.equal(result.findings.length, 0)
    assert.equal(result.attackChains.length, 0)
    assert.equal(result.complete, true)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('scan report includes CommonJS cross-file findings and attack chains', async () => {
  const root = writeCommonJsFixture()
  try {
    const report = await scan(root)
    const finding = report.findings.find((item) => item.crossFile
      && item.id === 'SEN-AGENT-001'
      && item.file === 'lib/runner.cjs')

    assert.ok(finding)
    assert.deepEqual(finding.modulePath, ['plugin/index.cjs', 'lib/runner.cjs'])
    assert.ok(report.attackChains.some((chain) => chain.id === finding.attackChainId))
    assert.equal(report.analysisLayers.moduleGraph.crossFile.complete, true)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('cross-file taint reports unresolved graph edges as incomplete', () => {
  const root = writeFixture()
  try {
    const graph = buildModuleGraph(root, ['plugin/index.js', 'missing.js'])
    const result = analyzeCrossFileTaint(root, graph)
    assert.equal(result.complete, false)
    assert.ok(result.failures.some((f) => f.reason === 'module-graph-incomplete'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('scan report includes cross-file findings and attack chains', async () => {
  const root = writeFixture()
  try {
    const report = await scan(root)
    assert.ok(report.findings.some((f) => f.crossFile && f.id === 'SEN-AGENT-001'))
    assert.equal(report.attackChains.length, 1)
    assert.equal(report.analysisLayers.moduleGraph.crossFile.complete, true)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
