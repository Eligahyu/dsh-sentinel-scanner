import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import { buildModuleGraph } from '../engine/semantic/module-graph.js'
import { analyzeCrossFileTaint } from '../engine/semantic/cross-file-taint.js'
import { scan } from '../engine/index.js'

function writeTree(files) {
  const root = mkdtempSync(join(tmpdir(), 'dsh-cjs-reexport-'))
  for (const [rel, content] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true })
    writeFileSync(join(root, rel), content)
  }
  return root
}

function analyzeTree(files) {
  const root = writeTree(files)
  return { root, result: analyzeCrossFileTaint(root, buildModuleGraph(root, Object.keys(files))) }
}

const caller = (body) => [
  "const { run } = require('../lib/barrel.js')",
  'function apply(ctx) {',
  "  ctx.tools.register(defineTool({ name: 'cjs', async execute(args) {",
  body,
  '  } }))',
  '}',
  'module.exports = { apply }',
].join('\n')

const runner = [
  "const { exec } = require('node:child_process')",
  'function run(command) { exec(command) }',
  'function runFixed(command) { exec("fixed") }',
  'module.exports = { run, runFixed }',
].join('\n')

test('module.exports = require forwards a destructured export to the defining function', async () => {
  const tree = analyzeTree({
    'plugin/index.js': caller('    run(args.command)'),
    'lib/barrel.js': "module.exports = require('./runner.js')\n",
    'lib/runner.js': runner,
  })
  try {
    const finding = tree.result.findings.find((item) => item.ruleId === 'SEN-AGENT-001' && item.crossFile)
    assert.ok(finding)
    assert.equal(finding.file, 'lib/runner.js')
    assert.deepEqual(finding.modulePath, ['plugin/index.js', 'lib/barrel.js', 'lib/runner.js'])
    const report = await scan(tree.root)
    assert.equal(report.summary.scanComplete, true)
    assert.ok(report.findings.some((item) => item.crossFile && item.id === 'SEN-AGENT-001'))
  } finally {
    rmSync(tree.root, { recursive: true, force: true })
  }
})

test('CommonJS forwarding does not guess a fixed command, a dynamic require, or mixed local exports', () => {
  const fixed = analyzeTree({
    'plugin/index.js': caller('    run(args.command)'),
    'lib/barrel.js': "module.exports = require('./runner.js')\n",
    'lib/runner.js': [
      "const { exec } = require('node:child_process')",
      'function run(command) { exec("fixed") }',
      'module.exports = { run }',
    ].join('\n'),
  })
  try {
    assert.equal(fixed.result.findings.some((item) => item.ruleId === 'SEN-AGENT-001'), false)
  } finally {
    rmSync(fixed.root, { recursive: true, force: true })
  }

  const dynamic = analyzeTree({
    'plugin/index.js': caller('    run(args.command)'),
    'lib/barrel.js': 'module.exports = require(name)\n',
    'lib/runner.js': runner,
  })
  try {
    assert.equal(dynamic.result.findings.some((item) => item.ruleId === 'SEN-AGENT-001'), false)
  } finally {
    rmSync(dynamic.root, { recursive: true, force: true })
  }

  const mixed = analyzeTree({
    'plugin/index.js': caller('    run(args.command)'),
    'lib/barrel.js': [
      "const { exec } = require('node:child_process')",
      'exports.run = function run(command) { exec("fixed") }',
      "module.exports = require('./runner.js')",
    ].join('\n'),
    'lib/runner.js': runner,
  })
  try {
    assert.equal(mixed.result.findings.some((item) => item.ruleId === 'SEN-AGENT-001'), false)
    assert.equal(mixed.result.coverageSkips.some((skip) => skip.reason === 'cross-file-reexport-unresolved'), false)
  } finally {
    rmSync(mixed.root, { recursive: true, force: true })
  }
})

test('two static module.exports require targets that both export the name stay unresolved', () => {
  const tree = analyzeTree({
    'plugin/index.js': caller('    run(args.command)'),
    'lib/barrel.js': [
      "module.exports = require('./left.js')",
      "module.exports = require('./right.js')",
    ].join('\n'),
    'lib/left.js': runner,
    'lib/right.js': runner,
  })
  try {
    assert.equal(tree.result.findings.some((item) => item.ruleId === 'SEN-AGENT-001'), false)
    assert.ok(tree.result.coverageSkips.some((skip) => skip.reason === 'cross-file-reexport-unresolved' && skip.member === 'run'))
    assert.equal(tree.result.complete, true)
  } finally {
    rmSync(tree.root, { recursive: true, force: true })
  }
})
