import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { parseTypeScript } from '../engine/semantic/ast.js'
import { buildModuleGraph } from '../engine/semantic/module-graph.js'
import { analyzeCrossFileTaint } from '../engine/semantic/cross-file-taint.js'
import { scan } from '../engine/index.js'

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'dsh-ts-native-'))
  mkdirSync(join(root, 'plugin'), { recursive: true })
  mkdirSync(join(root, 'lib'), { recursive: true })
  writeFileSync(join(root, 'lib', 'runner.ts'), [
    'import { exec } from "node:child_process"',
    'export const run = (command: string): void => { exec(command) }',
    'export function read(value: string): string { return value }',
  ].join('\n'))
  return root
}

test('oxc parses TypeScript, TSX, MTS, CTS and type-only syntax into ESTree nodes', () => {
  for (const [file, code] of [
    ['input.ts', 'const value: number = 1'],
    ['input.tsx', 'const view = <div>{String(1)}</div>'],
    ['input.mts', 'export const value: number = 1'],
    ['input.cts', 'import fs = require("node:fs")'],
    ['input.d.ts', 'declare namespace N { type A = string }'],
  ]) {
    const parsed = parseTypeScript(code, file)
    assert.equal(parsed.parser, 'oxc', file)
    assert.equal(parsed.errors.length, 0, file)
    assert.ok(parsed.ast, file)
  }
})

test('type-only imports and re-exports never become runtime edges', () => {
  const root = fixture()
  try {
    writeFileSync(join(root, 'plugin', 'entry.ts'), [
      "import type { Missing } from '../lib/does-not-exist.js'",
      "import { type Runner, run } from '../lib/runner.js'",
      "import { type Only } from '../lib/does-not-exist-either.js'",
      "export type { AlsoOnly } from '../lib/also-missing.js'",
      "export { type Mixed } from '../lib/mixed-missing.js'",
      'run("safe")',
      'export type Local = Runner | Only',
    ].join('\n'))

    const graph = buildModuleGraph(root, ['plugin/entry.ts'])

    assert.equal(graph.complete, true)
    assert.deepEqual(graph.edges.map((edge) => edge.to), ['lib/runner.ts'])
    assert.equal(graph.edges.some((edge) => edge.specifier.includes('does-not-exist')), false)
    assert.equal(graph.failures.length, 0)
    assert.equal(graph.warnings.some((warning) => warning.reason === 'parser-unparsed'), false)
    assert.equal(graph.nodes.find((node) => node.path === 'plugin/entry.ts')?.parser, 'oxc')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('TypeScript import-equals requires runtime edges and ignores the type-only form', () => {
  const root = fixture()
  try {
    writeFileSync(join(root, 'plugin', 'equals.cts'), [
      "import runtime = require('../lib/runner.js')",
      "import type Types = require('../lib/type-only.js')",
      'runtime.run("safe")',
      'void (null as unknown as Types)',
    ].join('\n'))

    const graph = buildModuleGraph(root, ['plugin/equals.cts'])

    assert.ok(graph.edges.some((edge) => edge.from === 'plugin/equals.cts'
      && edge.to === 'lib/runner.ts'
      && edge.kind === 'static-require'))
    assert.equal(graph.edges.some((edge) => edge.specifier === '../lib/type-only.js'), false)
    assert.equal(graph.failures.length, 0)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('invalid TypeScript falls back to static recovery with an explicit warning', async () => {
  const root = fixture()
  try {
    writeFileSync(join(root, 'plugin', 'broken.ts'), [
      "import type { Missing } from '../lib/missing-type.js'",
      "import { run } from '../lib/runner.js'",
      'const broken: = 1',
      'run("safe")',
    ].join('\n'))

    const graph = buildModuleGraph(root, ['plugin/broken.ts'])
    const warning = graph.warnings.find((item) => item.reason === 'parser-unparsed')

    assert.ok(warning)
    assert.equal(warning.parser, 'oxc')
    assert.equal(warning.fallback, 'static-module-specifiers')
    assert.ok(warning.parseErrors >= 1)
    assert.ok(warning.error)
    assert.ok(graph.edges.some((edge) => edge.to === 'lib/runner.ts'))
    assert.equal(graph.edges.some((edge) => edge.specifier === '../lib/missing-type.js'), false)
    assert.equal(graph.complete, true)

    const report = await scan(join(root, 'plugin', 'broken.ts'))
    assert.equal(report.scanCoverage.parseFailures, 1)
    assert.ok(report.coverageSkips.some((skip) => skip.stage === 'module-graph'
      && skip.reason === 'parser-unparsed'
      && skip.path === 'broken.ts'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('TSX imports are parsed and resolved as runtime edges', () => {
  const root = fixture()
  try {
    writeFileSync(join(root, 'plugin', 'view.tsx'), [
      "import { run } from '../lib/runner.js'",
      'type Props = { command: string }',
      'export function View({ command }: Props) { run(command); return <div>{command}</div> }',
    ].join('\n'))

    const graph = buildModuleGraph(root, ['plugin/view.tsx'])

    assert.equal(graph.complete, true)
    assert.equal(graph.nodes.find((node) => node.path === 'plugin/view.tsx')?.parser, 'oxc')
    assert.ok(graph.edges.some((edge) => edge.from === 'plugin/view.tsx' && edge.to === 'lib/runner.ts'))
    assert.equal(graph.warnings.some((warning) => warning.reason === 'parser-unparsed'), false)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('single-file TypeScript taint runs on the AST with high confidence', async () => {
  const root = fixture()
  try {
    writeFileSync(join(root, 'plugin', 'tool.ts'), [
      "import { exec } from 'node:child_process'",
      'export function apply(ctx: { tools: { register(tool: unknown): void } }): void {',
      '  ctx.tools.register(defineTool({',
      "    name: 'typed-tool',",
      '    async execute(args: { command: string }): Promise<void> { exec(args.command) },',
      '  }))',
      '}',
    ].join('\n'))

    const report = await scan(join(root, 'plugin', 'tool.ts'))
    const finding = report.findings.find((item) => item.id === 'SEN-AGENT-001')
    assert.ok(finding)
    assert.equal(finding.confidence, 'high')
    assert.deepEqual(finding.flowSteps, ['args.command', 'exec'])
    assert.equal(report.analysisLayers.moduleGraph.nodes[0].parser, 'oxc')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('type-only child_process imports cannot confirm a high-confidence sink binding', async () => {
  const root = fixture()
  try {
    writeFileSync(join(root, 'plugin', 'type-only-exec.ts'), [
      "import type { exec as execType } from 'node:child_process'",
      'function exec(value: string): void { void value }',
      'export function apply(ctx: { tools: { register(tool: unknown): void } }): void {',
      '  ctx.tools.register(defineTool({',
      "    name: 'type-only',",
      '    async execute(args: { command: string }): Promise<void> { exec(args.command) },',
      '  }))',
      '}',
      'void (null as unknown as typeof execType)',
    ].join('\n'))

    const report = await scan(join(root, 'plugin', 'type-only-exec.ts'))
    assert.equal(report.findings.some((item) => item.id === 'SEN-AGENT-001'), false)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('TypeScript dynamic specifiers fold unambiguous const strings through the AST', () => {
  const root = fixture()
  try {
    writeFileSync(join(root, 'plugin', 'dynamic.ts'), [
      "const target: string = '../lib/' + 'runner.js'",
      'const mod = await import(target)',
      'const required = require(target)',
      'export { mod, required }',
    ].join('\n'))

    const graph = buildModuleGraph(root, ['plugin/dynamic.ts'])

    assert.equal(graph.complete, true)
    assert.equal(graph.warnings.length, 0)
    assert.ok(graph.edges.some((edge) => edge.from === 'plugin/dynamic.ts'
      && edge.to === 'lib/runner.ts'
      && edge.kind === 'static-import'))
    assert.ok(graph.edges.some((edge) => edge.from === 'plugin/dynamic.ts'
      && edge.to === 'lib/runner.ts'
      && edge.kind === 'static-require'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('ambiguous TypeScript dynamic specifiers stay warnings without guessed edges', () => {
  const root = fixture()
  try {
    writeFileSync(join(root, 'plugin', 'ambiguous.ts'), [
      'let target: string = "../lib/runner.js"',
      'target = process.env.TARGET ?? target',
      'const mod = await import(target)',
      'export { mod }',
    ].join('\n'))

    const graph = buildModuleGraph(root, ['plugin/ambiguous.ts'])

    assert.equal(graph.complete, true)
    assert.equal(graph.edges.length, 0)
    assert.ok(graph.warnings.some((warning) => warning.reason === 'dynamic-module-specifier'
      && warning.kind === 'dynamic-import'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('cross-file taint follows TypeScript import-equals default exports', () => {
  const root = fixture()
  try {
    writeFileSync(join(root, 'lib', 'default-runner.ts'), [
      'import { exec } from "node:child_process"',
      'export default function run(command: string): void { exec(command) }',
    ].join('\n'))
    writeFileSync(join(root, 'plugin', 'equals-cross.cts'), [
      "import run = require('../lib/default-runner.js')",
      'export function apply(ctx: { tools: { register(tool: unknown): void } }): void {',
      '  ctx.tools.register(defineTool({',
      "    name: 'equals-cross',",
      '    async execute(args: { command: string }): Promise<void> { run(args.command) },',
      '  }))',
      '}',
    ].join('\n'))

    const graph = buildModuleGraph(root, ['plugin/equals-cross.cts'])
    const result = analyzeCrossFileTaint(root, graph)
    const finding = result.findings.find((item) => item.ruleId === 'SEN-AGENT-001')

    assert.ok(finding)
    assert.deepEqual(finding.modulePath, ['plugin/equals-cross.cts', 'lib/default-runner.ts'])
    assert.deepEqual(finding.flowSteps, ['args.command', 'default(command)', 'exec'])
    assert.equal(result.complete, true)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('cross-file taint follows typed ESM arrow exports', () => {
  const root = fixture()
  try {
    writeFileSync(join(root, 'plugin', 'entry.ts'), [
      "import { run } from '../lib/runner.js'",
      'export function apply(ctx: { tools: { register(tool: unknown): void } }): void {',
      '  ctx.tools.register(defineTool({',
      "    name: 'typed-cross',",
      '    async execute(args: { command: string }): Promise<void> { run(args.command) },',
      '  }))',
      '}',
    ].join('\n'))

    const graph = buildModuleGraph(root, ['plugin/entry.ts'])
    const result = analyzeCrossFileTaint(root, graph)
    const finding = result.findings.find((item) => item.ruleId === 'SEN-AGENT-001')

    assert.ok(finding)
    assert.equal(finding.confidence, 'high')
    assert.deepEqual(finding.modulePath, ['plugin/entry.ts', 'lib/runner.ts'])
    assert.deepEqual(finding.flowSteps, ['args.command', 'run(command)', 'exec'])
    assert.equal(result.complete, true)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
