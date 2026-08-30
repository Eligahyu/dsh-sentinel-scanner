import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { buildModuleGraph } from '../engine/semantic/module-graph.js'
import { scan } from '../engine/index.js'

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'dsh-module-graph-'))
  mkdirSync(join(root, 'plugin'), { recursive: true })
  mkdirSync(join(root, 'lib'), { recursive: true })
  mkdirSync(join(root, 'pkg'), { recursive: true })
  writeFileSync(join(root, 'plugin', 'index.js'), [
    "import { run } from '../lib/runner'",
    "import tool from '../pkg'",
    "import external from 'external-package'",
    'run(tool, external)',
  ].join('\n'))
  writeFileSync(join(root, 'lib', 'runner.js'), 'export function run() {}\n')
  writeFileSync(join(root, 'pkg', 'package.json'), JSON.stringify({
    name: 'local-pkg',
    exports: { '.': './entry.js' },
  }))
  writeFileSync(join(root, 'pkg', 'entry.js'), 'export default {}\n')
  return root
}

test('module graph resolves relative, extensionless, directory, and external imports', () => {
  const root = fixture()
  try {
    const graph = buildModuleGraph(root, ['plugin/index.js', 'lib/runner.js', 'pkg/entry.js'])
    assert.equal(graph.complete, true)
    assert.equal(graph.nodes.length, 3)
    assert.ok(graph.edges.some((e) => e.from === 'plugin/index.js' && e.to === 'lib/runner.js'))
    assert.ok(graph.edges.some((e) => e.from === 'plugin/index.js' && e.to === 'pkg/entry.js'))
    assert.ok(graph.unresolved.some((e) => e.specifier === 'external-package' && e.external === true))
    assert.equal(graph.failures.length, 0)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('module graph resolves static CommonJS require and require.resolve edges', () => {
  const root = fixture()
  try {
    writeFileSync(join(root, 'plugin', 'commonjs.cjs'), [
      "const { run } = require('../lib/' + 'runner')",
      "const toolPath = require.resolve('../pkg')",
      'run(toolPath)',
    ].join('\n'))

    const graph = buildModuleGraph(root, ['plugin/commonjs.cjs'])

    assert.equal(graph.complete, true)
    assert.ok(graph.edges.some((edge) => edge.from === 'plugin/commonjs.cjs'
      && edge.to === 'lib/runner.js'
      && edge.specifier === '../lib/runner'
      && edge.kind === 'static-require'))
    assert.ok(graph.edges.some((edge) => edge.from === 'plugin/commonjs.cjs'
      && edge.to === 'pkg/entry.js'
      && edge.specifier === '../pkg'
      && edge.kind === 'static-require-resolve'))
    assert.equal(graph.failures.length, 0)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('module graph reports dynamic module specifiers without inventing edges', () => {
  const root = fixture()
  try {
    writeFileSync(join(root, 'plugin', 'dynamic.cjs'), [
      'const first = require(args.module)',
      'const second = import(args.fallback)',
      'module.exports = { first, second }',
    ].join('\n'))

    const graph = buildModuleGraph(root, ['plugin/dynamic.cjs'])

    assert.equal(graph.complete, true)
    assert.equal(graph.edges.length, 0)
    assert.equal(graph.failures.length, 0)
    assert.deepEqual(
      graph.warnings
        .filter((warning) => warning.reason === 'dynamic-module-specifier')
        .map((warning) => warning.kind)
        .sort(),
      ['dynamic-import', 'dynamic-require'],
    )
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('module graph rejects imports that escape the scan root', () => {
  const root = fixture()
  try {
    writeFileSync(join(root, 'plugin', 'escape.js'), "import x from '../../outside.js'\nexport default x\n")
    const graph = buildModuleGraph(root, ['plugin/escape.js'])
    assert.equal(graph.complete, false)
    assert.ok(graph.failures.some((f) => f.reason === 'path-escape'))
    assert.equal(graph.edges.length, 0)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('module graph reports parse and missing-file failures without throwing', () => {
  const root = fixture()
  try {
    writeFileSync(join(root, 'broken.js'), 'export function ( {')
    const graph = buildModuleGraph(root, ['broken.js', 'missing.js'])
    assert.equal(graph.complete, false)
    assert.ok(graph.failures.some((f) => f.reason === 'parse-error'))
    assert.ok(graph.failures.some((f) => f.reason === 'missing-file'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('scan report exposes the module graph analysis layer', async () => {
  const root = fixture()
  try {
    const report = await scan(root)
    assert.ok(report.analysisLayers.moduleGraph.nodes.length >= 3)
    assert.ok(report.analysisLayers.moduleGraph.edges.length >= 2)
    assert.equal(report.analysisLayers.moduleGraph.complete, true)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('typed TypeScript imports use a static fallback and resolve .js specifiers to .ts', () => {
  const root = fixture()
  try {
    writeFileSync(join(root, 'plugin', 'typed.ts'), [
      "import { run } from '../lib/typed-runner.js'",
      'const command: string = "safe"',
      'run(command)',
    ].join('\n'))
    writeFileSync(join(root, 'lib', 'typed-runner.ts'), 'export function run(value: string): void {}\n')

    const graph = buildModuleGraph(root, ['plugin/typed.ts'])

    assert.equal(graph.complete, true)
    assert.ok(graph.nodes.some((node) => node.path === 'plugin/typed.ts' && node.parser === 'unparsed'))
    assert.ok(graph.edges.some((edge) => edge.from === 'plugin/typed.ts' && edge.to === 'lib/typed-runner.ts'))
    assert.ok(graph.warnings.some((warning) => warning.path === 'plugin/typed.ts' && warning.reason === 'parser-unparsed'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('typed CommonJS files recover static require edges through the TypeScript fallback', () => {
  const root = fixture()
  try {
    writeFileSync(join(root, 'plugin', 'typed.cts'), [
      "const { run }: { run(value: string): void } = require('../lib/typed-runner.js')",
      'run("safe")',
    ].join('\n'))
    writeFileSync(join(root, 'lib', 'typed-runner.ts'), 'export function run(value: string): void {}\n')

    const graph = buildModuleGraph(root, ['plugin/typed.cts'])

    assert.equal(graph.complete, true)
    assert.ok(graph.nodes.some((node) => node.path === 'plugin/typed.cts' && node.parser === 'unparsed'))
    assert.ok(graph.edges.some((edge) => edge.from === 'plugin/typed.cts'
      && edge.to === 'lib/typed-runner.ts'
      && edge.kind === 'static-require'))
    assert.ok(graph.warnings.some((warning) => warning.path === 'plugin/typed.cts'
      && warning.reason === 'parser-unparsed'
      && warning.importsRecovered === 1))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('TypeScript fallback ignores require text inside strings', () => {
  const root = fixture()
  try {
    writeFileSync(join(root, 'plugin', 'string-only.ts'), [
      'const example: string = "require(\'../lib/runner.js\')"',
      'export default example',
    ].join('\n'))

    const graph = buildModuleGraph(root, ['plugin/string-only.ts'])

    assert.equal(graph.complete, true)
    assert.equal(graph.edges.length, 0)
    assert.deepEqual(graph.nodes.find((node) => node.path === 'plugin/string-only.ts')?.imports, [])
    assert.ok(graph.warnings.some((warning) => warning.path === 'plugin/string-only.ts'
      && warning.reason === 'parser-unparsed'
      && warning.importsRecovered === 0))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('.mts and .cts files are represented instead of silently skipped', () => {
  const root = fixture()
  try {
    writeFileSync(join(root, 'plugin', 'entry.mts'), 'export const value: number = 1\n')
    writeFileSync(join(root, 'plugin', 'legacy.cts'), 'export const value: number = 2\n')

    const graph = buildModuleGraph(root, ['plugin/entry.mts', 'plugin/legacy.cts'])

    assert.deepEqual(graph.nodes.map((node) => node.path).sort(), ['plugin/entry.mts', 'plugin/legacy.cts'])
    assert.equal(graph.complete, true)
    assert.equal(graph.warnings.filter((warning) => warning.reason === 'parser-unparsed').length, 2)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('test-only missing build imports are warnings, not hidden failures', () => {
  const root = fixture()
  try {
    mkdirSync(join(root, 'test'), { recursive: true })
    writeFileSync(join(root, 'test', 'entry.test.js'), "import '../dist/not-built.js'\n")

    const graph = buildModuleGraph(root, ['test/entry.test.js'])

    assert.equal(graph.complete, true)
    assert.equal(graph.failures.length, 0)
    assert.ok(graph.warnings.some((warning) => warning.path === 'test/entry.test.js' && warning.reason === 'missing-file'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('declaration files and development scripts do not make runtime analysis incomplete', () => {
  const root = fixture()
  try {
    mkdirSync(join(root, 'lib', 'types'), { recursive: true })
    mkdirSync(join(root, 'scripts'), { recursive: true })
    writeFileSync(join(root, 'lib', 'types', 'index.d.ts'), "export type { Runner } from './runner.js'\n")
    writeFileSync(join(root, 'scripts', 'live-e2e.mjs'), "import '../lib/not-built.js'\n")

    const graph = buildModuleGraph(root, ['lib/types/index.d.ts', 'scripts/live-e2e.mjs'])

    assert.equal(graph.complete, true)
    assert.equal(graph.failures.length, 0)
    assert.ok(graph.warnings.some((warning) => warning.path === 'lib/types/index.d.ts' && warning.reason === 'missing-file'))
    assert.ok(graph.warnings.some((warning) => warning.path === 'scripts/live-e2e.mjs' && warning.reason === 'missing-file'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('test paths do not downgrade containment failures', () => {
  const root = fixture()
  try {
    mkdirSync(join(root, 'test'), { recursive: true })
    writeFileSync(join(root, 'test', 'escape.test.js'), "import '../../outside.js'\n")

    const graph = buildModuleGraph(root, ['test/escape.test.js'])

    assert.equal(graph.complete, false)
    assert.ok(graph.failures.some((failure) => failure.reason === 'path-escape'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
