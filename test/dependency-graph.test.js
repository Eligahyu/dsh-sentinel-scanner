import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { performance } from 'node:perf_hooks'
import { buildDependencyGraph, dependencyPaths } from '../engine/supplychain/dependency-graph.js'
import { scan } from '../engine/index.js'

function writeLock(root) {
  writeFileSync(join(root, 'package.json'), JSON.stringify({
    name: 'fixture-plugin',
    dependencies: { alpha: '^1.0.0' },
    devDependencies: { 'test-only': '^2.0.0' },
  }))
  writeFileSync(join(root, 'package-lock.json'), JSON.stringify({
    name: 'fixture-plugin', lockfileVersion: 3, requires: true,
    packages: {
      '': { name: 'fixture-plugin', version: '1.0.0', dependencies: { alpha: '^1.0.0' }, devDependencies: { 'test-only': '^2.0.0' } },
      'node_modules/alpha': { version: '1.2.0', resolved: 'https://registry.npmjs.org/alpha/-/alpha-1.2.0.tgz', integrity: 'sha512-alpha', dependencies: { beta: '^1.0.0' }, hasInstallScript: true },
      'node_modules/beta': { version: '1.4.0', integrity: 'sha512-beta' },
      'node_modules/test-only': { version: '2.1.0', dev: true, integrity: 'sha512-test' },
    },
  }))
}

function writePnpmLock(root, { requiresBuild = false } = {}) {
  writeFileSync(join(root, 'package.json'), JSON.stringify({
    name: 'fixture-plugin',
    version: '1.0.0',
    dependencies: { alpha: '^1.0.0' },
  }))
  const lines = [
    "lockfileVersion: '9.0'",
    'importers:',
    '  .:',
    '    dependencies:',
    '      alpha:',
    '        specifier: ^1.0.0',
    '        version: 1.2.0',
    'packages:',
    '  alpha@1.2.0:',
    '    resolution:',
    '      integrity: sha512-alpha',
    '  beta@2.0.0:',
    '    resolution:',
    '      integrity: sha512-beta',
    ...(requiresBuild ? [
      '  native-addon@3.0.0:',
      '    resolution:',
      '      integrity: sha512-native',
      '    requiresBuild: true',
    ] : []),
    'snapshots:',
    '  alpha@1.2.0:',
    '    dependencies:',
    '      beta: 2.0.0',
    ...(requiresBuild ? [
      '  beta@2.0.0:',
      '    optionalDependencies:',
      '      native-addon: 3.0.0',
      '  native-addon@3.0.0: {}',
    ] : ['  beta@2.0.0: {}']),
  ]
  writeFileSync(join(root, 'pnpm-lock.yaml'), lines.join('\n'))
}

test('dependency graph normalizes npm lockfile nodes and edges', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-graph-'))
  try {
    writeLock(root)
    const graph = buildDependencyGraph(root)
    assert.equal(graph.complete, true)
    assert.equal(graph.ecosystem, 'npm')
    assert.equal(graph.nodes.length, 3)
    const alpha = graph.nodes.find((n) => n.name === 'alpha')
    assert.equal(alpha.version, '1.2.0')
    assert.equal(alpha.direct, true)
    assert.equal(alpha.hasInstallScript, true)
    assert.ok(graph.edges.some((e) => e.from === alpha.id && e.to.includes('beta')))
    assert.equal(graph.nodes.find((n) => n.name === 'test-only').dev, true)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('npm hasInstallScript evidence uses the same root-to-package chain contract', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-npm-script-'))
  try {
    writeLock(root)

    const graph = buildDependencyGraph(root)

    assert.deepEqual(graph.buildRequirements, [{
      id: 'node_modules/alpha',
      name: 'alpha',
      version: '1.2.0',
      evidence: 'npm-has-install-script',
      dependencyPaths: [[
        'fixture-plugin@1.0.0',
        'alpha@1.2.0',
      ]],
    }])
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('dependencyPaths returns shortest root-to-target paths in report order', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-paths-'))
  try {
    writeLock(root)
    const graph = buildDependencyGraph(root)

    assert.deepEqual(dependencyPaths(graph, 'beta'), [[
      'fixture-plugin@1.0.0',
      'alpha@1.2.0',
      'beta@1.4.0',
    ]])
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

function diamondGraph(levels) {
  const nodes = [{ id: 'root@1.0.0', name: 'root', version: '1.0.0', direct: true, parents: [], children: [] }]
  let frontier = ['root@1.0.0']
  for (let level = 0; level < levels; level += 1) {
    const next = [`diamond-${level}-a@1.0.0`, `diamond-${level}-b@1.0.0`]
    for (const id of next) {
      const [name, version] = id.split('@')
      nodes.push({ id, name, version, direct: false, parents: [...frontier], children: [] })
    }
    for (const parentId of frontier) nodes.find((node) => node.id === parentId).children.push(...next)
    frontier = next
  }
  const target = { id: 'target@1.0.0', name: 'target', version: '1.0.0', direct: false, parents: [...frontier], children: [] }
  nodes.push(target)
  for (const parentId of frontier) nodes.find((node) => node.id === parentId).children.push(target.id)
  return { root: { name: 'root', version: '1.0.0' }, nodes, edges: [] }
}

test('dependencyPaths returns one deterministic path for an exponential diamond graph', { timeout: 1500 }, () => {
  const graph = diamondGraph(20)
  const started = performance.now()

  const paths = dependencyPaths(graph, 'target')

  const elapsed = performance.now() - started
  assert.equal(paths.length, 1)
  assert.equal(paths[0].length, 23)
  assert.ok(elapsed < 500, `diamond path resolution took ${elapsed.toFixed(1)}ms`)
})

test('dependency paths preserve exact ids for peer-suffixed nodes', () => {
  const graph = {
    root: { name: 'root', version: '1.0.0' },
    nodes: [{
      id: 'dep@1.0.0(peer@2.0.0)',
      name: 'dep',
      version: '1.0.0',
      peer: true,
      direct: true,
      parents: [],
      children: [],
    }],
    edges: [],
  }

  assert.deepEqual(dependencyPaths(graph, 'dep'), [[
    'root@1.0.0',
    'dep@1.0.0(peer@2.0.0)',
  ]])
})

test('dependency graph normalizes pnpm v9 packages, importers, and snapshots', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-pnpm-'))
  try {
    writePnpmLock(root)

    const graph = buildDependencyGraph(root)

    assert.equal(graph.complete, true)
    assert.equal(graph.ecosystem, 'pnpm')
    assert.equal(graph.lockfile, 'pnpm-lock.yaml')
    assert.equal(graph.lockfileVersion, '9.0')
    assert.equal(graph.root.name, 'fixture-plugin')
    assert.equal(graph.root.directDependencies, 1)
    assert.deepEqual(graph.nodes.map((node) => [node.name, node.version, node.direct]), [
      ['alpha', '1.2.0', true],
      ['beta', '2.0.0', false],
    ])
    assert.ok(graph.edges.some((edge) => edge.from === 'alpha@1.2.0'
      && edge.to === 'beta@2.0.0'
      && edge.kind === 'runtime'))
    assert.equal(graph.failures.length, 0)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('pnpm requiresBuild evidence includes a root-to-package dependency chain', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-pnpm-build-'))
  try {
    writePnpmLock(root, { requiresBuild: true })

    const graph = buildDependencyGraph(root)

    assert.equal(graph.complete, true)
    assert.deepEqual(graph.buildRequirements, [{
      id: 'native-addon@3.0.0',
      name: 'native-addon',
      version: '3.0.0',
      evidence: 'pnpm-requires-build',
      dependencyPaths: [[
        'fixture-plugin@1.0.0',
        'alpha@1.2.0',
        'beta@2.0.0',
        'native-addon@3.0.0',
      ]],
    }])
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('pnpm workspace importers create local nodes instead of promoting child dependencies to root direct', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-pnpm-workspace-'))
  try {
    mkdirSync(join(root, 'packages', 'tool'), { recursive: true })
    writeFileSync(join(root, 'package.json'), JSON.stringify({
      name: 'workspace-root',
      version: '1.0.0',
      dependencies: { '@scope/tool': 'workspace:*' },
    }))
    writeFileSync(join(root, 'packages', 'tool', 'package.json'), JSON.stringify({
      name: '@scope/tool',
      version: '2.0.0',
      dependencies: { alpha: '^1.0.0' },
    }))
    writeFileSync(join(root, 'pnpm-lock.yaml'), [
      "lockfileVersion: '9.0'",
      'importers:',
      '  .:',
      '    dependencies:',
      '      "@scope/tool":',
      '        specifier: workspace:*',
      '        version: link:packages/tool',
      '  packages/tool:',
      '    dependencies:',
      '      alpha:',
      '        specifier: ^1.0.0',
      '        version: 1.2.0',
      'packages:',
      '  alpha@1.2.0:',
      '    resolution:',
      '      integrity: sha512-alpha',
      'snapshots:',
      '  alpha@1.2.0: {}',
    ].join('\n'))

    const graph = buildDependencyGraph(root)

    assert.equal(graph.complete, true)
    assert.deepEqual(graph.nodes.map((node) => [node.id, node.name, node.version, node.direct]), [
      ['workspace:packages/tool', '@scope/tool', '2.0.0', true],
      ['alpha@1.2.0', 'alpha', '1.2.0', false],
    ])
    assert.deepEqual(graph.edges, [{
      from: 'workspace:packages/tool',
      to: 'alpha@1.2.0',
      name: 'alpha',
      kind: 'runtime',
    }])
    assert.equal(graph.root.directDependencies, 1)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('pnpm nested workspace links resolve relative to their importer directory', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-pnpm-nested-workspace-'))
  try {
    mkdirSync(join(root, 'packages', 'app'), { recursive: true })
    mkdirSync(join(root, 'packages', 'tool'), { recursive: true })
    writeFileSync(join(root, 'package.json'), JSON.stringify({
      name: 'workspace-root',
      version: '1.0.0',
      dependencies: { '@scope/app': 'workspace:*' },
    }))
    writeFileSync(join(root, 'packages', 'app', 'package.json'), JSON.stringify({
      name: '@scope/app',
      version: '2.0.0',
      dependencies: { '@scope/tool': 'workspace:*' },
    }))
    writeFileSync(join(root, 'packages', 'tool', 'package.json'), JSON.stringify({
      name: '@scope/tool',
      version: '3.0.0',
    }))
    writeFileSync(join(root, 'pnpm-lock.yaml'), [
      "lockfileVersion: '9.0'",
      'importers:',
      '  .:',
      '    dependencies:',
      '      "@scope/app":',
      '        specifier: workspace:*',
      '        version: link:packages/app',
      '  packages/app:',
      '    dependencies:',
      '      "@scope/tool":',
      '        specifier: workspace:*',
      '        version: link:../tool',
      '  packages/tool: {}',
      'packages: {}',
      'snapshots: {}',
    ].join('\n'))

    const graph = buildDependencyGraph(root)

    assert.equal(graph.complete, true)
    assert.deepEqual(graph.edges, [{
      from: 'workspace:packages/app',
      to: 'workspace:packages/tool',
      name: '@scope/tool',
      kind: 'runtime',
    }])
    assert.equal(graph.nodes.find((node) => node.id === 'workspace:packages/app').direct, true)
    assert.equal(graph.nodes.find((node) => node.id === 'workspace:packages/tool').direct, false)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('pnpm peer-suffixed snapshots retain exact instances and base package metadata', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-pnpm-peer-'))
  try {
    writeFileSync(join(root, 'package.json'), JSON.stringify({
      name: 'peer-root',
      version: '1.0.0',
      dependencies: { consumer: '^1.0.0', peer: '^2.0.0' },
    }))
    writeFileSync(join(root, 'pnpm-lock.yaml'), [
      "lockfileVersion: '9.0'",
      'importers:',
      '  .:',
      '    dependencies:',
      '      consumer:',
      '        specifier: ^1.0.0',
      '        version: 1.0.0(peer@2.0.0)',
      '      peer:',
      '        specifier: ^2.0.0',
      '        version: 2.0.0',
      'packages:',
      '  consumer@1.0.0:',
      '    resolution:',
      '      integrity: sha512-consumer',
      '    peerDependencies:',
      '      peer: ^2.0.0',
      '  peer@2.0.0:',
      '    resolution:',
      '      integrity: sha512-peer',
      'snapshots:',
      '  consumer@1.0.0(peer@2.0.0):',
      '    dependencies:',
      '      peer: 2.0.0',
      '  peer@2.0.0: {}',
    ].join('\n'))

    const graph = buildDependencyGraph(root)
    const consumer = graph.nodes.find((node) => node.id === 'consumer@1.0.0(peer@2.0.0)')

    assert.equal(graph.complete, true)
    assert.equal(consumer.name, 'consumer')
    assert.equal(consumer.version, '1.0.0')
    assert.equal(consumer.direct, true)
    assert.equal(consumer.peer, true)
    assert.equal(consumer.integrity, 'sha512-consumer')
    assert.ok(graph.edges.some((edge) => edge.from === consumer.id && edge.to === 'peer@2.0.0'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('pnpm npm aliases resolve to the installed package identity', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-pnpm-alias-'))
  try {
    writeFileSync(join(root, 'package.json'), JSON.stringify({
      name: 'alias-root',
      version: '1.0.0',
      dependencies: { compat: 'npm:real-package@^1.0.0', 'real-package': '^1.0.0' },
    }))
    writeFileSync(join(root, 'pnpm-lock.yaml'), [
      "lockfileVersion: '9.0'",
      'importers:',
      '  .:',
      '    dependencies:',
      '      compat:',
      '        specifier: npm:real-package@^1.0.0',
      '        version: npm:real-package@1.2.0',
      '      real-package:',
      '        specifier: ^1.0.0',
      '        version: 1.2.0',
      'packages:',
      '  real-package@1.2.0:',
      '    resolution:',
      '      integrity: sha512-real',
      'snapshots:',
      '  real-package@1.2.0: {}',
    ].join('\n'))

    const graph = buildDependencyGraph(root)

    assert.equal(graph.complete, true)
    assert.equal(graph.nodes.length, 1)
    assert.equal(graph.nodes[0].id, 'real-package@1.2.0')
    assert.equal(graph.nodes[0].name, 'real-package')
    assert.equal(graph.nodes[0].direct, true)
    assert.equal(graph.root.directDependencies, 2)
    assert.deepEqual(graph.nodes[0].requestedAs, ['compat'])
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('dependency graph marks malformed lockfiles incomplete instead of guessing', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-bad-'))
  try {
    mkdirSync(join(root, 'node_modules'), { recursive: true })
    writeFileSync(join(root, 'package-lock.json'), '{not-json')
    const graph = buildDependencyGraph(root)
    assert.equal(graph.complete, false)
    assert.ok(graph.failures.some((f) => f.reason === 'parse-error'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('dependency graph distinguishes unsupported pnpm versions from malformed YAML', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-pnpm-version-'))
  try {
    writeFileSync(join(root, 'pnpm-lock.yaml'), [
      "lockfileVersion: '10.0'",
      'importers: {}',
      'packages: {}',
      'snapshots: {}',
    ].join('\n'))

    const graph = buildDependencyGraph(root)

    assert.equal(graph.complete, false)
    assert.equal(graph.lockfileVersion, '10.0')
    assert.deepEqual(graph.failures, [{
      reason: 'unsupported-lockfile-version',
      path: 'pnpm-lock.yaml',
      version: '10.0',
    }])
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('pnpm dual-document YAML selects the unique valid v9 graph document', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-pnpm-docs-'))
  try {
    writeFileSync(join(root, 'pnpm-lock.yaml'), [
      "lockfileVersion: '12.0'",
      'metadata: auxiliary',
      '---',
      "lockfileVersion: '9.0'",
      'importers: {}',
      'packages: {}',
      'snapshots: {}',
    ].join('\n'))

    const graph = buildDependencyGraph(root)

    assert.equal(graph.complete, true)
    assert.equal(graph.lockfileVersion, '9.0')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('pnpm valid graph followed by a parse-error document fails the whole lockfile', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-pnpm-trailing-error-'))
  try {
    writeFileSync(join(root, 'pnpm-lock.yaml'), [
      "lockfileVersion: '9.0'",
      'importers: {}',
      'packages: {}',
      'snapshots: {}',
      '---',
      'broken: [',
    ].join('\n'))

    const graph = buildDependencyGraph(root)

    assert.equal(graph.complete, false)
    assert.deepEqual(graph.nodes, [])
    assert.deepEqual(graph.failures, [{ reason: 'parse-error', path: 'pnpm-lock.yaml' }])
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('pnpm multiple valid v9 graph documents fail explicitly instead of guessing', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-pnpm-ambiguous-'))
  try {
    writeFileSync(join(root, 'pnpm-lock.yaml'), [
      "lockfileVersion: '9.0'",
      'importers: {}',
      'packages: {}',
      'snapshots: {}',
      '---',
      "lockfileVersion: '9.0'",
      'importers: {}',
      'packages: {}',
      'snapshots: {}',
    ].join('\n'))

    const graph = buildDependencyGraph(root)

    assert.equal(graph.complete, false)
    assert.deepEqual(graph.failures, [{
      reason: 'ambiguous-lockfile-documents',
      path: 'pnpm-lock.yaml',
      candidates: 2,
    }])
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('pnpm graph rejects non-map importer, package, and snapshot sections', () => {
  for (const section of ['importers', 'packages', 'snapshots']) {
    const root = mkdtempSync(join(tmpdir(), `dsh-dependency-pnpm-schema-${section}-`))
    try {
      writeFileSync(join(root, 'pnpm-lock.yaml'), [
        "lockfileVersion: '9.0'",
        `importers: ${section === 'importers' ? '[]' : '{}'}`,
        `packages: ${section === 'packages' ? 'null' : '{}'}`,
        `snapshots: ${section === 'snapshots' ? 'scalar' : '{}'}`,
      ].join('\n'))

      const graph = buildDependencyGraph(root)

      assert.equal(graph.complete, false, section)
      assert.deepEqual(graph.nodes, [])
      assert.equal(graph.failures[0].reason, 'schema-error')
      assert.equal(graph.failures[0].section, section)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  }
})

test('pnpm graph rejects non-map section entries without creating nodes', () => {
  const invalidValues = ['null', '[]', '7', 'scalar']
  for (const section of ['importers', 'packages', 'snapshots']) {
    for (const invalidValue of invalidValues) {
      const root = mkdtempSync(join(tmpdir(), `dsh-dependency-pnpm-entry-${section}-`))
      try {
        const entry = section === 'importers' ? `  packages/app: ${invalidValue}` : '  app@1.0.0: null'
        const packageSection = section === 'packages' ? `  app@1.0.0: ${invalidValue}` : '  app@1.0.0: {}'
        const snapshotSection = section === 'snapshots' ? `  app@1.0.0: ${invalidValue}` : '  app@1.0.0: {}'
        writeFileSync(join(root, 'pnpm-lock.yaml'), [
          "lockfileVersion: '9.0'",
          'importers:',
          '  .: {}',
          ...(section === 'importers' ? [entry] : []),
          'packages:',
          packageSection,
          'snapshots:',
          snapshotSection,
        ].join('\n'))

        const graph = buildDependencyGraph(root)

        assert.equal(graph.complete, false, `${section}:${invalidValue}`)
        assert.deepEqual(graph.nodes, [], `${section}:${invalidValue}`)
        assert.equal(graph.failures[0].reason, 'schema-error', `${section}:${invalidValue}`)
        assert.equal(graph.failures[0].section, section, `${section}:${invalidValue}`)
      } finally {
        rmSync(root, { recursive: true, force: true })
      }
    }
  }
})

test('pnpm dependency groups must be plain maps', () => {
  for (const group of ['dependencies', 'optionalDependencies', 'devDependencies']) {
    const root = mkdtempSync(join(tmpdir(), `dsh-dependency-pnpm-group-${group}-`))
    try {
      writeFileSync(join(root, 'pnpm-lock.yaml'), [
        "lockfileVersion: '9.0'",
        'importers:',
        '  .:',
        `    ${group}: []`,
        'packages: {}',
        'snapshots: {}',
      ].join('\n'))

      const graph = buildDependencyGraph(root)

      assert.equal(graph.complete, false, group)
      assert.deepEqual(graph.nodes, [], group)
      assert.equal(graph.failures[0].reason, 'schema-error', group)
      assert.equal(graph.failures[0].section, `importers.<root>.${group}`, group)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  }
})

test('pnpm dependency failures are capped with an explicit truncation record', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-pnpm-failure-cap-'))
  try {
    const dependencies = Array.from({ length: 1200 }, (_, index) => `      missing-${index}:\n        specifier: ^1.0.0\n        version: 1.0.0`).join('\n')
    writeFileSync(join(root, 'pnpm-lock.yaml'), [
      "lockfileVersion: '9.0'",
      'importers:',
      '  .:',
      '    dependencies:',
      dependencies,
      'packages: {}',
      'snapshots: {}',
    ].join('\n'))

    const graph = buildDependencyGraph(root)

    assert.equal(graph.complete, false)
    assert.ok(graph.failures.length <= 1000)
    assert.ok(graph.failures.some((failure) => failure.reason === 'failure-truncated'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('pnpm lockfile read failures are distinct from YAML parse failures', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-pnpm-read-error-'))
  try {
    mkdirSync(join(root, 'pnpm-lock.yaml'))

    const graph = buildDependencyGraph(root)

    assert.equal(graph.complete, false)
    assert.deepEqual(graph.failures, [{ reason: 'read-error', path: 'pnpm-lock.yaml' }])
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('pnpm graph resource budgets reject before returning a partial graph', () => {
  const base = [
    "lockfileVersion: '9.0'",
    'importers:',
    '  .:',
    '    dependencies:',
    '      alpha:',
    '        specifier: ^1.0.0',
    '        version: 1.0.0',
    'packages:',
    '  alpha@1.0.0: {}',
    '  beta@2.0.0: {}',
    'snapshots:',
    '  alpha@1.0.0:',
    '    dependencies:',
    '      beta: 2.0.0',
    '  beta@2.0.0: {}',
  ]
  const cases = [
    ['maxNodes', 1, 'graph-node-limit'],
    ['maxEdges', 0, 'graph-edge-limit'],
    ['maxLines', 5, 'lockfile-line-limit'],
  ]
  for (const [option, value, reason] of cases) {
    const root = mkdtempSync(join(tmpdir(), `dsh-dependency-pnpm-budget-${option}-`))
    try {
      writeFileSync(join(root, 'pnpm-lock.yaml'), base.join('\n'))
      const graph = buildDependencyGraph(root, { [option]: value })

      assert.equal(graph.complete, false, option)
      assert.deepEqual(graph.nodes, [], option)
      assert.deepEqual(graph.edges, [], option)
      assert.equal(graph.failures[0].reason, reason, option)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  }
})

test('pnpm malformed YAML returns an explicit parse failure without fabricated nodes', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-pnpm-malformed-'))
  try {
    writeFileSync(join(root, 'pnpm-lock.yaml'), [
      "lockfileVersion: '9.0'",
      'importers:',
      '  .: [',
    ].join('\n'))

    const graph = buildDependencyGraph(root)

    assert.equal(graph.complete, false)
    assert.deepEqual(graph.nodes, [])
    assert.deepEqual(graph.failures, [{ reason: 'parse-error', path: 'pnpm-lock.yaml' }])
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('pnpm workspace importer path escape is rejected without creating an outside node', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-pnpm-escape-'))
  try {
    writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'safe-root', version: '1.0.0' }))
    writeFileSync(join(root, 'pnpm-lock.yaml'), [
      "lockfileVersion: '9.0'",
      'importers:',
      '  .: {}',
      '  ../outside: {}',
      'packages: {}',
      'snapshots: {}',
    ].join('\n'))

    const graph = buildDependencyGraph(root)

    assert.equal(graph.complete, false)
    assert.deepEqual(graph.nodes, [])
    assert.deepEqual(graph.failures.map(({ reason, path }) => ({ reason, path })), [{
      reason: 'workspace-path-error',
      path: '../outside',
    }])
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('dependency graph rejects lockfiles above the configured byte limit before parsing', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-pnpm-size-'))
  try {
    const lockfile = [
      '# padding padding padding padding padding',
      "lockfileVersion: '9.0'",
      'importers: {}',
      'packages: {}',
      'snapshots: {}',
    ].join('\n')
    writeFileSync(join(root, 'pnpm-lock.yaml'), lockfile)

    const graph = buildDependencyGraph(root, { maxBytes: 32 })

    assert.equal(graph.complete, false)
    assert.equal(graph.nodes.length, 0)
    assert.deepEqual(graph.failures, [{
      reason: 'lockfile-too-large',
      path: 'pnpm-lock.yaml',
      bytes: Buffer.byteLength(lockfile),
      maxBytes: 32,
    }])
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('dependency graph returns explicit unsupported state for remaining lockfiles', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-other-'))
  try {
    writeFileSync(join(root, 'yarn.lock'), 'alpha@^1.0.0:\n  version "1.0.0"\n')
    const graph = buildDependencyGraph(root)
    assert.equal(graph.complete, false)
    assert.equal(graph.ecosystem, 'yarn')
    assert.equal(graph.lockfile, 'yarn.lock')
    assert.ok(graph.failures.some((f) => f.reason === 'unsupported-lockfile'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('scan report exposes the normalized dependency graph when a lockfile exists', async () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-report-'))
  try {
    writeLock(root)
    const report = await scan(root)
    assert.equal(report.analysisLayers.dependencyGraph.complete, true)
    assert.equal(report.analysisLayers.dependencyGraph.nodes.length, 3)
    assert.equal(report.supplyChain.dependencyGraph.nodes, 3)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('scan report exposes pnpm build-requirement dependency paths', async () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-pnpm-report-'))
  try {
    writePnpmLock(root, { requiresBuild: true })

    const report = await scan(root)

    assert.equal(report.analysisLayers.dependencyGraph.ecosystem, 'pnpm')
    assert.equal(report.analysisLayers.dependencyGraph.complete, true)
    assert.deepEqual(report.supplyChain.dependencyGraph.buildRequirements, [{
      id: 'native-addon@3.0.0',
      name: 'native-addon',
      version: '3.0.0',
      evidence: 'pnpm-requires-build',
      dependencyPaths: [[
        'fixture-plugin@1.0.0',
        'alpha@1.2.0',
        'beta@2.0.0',
        'native-addon@3.0.0',
      ]],
    }])
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
