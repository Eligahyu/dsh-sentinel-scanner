import assert from 'node:assert/strict'
import { test } from 'node:test'
import { toCycloneDx, toSpdx, sbomDigest } from '../engine/supplychain/sbom.js'
import { VERSION } from '../engine/version.js'
import { main } from '../bin/sentinel.mjs'
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

const graph = {
  ecosystem: 'npm', lockfile: 'package-lock.json', complete: true,
  nodes: [
    { id: 'node_modules/alpha', name: 'alpha', version: '1.2.0', direct: true, dev: false, optional: false, peer: false, integrity: `sha512-${Buffer.alloc(64).toString('base64')}`, resolved: 'https://registry.npmjs.org/alpha/-/alpha-1.2.0.tgz', hasInstallScript: true, parents: [], children: ['node_modules/beta'] },
    { id: 'node_modules/beta', name: 'beta', version: '2.0.0', direct: false, dev: false, optional: false, peer: false, integrity: null, resolved: null, hasInstallScript: false, parents: ['node_modules/alpha'], children: [] },
  ],
  edges: [{ from: 'node_modules/alpha', to: 'node_modules/beta', name: 'beta', kind: 'runtime' }],
}

test('SBOM serializers default to the scanner package version', () => {
  const cycloneDx = toCycloneDx(graph)
  const spdx = toSpdx(graph)

  assert.equal(cycloneDx.metadata.tools[0].version, VERSION)
  assert.deepEqual(spdx.creationInfo.creators, [`Tool: dsh-sentinel-${VERSION}`])
})

test('CycloneDX output is deterministic and contains purls, hashes, and edges', () => {
  const a = toCycloneDx(graph, { toolVersion: '0.5.0' })
  const b = toCycloneDx(graph, { toolVersion: '0.5.0' })
  assert.deepEqual(a, b)
  assert.equal(a.bomFormat, 'CycloneDX')
  assert.equal(a.specVersion, '1.6')
  assert.equal(a.components.length, 2)
  assert.equal(a.components[0].bomRef, 'pkg:npm/alpha@1.2.0')
  assert.ok(a.components[0].hashes.some((h) => h.alg === 'SHA-512'))
  assert.deepEqual(a.dependencies[0].dependsOn, ['pkg:npm/beta@2.0.0'])
  assert.equal(sbomDigest(a), sbomDigest(b))
})

test('SBOM converts valid SRI digests to hex and rejects malformed hashes', () => {
  const digestBytes = Buffer.alloc(32, 0xab)
  const validIntegrity = `sha256-${digestBytes.toString('base64')}`
  const validGraph = {
    ...graph,
    nodes: graph.nodes.map((node, index) => index === 0 ? { ...node, integrity: validIntegrity } : node),
  }

  const cycloneComponent = toCycloneDx(validGraph).components[0]
  assert.deepEqual(cycloneComponent.hashes, [{ alg: 'SHA-256', content: 'ab'.repeat(32) }])

  const spdxPackage = toSpdx(validGraph).packages[0]
  assert.deepEqual(spdxPackage.checksums, [{ algorithm: 'SHA256', checksumValue: 'ab'.repeat(32) }])

  for (const integrity of [
    'sha256-not base64!',
    `sha256-${Buffer.alloc(31).toString('base64')}`,
    'md5-YWJj',
  ]) {
    const malformedGraph = {
      ...graph,
      nodes: graph.nodes.map((node, index) => index === 0 ? { ...node, integrity } : node),
    }
    assert.equal(toCycloneDx(malformedGraph).components[0].hashes, undefined)
    assert.equal(toSpdx(malformedGraph).packages[0].checksums, undefined)
  }
})

test('CycloneDX preserves pnpm requiresBuild without claiming install scripts are absent', () => {
  const pnpmGraph = {
    ecosystem: 'pnpm',
    lockfile: 'pnpm-lock.yaml',
    complete: true,
    nodes: [{
      id: 'native-addon@3.0.0',
      name: 'native-addon',
      version: '3.0.0',
      direct: true,
      dev: false,
      optional: false,
      peer: false,
      integrity: null,
      resolved: null,
      hasInstallScript: null,
      requiresBuild: true,
      parents: [],
      children: [],
    }],
    edges: [],
  }

  const component = toCycloneDx(pnpmGraph).components[0]
  const properties = new Map(component.properties.map((property) => [property.name, property.value]))

  assert.equal(properties.get('dsh:requiresBuild'), 'true')
  assert.equal(properties.has('dsh:hasInstallScript'), false)

  const withoutBuild = toCycloneDx({
    ...pnpmGraph,
    nodes: pnpmGraph.nodes.map((node) => ({ ...node, requiresBuild: false })),
  })
  assert.notEqual(toCycloneDx(pnpmGraph).serialNumber, withoutBuild.serialNumber)
})

test('SPDX exposes pnpm requiresBuild on the package without inventing lifecycle evidence', () => {
  const pnpmGraph = {
    ecosystem: 'pnpm',
    lockfile: 'pnpm-lock.yaml',
    complete: true,
    nodes: [
      { id: 'native-addon@3.0.0', name: 'native-addon', version: '3.0.0', direct: true, dev: false, optional: false, integrity: null, requiresBuild: true, parents: [], children: [] },
      { id: 'plain@1.0.0', name: 'plain', version: '1.0.0', direct: false, dev: false, optional: false, integrity: null, requiresBuild: false, parents: [], children: [] },
      { id: 'unknown@1.0.0', name: 'unknown', version: '1.0.0', direct: false, dev: false, optional: false, integrity: null, requiresBuild: null, parents: [], children: [] },
    ],
    edges: [],
  }

  const spdx = toSpdx(pnpmGraph)
  const nativePackage = spdx.packages.find((pkg) => pkg.name === 'native-addon')
  const plainPackage = spdx.packages.find((pkg) => pkg.name === 'plain')
  const unknownPackage = spdx.packages.find((pkg) => pkg.name === 'unknown')
  assert.equal(nativePackage.packageComment, 'dsh:requiresBuild=true')
  assert.equal(plainPackage.packageComment, undefined)
  assert.equal(unknownPackage.packageComment, undefined)
  assert.equal(nativePackage.packageComment.includes('install'), false)
  assert.equal(nativePackage.packageComment.includes('lifecycle'), false)

  const reversed = {
    ...pnpmGraph,
    nodes: [...pnpmGraph.nodes].reverse(),
    edges: [...pnpmGraph.edges].reverse(),
  }
  const reversedSpdx = toSpdx(reversed)
  assert.deepEqual(spdx, reversedSpdx)
})

test('SBOM keeps distinct pnpm peer instances with unique component references', () => {
  const peerGraph = {
    ecosystem: 'pnpm',
    lockfile: 'pnpm-lock.yaml',
    complete: true,
    nodes: [
      { id: 'consumer@1.0.0(peer@2.0.0)', name: 'consumer', version: '1.0.0', direct: true, dev: false, optional: false, integrity: null, resolved: null, parents: [], children: ['peer@2.0.0'] },
      { id: 'consumer@1.0.0(peer@3.0.0)', name: 'consumer', version: '1.0.0', direct: true, dev: false, optional: false, integrity: null, resolved: null, parents: [], children: ['peer@3.0.0'] },
      { id: 'peer@2.0.0', name: 'peer', version: '2.0.0', direct: true, dev: false, optional: false, integrity: null, resolved: null, parents: ['consumer@1.0.0(peer@2.0.0)'], children: [] },
      { id: 'peer@3.0.0', name: 'peer', version: '3.0.0', direct: true, dev: false, optional: false, integrity: null, resolved: null, parents: ['consumer@1.0.0(peer@3.0.0)'], children: [] },
    ],
    edges: [
      { from: 'consumer@1.0.0(peer@2.0.0)', to: 'peer@2.0.0', name: 'peer', kind: 'runtime' },
      { from: 'consumer@1.0.0(peer@3.0.0)', to: 'peer@3.0.0', name: 'peer', kind: 'runtime' },
    ],
  }

  const cycloneDx = toCycloneDx(peerGraph)
  const consumerRefs = cycloneDx.components
    .filter((component) => component.name === 'consumer')
    .map((component) => component.bomRef)

  assert.equal(new Set(consumerRefs).size, 2)
  assert.equal(cycloneDx.dependencies.filter((dependency) => consumerRefs.includes(dependency.ref)).length, 2)

  const spdx = toSpdx(peerGraph)
  const consumerIds = spdx.packages
    .filter((pkg) => pkg.name === 'consumer')
    .map((pkg) => pkg.SPDXID)
  assert.equal(new Set(consumerIds).size, 2)
})

test('SBOM output is stable when peer nodes and edges are reversed', () => {
  const peerGraph = {
    ecosystem: 'pnpm',
    lockfile: 'pnpm-lock.yaml',
    complete: true,
    nodes: [
      { id: 'consumer@1.0.0(peer@2.0.0)', name: 'consumer', version: '1.0.0', direct: true, dev: false, optional: false, integrity: null, parents: [], children: ['peer@2.0.0'] },
      { id: 'consumer@1.0.0(peer@3.0.0)', name: 'consumer', version: '1.0.0', direct: true, dev: false, optional: false, integrity: null, parents: [], children: ['peer@3.0.0'] },
      { id: 'peer@2.0.0', name: 'peer', version: '2.0.0', direct: false, dev: false, optional: false, integrity: null, parents: ['consumer@1.0.0(peer@2.0.0)'], children: [] },
      { id: 'peer@3.0.0', name: 'peer', version: '3.0.0', direct: false, dev: false, optional: false, integrity: null, parents: ['consumer@1.0.0(peer@3.0.0)'], children: [] },
    ],
    edges: [
      { from: 'consumer@1.0.0(peer@2.0.0)', to: 'peer@2.0.0', name: 'peer', kind: 'runtime' },
      { from: 'consumer@1.0.0(peer@3.0.0)', to: 'peer@3.0.0', name: 'peer', kind: 'runtime' },
    ],
  }
  const reversed = {
    ...peerGraph,
    nodes: [...peerGraph.nodes].reverse(),
    edges: [...peerGraph.edges].reverse(),
  }

  const cycloneDx = toCycloneDx(peerGraph)
  const reversedCycloneDx = toCycloneDx(reversed)
  assert.equal(cycloneDx.serialNumber, reversedCycloneDx.serialNumber)
  assert.deepEqual(cycloneDx, reversedCycloneDx)

  const spdx = toSpdx(peerGraph)
  const reversedSpdx = toSpdx(reversed)
  assert.equal(spdx.documentNamespace, reversedSpdx.documentNamespace)
  assert.deepEqual(spdx, reversedSpdx)
})

test('SBOM encodes scoped npm package URLs and keeps references connected', () => {
  const scopedGraph = {
    ecosystem: 'npm',
    lockfile: 'package-lock.json',
    complete: true,
    nodes: [
      { id: 'node_modules/@scope/parent', name: '@scope/parent', version: '1.0.0', direct: true, dev: false, optional: false, integrity: null, parents: [], children: ['node_modules/@scope/child'] },
      { id: 'node_modules/@scope/child', name: '@scope/child', version: '2.0.0', direct: false, dev: false, optional: false, integrity: null, parents: ['node_modules/@scope/parent'], children: [] },
    ],
    edges: [{ from: 'node_modules/@scope/parent', to: 'node_modules/@scope/child', name: '@scope/child', kind: 'runtime' }],
  }

  const cycloneDx = toCycloneDx(scopedGraph)
  const parent = cycloneDx.components.find((component) => component.name === '@scope/parent')
  const child = cycloneDx.components.find((component) => component.name === '@scope/child')
  assert.equal(parent.purl, 'pkg:npm/%40scope/parent@1.0.0')
  assert.equal(parent.bomRef, parent.purl)
  assert.equal(child.purl, 'pkg:npm/%40scope/child@2.0.0')
  assert.deepEqual(cycloneDx.dependencies, [{ ref: parent.bomRef, dependsOn: [child.bomRef] }])

  const spdx = toSpdx(scopedGraph)
  assert.deepEqual(spdx.packages.map((pkg) => pkg.externalRefs[0].referenceLocator), [
    'pkg:npm/%40scope/child@2.0.0',
    'pkg:npm/%40scope/parent@1.0.0',
  ])
  assert.ok(spdx.relationships.some((relationship) => relationship.relationshipType === 'DEPENDS_ON'))
})

test('SPDX output contains package checksums and dependency relationships', () => {
  const doc = toSpdx(graph, { toolVersion: '0.5.0' })
  assert.equal(doc.spdxVersion, 'SPDX-2.3')
  assert.equal(doc.packages.length, 2)
  assert.ok(doc.packages[0].externalRefs.some((ref) => ref.referenceType === 'purl'))
  assert.ok(doc.packages[0].checksums.some((sum) => sum.algorithm === 'SHA512'))
  assert.ok(doc.relationships.some((r) => r.relationshipType === 'DEPENDS_ON'))
})

test('SBOM serializers reject incomplete dependency graphs', () => {
  assert.throws(() => toCycloneDx({ ...graph, complete: false }, {}), /incomplete/)
  assert.throws(() => toSpdx({ ...graph, complete: false }, {}), /incomplete/)
})

test('CLI exports an SBOM format from a lockfile scan', async () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-sbom-cli-'))
  try {
    writeFileSync(join(root, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: {
      '': { name: 'cli-fixture', version: '1.0.0', dependencies: { alpha: '^1.0.0' } },
      'node_modules/alpha': { version: '1.0.0' },
    } }))
    const out = join(root, 'bom.json')
    const stdout = { isTTY: false, write() {} }
    const code = await main([root, '--format', 'cyclonedx', '--out', out], { stdout, stderr: stdout })
    assert.equal(code, 0)
    assert.equal(JSON.parse(readFileSync(out, 'utf8')).bomFormat, 'CycloneDX')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
