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
    { id: 'node_modules/alpha', name: 'alpha', version: '1.2.0', direct: true, dev: false, optional: false, peer: false, integrity: 'sha512-YWxwaGE=', resolved: 'https://registry.npmjs.org/alpha/-/alpha-1.2.0.tgz', hasInstallScript: true, parents: [], children: ['node_modules/beta'] },
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
