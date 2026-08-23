/** Deterministic CycloneDX 1.6 and SPDX 2.3 serializers. */

import { createHash } from 'node:crypto'
import { VERSION } from '../version.js'

function purl(node) {
  return `pkg:npm/${node.name}@${node.version}`
}

function integrityHash(integrity) {
  if (typeof integrity !== 'string') return null
  const match = /^(sha512|sha256|sha1)-(.+)$/.exec(integrity)
  if (!match) return null
  return { alg: match[1].toUpperCase().replace('SHA1', 'SHA-1').replace('SHA256', 'SHA-256').replace('SHA512', 'SHA-512'), content: match[2] }
}

function sortedNodes(graph) {
  if (!graph || graph.complete === false) throw new Error('cannot serialize incomplete dependency graph')
  return [...(graph.nodes ?? [])].sort((a, b) => purl(a).localeCompare(purl(b)))
}

function canonicalBasis(graph) {
  return sortedNodes(graph).map((node) => ({
    id: node.id, name: node.name, version: node.version, integrity: node.integrity ?? null,
    children: [...(node.children ?? [])].sort(), direct: Boolean(node.direct), dev: Boolean(node.dev),
  }))
}

export function sbomDigest(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex')
}

export function toCycloneDx(graph, { toolVersion = VERSION, serialNumber = null } = {}) {
  const nodes = sortedNodes(graph)
  const refs = new Map(nodes.map((node) => [node.id, purl(node)]))
  const components = nodes.map((node) => {
    const component = {
      type: 'library',
      bomRef: purl(node),
      name: node.name,
      version: node.version,
      purl: purl(node),
      properties: [
        { name: 'dsh:direct', value: String(Boolean(node.direct)) },
        { name: 'dsh:dev', value: String(Boolean(node.dev)) },
        { name: 'dsh:optional', value: String(Boolean(node.optional)) },
        { name: 'dsh:hasInstallScript', value: String(Boolean(node.hasInstallScript)) },
      ],
    }
    const hash = integrityHash(node.integrity)
    if (hash) component.hashes = [hash]
    if (node.resolved) component.externalReferences = [{ type: 'distribution', url: node.resolved }]
    return component
  })
  const dependencies = nodes.map((node) => ({
    ref: purl(node),
    dependsOn: [...(node.children ?? [])].map((id) => refs.get(id)).filter(Boolean).sort(),
  })).filter((entry) => entry.dependsOn.length > 0)
  const basis = canonicalBasis(graph)
  const digest = sbomDigest(basis)
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: serialNumber ?? `urn:uuid:${digest.slice(0, 8)}-${digest.slice(8, 12)}-4${digest.slice(12, 15)}-8${digest.slice(15, 18)}-${digest.slice(18, 30)}`,
    version: 1,
    metadata: { tools: [{ vendor: 'dsh-sentinel', name: 'dsh-sentinel', version: toolVersion }] },
    components,
    dependencies,
  }
}

function spdxId(ref) {
  return `SPDXRef-${createHash('sha256').update(ref).digest('hex').slice(0, 16)}`
}

export function toSpdx(graph, { toolVersion = VERSION, created = '1970-01-01T00:00:00Z' } = {}) {
  const nodes = sortedNodes(graph)
  const refs = new Map(nodes.map((node) => [node.id, spdxId(purl(node))]))
  const basisDigest = sbomDigest(canonicalBasis(graph))
  const packages = nodes.map((node) => {
    const pkg = {
      SPDXID: refs.get(node.id),
      name: node.name,
      versionInfo: node.version,
      downloadLocation: node.resolved ?? 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: 'NOASSERTION',
      licenseDeclared: 'NOASSERTION',
      externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: purl(node) }],
    }
    const hash = integrityHash(node.integrity)
    if (hash) pkg.checksums = [{ algorithm: hash.alg.replace('-', ''), checksumValue: hash.content }]
    return pkg
  })
  const relationships = [{ spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'DESCRIBES', relatedSpdxElement: refs.values().next().value ?? 'NOASSERTION' }]
  for (const edge of graph.edges ?? []) {
    const from = refs.get(edge.from)
    const to = refs.get(edge.to)
    if (from && to) relationships.push({ spdxElementId: from, relationshipType: 'DEPENDS_ON', relatedSpdxElement: to })
  }
  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: 'dsh-sentinel dependency SBOM',
    documentNamespace: `https://dsh-sentinel.invalid/sbom/${basisDigest}`,
    creationInfo: { created, creators: [`Tool: dsh-sentinel-${toolVersion}`] },
    packages,
    relationships,
  }
}
