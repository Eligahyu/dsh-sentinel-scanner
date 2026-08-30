/** Normalize package-manager metadata into a dependency graph. */

import { existsSync, readFileSync, statSync } from 'node:fs'
import { join, posix } from 'node:path'
import { parseAllDocuments } from 'yaml'
import { resolveInside } from '../path-safety.js'

export const DEPENDENCY_LOCKFILE_MAX_BYTES = 64 * 1024 * 1024
export const PNPM_FAILURE_LIMIT = 1000
export const PNPM_GRAPH_MAX_NODES = 20_000
export const PNPM_GRAPH_MAX_EDGES = 100_000
export const PNPM_LOCKFILE_MAX_LINES = 100_000

function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
  } catch {
    return null
  }
}

function packageNameFromKey(key) {
  const marker = 'node_modules/'
  const index = key.lastIndexOf(marker)
  return index >= 0 ? key.slice(index + marker.length) : key
}

function directNames(root) {
  return new Set([
    ...Object.keys(root.dependencies ?? {}),
    ...Object.keys(root.optionalDependencies ?? {}),
    ...Object.keys(root.peerDependencies ?? {}),
    ...Object.keys(root.devDependencies ?? {}),
  ])
}

function dependencyKinds(root, name) {
  return {
    direct: directNames(root).has(name),
    dev: Object.prototype.hasOwnProperty.call(root.devDependencies ?? {}, name),
    optional: Object.prototype.hasOwnProperty.call(root.optionalDependencies ?? {}, name),
    peer: Object.prototype.hasOwnProperty.call(root.peerDependencies ?? {}, name),
  }
}

function candidateKeys(parentKey, dependency) {
  const out = []
  if (parentKey) {
    const slash = parentKey.lastIndexOf('/node_modules/')
    const parentPackageRoot = slash >= 0 ? parentKey.slice(0, slash + '/node_modules/'.length) : `${parentKey}/node_modules/`
    out.push(`${parentPackageRoot}${dependency}`)
  }
  out.push(`node_modules/${dependency}`)
  return [...new Set(out)]
}

function unsupportedLockfile(dir) {
  for (const name of ['pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'bun.lockb']) {
    if (existsSync(join(dir, name))) return name
  }
  return null
}

function isPlainMap(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

function readPnpmDocument(file, { maxLines = PNPM_LOCKFILE_MAX_LINES } = {}) {
  let text
  try {
    text = readFileSync(file, 'utf8')
  } catch {
    return { error: { reason: 'read-error', path: 'pnpm-lock.yaml' } }
  }

  const lines = text.length === 0 ? 0 : text.split(/\r\n|\r|\n/).length
  if (lines > maxLines) {
    return { error: { reason: 'lockfile-line-limit', path: 'pnpm-lock.yaml', lines, maxLines } }
  }

  let documents
  try {
    documents = parseAllDocuments(text, { maxAliasCount: 100 })
  } catch {
    return { error: { reason: 'parse-error', path: 'pnpm-lock.yaml' } }
  }

  const candidates = []
  let parseFailure = false
  let documentFailure = false
  let schemaFailure = null
  let unsupportedVersion = null
  for (const document of documents) {
    if (document.errors.length > 0) {
      parseFailure = true
      documentFailure = true
      continue
    }
    let value
    try {
      value = document.toJS({ maxAliasCount: 100 })
    } catch {
      parseFailure = true
      documentFailure = true
      continue
    }
    if (!isPlainMap(value)) {
      parseFailure = true
      documentFailure = true
      continue
    }
    const version = String(value.lockfileVersion ?? '')
    if (!/^9(?:\.|$)/.test(version)) {
      if (version && unsupportedVersion === null) unsupportedVersion = version
      continue
    }
    const invalidSection = ['importers', 'packages', 'snapshots']
      .find((section) => !isPlainMap(value[section]))
    if (invalidSection) {
      schemaFailure ??= { reason: 'schema-error', path: 'pnpm-lock.yaml', section: invalidSection }
      continue
    }
    candidates.push(value)
  }

  if (documentFailure) return { error: { reason: 'parse-error', path: 'pnpm-lock.yaml' } }
  if (candidates.length === 1) return { document: candidates[0] }
  if (candidates.length > 1) {
    return { error: { reason: 'ambiguous-lockfile-documents', path: 'pnpm-lock.yaml', candidates: candidates.length } }
  }
  if (schemaFailure) return { error: schemaFailure }
  if (unsupportedVersion !== null && !parseFailure) {
    return {
      error: {
        reason: 'unsupported-lockfile-version',
        path: 'pnpm-lock.yaml',
        version: unsupportedVersion,
      },
    }
  }
  return { error: { reason: 'parse-error', path: 'pnpm-lock.yaml' } }
}

function makeFailureRecorder(limit = PNPM_FAILURE_LIMIT) {
  const failures = []
  let dropped = 0
  return {
    add(failure) {
      if (failures.length < Math.max(0, limit - 1)) failures.push(failure)
      else dropped += 1
    },
    finish() {
      if (dropped > 0) {
        failures.push({ reason: 'failure-truncated', path: 'pnpm-lock.yaml', dropped, maxFailures: limit })
      }
      return failures
    },
  }
}

function pnpmPackageIdentity(key, entry = {}) {
  const withoutPeers = String(key).split('(')[0]
  const separator = withoutPeers.lastIndexOf('@')
  return {
    name: String(entry.name ?? (separator > 0 ? withoutPeers.slice(0, separator) : withoutPeers)),
    version: String(entry.version ?? (separator > 0 ? withoutPeers.slice(separator + 1) : '')),
  }
}

function dependencyVersion(value) {
  if (typeof value === 'string' || typeof value === 'number') return String(value)
  if (value && typeof value === 'object' && (typeof value.version === 'string' || typeof value.version === 'number')) {
    return String(value.version)
  }
  return null
}

function buildPnpmReferenceIndex(ids) {
  const index = new Map()
  const add = (key, id) => {
    const values = index.get(key) ?? new Set()
    values.add(id)
    index.set(key, values)
  }
  for (const id of ids) {
    add(id, id)
    add(String(id).split('(')[0], id)
  }
  return index
}

function pnpmNodeId(index, name, value) {
  const version = dependencyVersion(value)
  if (version === null) return null
  const expected = version.startsWith('npm:') ? version.slice('npm:'.length) : `${name}@${version}`
  const matches = index.get(expected)
  if (!matches) return null
  if (matches.has(expected)) return expected
  return matches.size === 1 ? [...matches][0] : null
}

function workspaceTarget(importerId, value) {
  const version = dependencyVersion(value)
  if (!version?.startsWith('link:')) return null
  const linkPath = version.slice('link:'.length).replace(/\\/g, '/')
  const basePath = importerId === '.' ? '' : importerId
  return posix.normalize(posix.join(basePath, linkPath)).replace(/^\.\//, '').replace(/\/$/, '')
}

function validatePnpmSchema(doc, lockfile) {
  for (const section of ['importers', 'packages', 'snapshots']) {
    for (const [key, value] of Object.entries(doc[section])) {
      if (!isPlainMap(value)) return { reason: 'schema-error', path: lockfile, section }
      if (section === 'importers') {
        for (const group of ['dependencies', 'optionalDependencies', 'devDependencies']) {
          if (Object.prototype.hasOwnProperty.call(value, group) && !isPlainMap(value[group])) {
            const importerLabel = key === '.' ? '<root>' : key
            return { reason: 'schema-error', path: lockfile, section: `importers.${importerLabel}.${group}` }
          }
        }
      }
    }
  }
  return null
}

function countPnpmEdges(doc) {
  let edges = 0
  for (const importer of Object.values(doc.importers)) {
    for (const group of ['dependencies', 'optionalDependencies', 'devDependencies']) {
      edges += Object.keys(importer[group] ?? {}).length
    }
  }
  for (const snapshot of Object.values(doc.snapshots)) {
    edges += Object.keys(snapshot.dependencies ?? {}).length
    edges += Object.keys(snapshot.optionalDependencies ?? {}).length
  }
  return edges
}

function pathLabel(node) {
  return node.peer ? node.id : `${node.name}@${node.version}`
}

function buildShortestPathIndex(graph) {
  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]))
  const predecessor = new Map()
  const distance = new Map()
  const queue = []
  for (const node of graph.nodes.filter((item) => item.direct).sort((a, b) => a.id.localeCompare(b.id))) {
    distance.set(node.id, 0)
    predecessor.set(node.id, null)
    queue.push(node.id)
  }
  for (let head = 0; head < queue.length; head += 1) {
    const id = queue[head]
    const node = nodeById.get(id)
    for (const child of [...(node?.children ?? [])].sort()) {
      if (distance.has(child)) continue
      distance.set(child, distance.get(id) + 1)
      predecessor.set(child, id)
      queue.push(child)
    }
  }
  return { nodeById, predecessor, distance }
}

function shortestDependencyPath(index, targetId, root) {
  if (!index.distance.has(targetId)) return []
  const ids = []
  for (let current = targetId; current !== null; current = index.predecessor.get(current)) {
    ids.push(current)
  }
  const labels = ids.reverse().map((id) => pathLabel(index.nodeById.get(id)))
  if (root?.name) labels.unshift(`${root.name}@${root.version ?? ''}`)
  return labels
}

function buildPnpmGraph(dir, { maxNodes = PNPM_GRAPH_MAX_NODES, maxEdges = PNPM_GRAPH_MAX_EDGES, maxLines = PNPM_LOCKFILE_MAX_LINES } = {}) {
  const lockfile = 'pnpm-lock.yaml'
  const loaded = readPnpmDocument(join(dir, lockfile), { maxLines })
  if (loaded.error) {
    return { ecosystem: 'pnpm', lockfile, lockfileVersion: loaded.error.version ?? null, nodes: [], edges: [], failures: [loaded.error], complete: false }
  }
  const doc = loaded.document
  const lockfileVersion = String(doc.lockfileVersion ?? '')
  const schemaFailure = validatePnpmSchema(doc, lockfile)
  if (schemaFailure) {
    return { ecosystem: 'pnpm', lockfile, lockfileVersion, nodes: [], edges: [], failures: [schemaFailure], complete: false }
  }
  const workspaceCount = Object.keys(doc.importers).filter((id) => id !== '.').length
  const nodeCount = workspaceCount + Object.keys(doc.snapshots).length
  if (nodeCount > maxNodes) {
    return {
      ecosystem: 'pnpm', lockfile, lockfileVersion, nodes: [], edges: [],
      failures: [{ reason: 'graph-node-limit', path: lockfile, nodes: nodeCount, maxNodes }], complete: false,
    }
  }
  const edgeCount = countPnpmEdges(doc)
  if (edgeCount > maxEdges) {
    return {
      ecosystem: 'pnpm', lockfile, lockfileVersion, nodes: [], edges: [],
      failures: [{ reason: 'graph-edge-limit', path: lockfile, edges: edgeCount, maxEdges }], complete: false,
    }
  }

  const root = readJson(join(dir, 'package.json')) ?? {}
  const snapshots = Object.entries(doc.snapshots)
  const snapshotReferenceIndex = buildPnpmReferenceIndex(snapshots.map(([id]) => id))
  const directById = new Map()
  const failureRecorder = makeFailureRecorder()
  const rootDirectNames = new Set()
  const workspaceDescriptors = new Map()
  for (const importerId of Object.keys(doc.importers)) {
    if (importerId === '.') continue
    const normalized = importerId.replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/$/, '')
    try {
      const workspaceRoot = resolveInside(dir, normalized, { mustExist: true })
      const manifest = readJson(join(workspaceRoot, 'package.json')) ?? {}
      workspaceDescriptors.set(normalized, {
        id: `workspace:${normalized}`,
        name: manifest.name ?? normalized,
        version: String(manifest.version ?? ''),
      })
    } catch (error) {
      failureRecorder.add({ reason: 'workspace-path-error', path: importerId, detail: error?.message })
    }
  }
  const importerEdges = []
  for (const [importerId, importer] of Object.entries(doc.importers)) {
    if (!isPlainMap(importer)) {
      failureRecorder.add({ reason: 'schema-error', path: lockfile, section: `importers.${importerId}` })
      continue
    }
    const normalizedImporter = importerId.replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/$/, '')
    const parentId = importerId === '.' ? null : workspaceDescriptors.get(normalizedImporter)?.id
    if (importerId !== '.' && !parentId) continue
    for (const [kind, dependencies] of [
      ['runtime', importer?.dependencies],
      ['optional', importer?.optionalDependencies],
      ['dev', importer?.devDependencies],
    ]) {
      for (const [name, value] of Object.entries(dependencies ?? {})) {
        if (!parentId) rootDirectNames.add(name)
        const target = workspaceTarget(normalizedImporter, value)
        if (target && (target === '..' || target.startsWith('../'))) {
          failureRecorder.add({ reason: 'workspace-path-error', path: `${importerId}:${name}` })
          continue
        }
        const id = target ? workspaceDescriptors.get(target)?.id : pnpmNodeId(snapshotReferenceIndex, name, value)
        if (!id) {
          failureRecorder.add({ reason: 'unresolved-dependency', from: `importer:${importerId}`, name })
          continue
        }
        if (parentId) {
          importerEdges.push({ from: parentId, to: id, name, kind })
        } else {
          const flags = directById.get(id) ?? { direct: true, dev: false, optional: false, requestedAs: new Set() }
          flags.dev ||= kind === 'dev'
          flags.optional ||= kind === 'optional'
          flags.requestedAs.add(name)
          directById.set(id, flags)
        }
      }
    }
  }

  const workspaceNodes = [...workspaceDescriptors.values()].map((workspace) => {
    const flags = directById.get(workspace.id) ?? {}
    return {
      ...workspace,
      ecosystem: 'pnpm',
      workspace: true,
      requestedAs: [...(flags.requestedAs ?? [])].filter((name) => name !== workspace.name).sort(),
      direct: Boolean(flags.direct),
      dev: Boolean(flags.dev),
      optional: Boolean(flags.optional),
      peer: false,
      integrity: null,
      resolved: null,
      hasInstallScript: null,
      requiresBuild: false,
      scripts: null,
      parents: [],
      children: [],
    }
  })
  const packageNodes = snapshots.map(([id]) => {
    const baseId = id.split('(')[0]
    const metadata = doc.packages[id] ?? doc.packages[baseId] ?? {}
    const identity = pnpmPackageIdentity(baseId, metadata)
    const flags = directById.get(id) ?? {}
    return {
      id,
      name: identity.name,
      version: identity.version,
      ecosystem: 'pnpm',
      requestedAs: [...(flags.requestedAs ?? [])].filter((name) => name !== identity.name).sort(),
      direct: Boolean(flags.direct),
      dev: Boolean(flags.dev || metadata.dev),
      optional: Boolean(flags.optional || metadata.optional),
      peer: id.includes('('),
      integrity: metadata.resolution?.integrity ?? null,
      resolved: metadata.resolution?.tarball ?? null,
      hasInstallScript: null,
      requiresBuild: Boolean(metadata.requiresBuild),
      scripts: null,
      parents: [],
      children: [],
    }
  })
  const nodes = [...workspaceNodes, ...packageNodes]
  const nodeById = new Map(nodes.map((node) => [node.id, node]))
  const edges = [...importerEdges]
  for (const edge of importerEdges) {
    nodeById.get(edge.from).children.push(edge.to)
    nodeById.get(edge.to).parents.push(edge.from)
  }
  for (const [parentId, snapshot] of snapshots) {
    for (const [kind, dependencies] of [
      ['runtime', snapshot?.dependencies],
      ['optional', snapshot?.optionalDependencies],
    ]) {
      for (const [name, value] of Object.entries(dependencies ?? {})) {
        const childId = pnpmNodeId(snapshotReferenceIndex, name, value)
        if (!childId) {
          failureRecorder.add({ reason: 'unresolved-dependency', from: parentId, name })
          continue
        }
        edges.push({ from: parentId, to: childId, name, kind })
        nodeById.get(parentId).children.push(childId)
        nodeById.get(childId).parents.push(parentId)
      }
    }
  }
  const graph = {
    ecosystem: 'pnpm',
    lockfile,
    lockfileVersion,
    root: { name: root.name ?? '', version: String(root.version ?? ''), directDependencies: rootDirectNames.size },
    nodes,
    edges,
    failures: failureRecorder.finish(),
  }
  graph.complete = graph.failures.length === 0
  const pathIndex = buildShortestPathIndex(graph)
  graph.buildRequirements = nodes
    .filter((node) => node.requiresBuild)
    .map((node) => ({
      id: node.id,
      name: node.name,
      version: node.version,
      evidence: 'pnpm-requires-build',
      dependencyPaths: [shortestDependencyPath(pathIndex, node.id, graph.root)].filter((path) => path.length > 0),
    }))
  return graph
}

/**
 * Build an exact npm package-lock v2/v3 graph. Unsupported lockfiles return
 * an explicit incomplete result instead of fabricated dependency counts.
 */
export function buildDependencyGraph(dir, {
  maxBytes = DEPENDENCY_LOCKFILE_MAX_BYTES,
  lockfileName = null,
  maxNodes = PNPM_GRAPH_MAX_NODES,
  maxEdges = PNPM_GRAPH_MAX_EDGES,
  maxLines = PNPM_LOCKFILE_MAX_LINES,
} = {}) {
  const lockPath = join(dir, 'package-lock.json')
  const tooLarge = (path, lockfile, ecosystem) => {
    try {
      const bytes = statSync(path).size
      if (bytes > maxBytes) {
        return {
          ecosystem,
          lockfile,
          nodes: [],
          edges: [],
          failures: [{ reason: 'lockfile-too-large', path: lockfile, bytes, maxBytes }],
          complete: false,
        }
      }
    } catch {
      // The parser reports an explicit read/parse failure below.
    }
    return null
  }
  if (lockfileName === 'pnpm-lock.yaml') {
    const pnpmPath = join(dir, 'pnpm-lock.yaml')
    if (!existsSync(pnpmPath)) {
      return { ecosystem: 'pnpm', lockfile: 'pnpm-lock.yaml', nodes: [], edges: [], failures: [{ reason: 'missing-lockfile', path: 'pnpm-lock.yaml' }], complete: false }
    }
    return tooLarge(pnpmPath, 'pnpm-lock.yaml', 'pnpm') ?? buildPnpmGraph(dir, { maxNodes, maxEdges, maxLines })
  }
  if (!existsSync(lockPath)) {
    const pnpmPath = join(dir, 'pnpm-lock.yaml')
    if (existsSync(pnpmPath)) {
      return tooLarge(pnpmPath, 'pnpm-lock.yaml', 'pnpm') ?? buildPnpmGraph(dir, { maxNodes, maxEdges, maxLines })
    }
    const unsupported = unsupportedLockfile(dir)
    return {
      ecosystem: unsupported?.startsWith('bun') ? 'bun' : unsupported?.startsWith('pnpm') ? 'pnpm' : 'yarn',
      lockfile: unsupported,
      nodes: [],
      edges: [],
      failures: [{ reason: unsupported ? 'unsupported-lockfile' : 'missing-lockfile', path: unsupported ?? 'package-lock.json' }],
      complete: false,
    }
  }
  const sizeFailure = tooLarge(lockPath, 'package-lock.json', 'npm')
  if (sizeFailure) return sizeFailure
  const doc = readJson(lockPath)
  if (!doc || ![2, 3].includes(doc.lockfileVersion) || !doc.packages || typeof doc.packages !== 'object') {
    return { ecosystem: 'npm', lockfile: 'package-lock.json', nodes: [], edges: [], failures: [{ reason: 'parse-error', path: 'package-lock.json' }], complete: false }
  }

  const root = doc.packages[''] ?? readJson(join(dir, 'package.json')) ?? {}
  const entries = Object.entries(doc.packages).filter(([key]) => key !== '')
  const byKey = new Map(entries.map(([key]) => [key, { key, ...doc.packages[key] }]))
  const nodes = entries.map(([key, entry]) => {
    const name = entry.name ?? packageNameFromKey(key)
    const kinds = dependencyKinds(root, name)
    return {
      id: key,
      name,
      version: String(entry.version ?? ''),
      ecosystem: 'npm',
      direct: kinds.direct,
      dev: Boolean(entry.dev || kinds.dev),
      optional: Boolean(entry.optional || kinds.optional),
      peer: Boolean(kinds.peer),
      integrity: entry.integrity ?? null,
      resolved: entry.resolved ?? null,
      hasInstallScript: Boolean(entry.hasInstallScript),
      scripts: entry.scripts ?? null,
      parents: [],
      children: [],
    }
  })
  const nodeByKey = new Map(nodes.map((node) => [node.id, node]))
  const edges = []
  const failures = []
  for (const [parentKey, entry] of byKey) {
    const dependencies = {
      ...(entry.dependencies ?? {}),
      ...(entry.optionalDependencies ?? {}),
      ...(entry.peerDependencies ?? {}),
    }
    for (const name of Object.keys(dependencies)) {
      const childKey = candidateKeys(parentKey, name).find((candidate) => nodeByKey.has(candidate))
      if (!childKey) {
        failures.push({ reason: 'unresolved-dependency', from: parentKey, name })
        continue
      }
      const parent = nodeByKey.get(parentKey)
      const child = nodeByKey.get(childKey)
      const edge = { from: parentKey, to: childKey, name, kind: entry.optionalDependencies?.[name] ? 'optional' : entry.peerDependencies?.[name] ? 'peer' : 'runtime' }
      edges.push(edge)
      parent.children.push(childKey)
      child.parents.push(parentKey)
    }
  }
  const graph = {
    ecosystem: 'npm',
    lockfile: 'package-lock.json',
    lockfileVersion: doc.lockfileVersion,
    root: { name: root.name ?? '', version: String(root.version ?? ''), directDependencies: directNames(root).size },
    nodes,
    edges,
    failures,
    complete: failures.length === 0,
  }
  const pathIndex = buildShortestPathIndex(graph)
  graph.buildRequirements = nodes
    .filter((node) => node.hasInstallScript)
    .map((node) => ({
      id: node.id,
      name: node.name,
      version: node.version,
      evidence: 'npm-has-install-script',
      dependencyPaths: [shortestDependencyPath(pathIndex, node.id, graph.root)].filter((path) => path.length > 0),
    }))
  return graph
}

export function dependencyPaths(graph, targetName) {
  const targetIds = (graph?.nodes ?? []).filter((node) => node.name === targetName).map((node) => node.id)
  const pathIndex = buildShortestPathIndex(graph)
  const paths = targetIds
    .sort()
    .map((id) => shortestDependencyPath(pathIndex, id, graph.root))
    .filter((path) => path.length > 0)
  const unique = new Map(paths.map((path) => [JSON.stringify(path), path]))
  return [...unique.values()]
}
