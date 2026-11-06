/** Normalize Bun text lockfiles (JSONC) and explicitly degrade binary bun.lockb. */

import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { resolveInside } from '../path-safety.js'
import {
  LOCKFILE_FAILURE_LIMIT,
  LOCKFILE_GRAPH_MAX_EDGES,
  LOCKFILE_GRAPH_MAX_LINES,
  LOCKFILE_GRAPH_MAX_NODES,
  attachBuildRequirements,
  dependencyKinds,
  directNames,
  installScriptEvidence,
  isPlainMap,
  makeFailureRecorder,
  metadataScriptEvidence,
  parseYarnLocator,
  versionSatisfies,
} from './lockfile-graph-utils.js'

const BUN_TEXT_LOCKFILE = 'bun.lock'
const BUN_BINARY_LOCKFILE = 'bun.lockb'
const SUPPORTED_BUN_LOCKFILE_VERSIONS = /^(?:1|2)(?:\.|$)/

function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
  } catch {
    return null
  }
}

function emptyGraph(lockfile, lockfileVersion = null) {
  return {
    ecosystem: 'bun',
    lockfile,
    lockfileVersion,
    nodes: [],
    edges: [],
    failures: [],
    complete: false,
    buildRequirements: [],
  }
}

function normalizeWorkspacePath(value) {
  return String(value ?? '')
    .replace(/\\/g, '/')
    .replace(/^\.\//, '')
    .replace(/\/+$/, '')
}

function workspacePathIsSafe(candidate) {
  if (!candidate || candidate === '.' || candidate === '..') return candidate === '.'
  if (candidate.startsWith('/') || /^[A-Za-z]:/.test(candidate)) return false
  return !candidate.split('/').includes('..')
}

/** Remove // and block comments without touching strings. */
function stripJsonComments(text) {
  let output = ''
  let inString = false
  let escaped = false
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index]
    if (inString) {
      output += character
      if (escaped) escaped = false
      else if (character === '\\') escaped = true
      else if (character === '"') inString = false
      continue
    }
    if (character === '"') {
      inString = true
      output += character
      continue
    }
    if (character === '/' && text[index + 1] === '/') {
      while (index < text.length && text[index] !== '\n') index += 1
      output += '\n'
      continue
    }
    if (character === '/' && text[index + 1] === '*') {
      index += 2
      while (index < text.length && !(text[index] === '*' && text[index + 1] === '/')) {
        if (text[index] === '\n') output += '\n'
        index += 1
      }
      index += 1
      continue
    }
    output += character
  }
  return output
}

/** Bun emits trailing commas (JSONC); remove only commas outside strings. */
function stripTrailingCommas(text) {
  let output = ''
  let inString = false
  let escaped = false
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index]
    if (inString) {
      output += character
      if (escaped) escaped = false
      else if (character === '\\') escaped = true
      else if (character === '"') inString = false
      continue
    }
    if (character === '"') {
      inString = true
      output += character
      continue
    }
    if (character === ',') {
      let lookahead = index + 1
      while (lookahead < text.length && /\s/.test(text[lookahead])) lookahead += 1
      if (text[lookahead] === ']' || text[lookahead] === '}') continue
    }
    output += character
  }
  return output
}

function parseBunJsonc(text) {
  try {
    return { value: JSON.parse(stripTrailingCommas(stripJsonComments(text))) }
  } catch {
    return { error: { reason: 'parse-error', path: BUN_TEXT_LOCKFILE } }
  }
}

function parseBunIdentity(value) {
  const locator = parseYarnLocator(value)
  if (!locator) return null
  if (locator.protocol === 'workspace') {
    return {
      workspacePath: normalizeWorkspacePath(locator.workspacePath),
      name: locator.actualName,
      version: null,
    }
  }
  return { name: locator.actualName ?? locator.name, version: locator.actualVersion ?? null }
}

function normalizeDependencyGroups(source) {
  return [
    ['runtime', source?.dependencies],
    ['optional', source?.optionalDependencies],
    ['dev', source?.devDependencies],
    ['peer', source?.peerDependencies],
  ]
}

function workspaceBySpec(workspaces, name, value) {
  if (typeof value !== 'string') return null
  if (value.startsWith('workspace:')) {
    const payload = normalizeWorkspacePath(value.slice('workspace:'.length))
    if (!payload || payload === '*' || payload.startsWith('^') || payload.startsWith('~')) {
      return workspaces.byName.get(name) ?? null
    }
    return workspaces.byPath.get(payload) ?? workspaces.byName.get(name) ?? null
  }
  if (value.startsWith('link:') || value.startsWith('file:') || value.startsWith('portal:')) {
    const payload = normalizeWorkspacePath(value.slice(value.indexOf(':') + 1))
    return workspaces.byPath.get(payload) ?? workspaces.byName.get(name) ?? null
  }
  const workspace = workspaces.byName.get(name)
  if (!workspace) return null
  if (versionSatisfies(workspace.version, value)) return workspace
  return null
}

function buildTextGraph(dir, text, {
  maxNodes = LOCKFILE_GRAPH_MAX_NODES,
  maxEdges = LOCKFILE_GRAPH_MAX_EDGES,
} = {}) {
  const lockfile = BUN_TEXT_LOCKFILE
  const parsed = parseBunJsonc(text)
  if (parsed.error) return { ...emptyGraph(lockfile), failures: [parsed.error] }
  const doc = parsed.value
  if (!isPlainMap(doc)) {
    return { ...emptyGraph(lockfile), failures: [{ reason: 'parse-error', path: lockfile }] }
  }
  const version = String(doc.lockfileVersion ?? '')
  if (!version) {
    return {
      ...emptyGraph(lockfile),
      failures: [{ reason: 'schema-error', path: lockfile, section: 'lockfileVersion' }],
    }
  }
  if (!SUPPORTED_BUN_LOCKFILE_VERSIONS.test(version)) {
    return {
      ...emptyGraph(lockfile, version),
      failures: [{ reason: 'unsupported-lockfile-version', path: lockfile, version }],
    }
  }
  if (!isPlainMap(doc.packages)) {
    return {
      ...emptyGraph(lockfile, version),
      failures: [{ reason: 'schema-error', path: lockfile, section: 'packages' }],
    }
  }
  const workspaceSections = doc.workspaces ?? {}
  if (!isPlainMap(workspaceSections)) {
    return {
      ...emptyGraph(lockfile, version),
      failures: [{ reason: 'schema-error', path: lockfile, section: 'workspaces' }],
    }
  }
  for (const [path, workspace] of Object.entries(workspaceSections)) {
    if (!isPlainMap(workspace)) {
      return {
        ...emptyGraph(lockfile, version),
        failures: [{ reason: 'schema-error', path: lockfile, section: `workspaces.${path}` }],
      }
    }
    for (const [group, value] of normalizeDependencyGroups(workspace)) {
      if (value === undefined) continue
      if (!isPlainMap(value)) {
        return {
          ...emptyGraph(lockfile, version),
          failures: [{ reason: 'schema-error', path: lockfile, section: `workspaces.${path}.${group}` }],
        }
      }
      for (const [name, range] of Object.entries(value)) {
        if (typeof range !== 'string') {
          return {
            ...emptyGraph(lockfile, version),
            failures: [{ reason: 'schema-error', path: lockfile, section: `workspaces.${path}.${group}.${name}` }],
          }
        }
      }
    }
  }
  for (const [key, tuple] of Object.entries(doc.packages)) {
    if (!Array.isArray(tuple) || typeof tuple[0] !== 'string' || (tuple[2] !== undefined && !isPlainMap(tuple[2]))) {
      return {
        ...emptyGraph(lockfile, version),
        failures: [{ reason: 'schema-error', path: lockfile, section: `packages.${key}` }],
      }
    }
    if (isPlainMap(tuple[2])) {
      for (const [group, value] of normalizeDependencyGroups(tuple[2])) {
        if (value === undefined) continue
        if (!isPlainMap(value)) {
          return {
            ...emptyGraph(lockfile, version),
            failures: [{ reason: 'schema-error', path: lockfile, section: `packages.${key}.${group}` }],
          }
        }
        for (const [name, range] of Object.entries(value)) {
          if (typeof range !== 'string') {
            return {
              ...emptyGraph(lockfile, version),
              failures: [{ reason: 'schema-error', path: lockfile, section: `packages.${key}.${group}.${name}` }],
            }
          }
        }
      }
    }
  }

  const failureRecorder = makeFailureRecorder(LOCKFILE_FAILURE_LIMIT, lockfile)
  const rootManifest = readJson(join(dir, 'package.json')) ?? {}
  const limitations = []
  if (!rootManifest || Object.keys(rootManifest).length === 0) limitations.push('root-package-json-missing')
  const workspaces = { byPath: new Map(), byName: new Map() }

  for (const [pathValue, workspace] of Object.entries(workspaceSections)) {
    const path = normalizeWorkspacePath(pathValue)
    if (path === '') continue
    if (!workspacePathIsSafe(path)) {
      failureRecorder.add({ reason: 'workspace-path-error', path: pathValue })
      continue
    }
    try {
      resolveInside(dir, path, { mustExist: false })
    } catch (error) {
      failureRecorder.add({ reason: 'workspace-path-error', path: pathValue, detail: error?.message })
      continue
    }
    const manifestPath = join(dir, path, 'package.json')
    const manifest = existsSync(manifestPath) ? readJson(manifestPath) : null
    if (!manifest) limitations.push(`workspace-manifest-missing:${path}`)
    const descriptor = {
      id: `workspace:${path}`,
      path,
      name: String(workspace.name ?? manifest?.name ?? path),
      version: String(workspace.version ?? manifest?.version ?? ''),
      workspace,
    }
    workspaces.byPath.set(path, descriptor)
    if (!workspaces.byName.has(descriptor.name)) workspaces.byName.set(descriptor.name, descriptor)
  }

  const packageByKey = new Map()
  for (const [key, tuple] of Object.entries(doc.packages)) {
    const identity = parseBunIdentity(tuple[0])
    if (!identity) {
      return {
        ...emptyGraph(lockfile, version),
        failures: [{ reason: 'schema-error', path: lockfile, section: `packages.${key}` }],
      }
    }
    if (identity.workspacePath) {
      if (identity.workspacePath !== '' && !workspaces.byPath.has(identity.workspacePath)) {
        if (!workspacePathIsSafe(identity.workspacePath)) {
          failureRecorder.add({ reason: 'workspace-path-error', path: identity.workspacePath })
          continue
        }
        try {
          resolveInside(dir, identity.workspacePath, { mustExist: false })
        } catch (error) {
          failureRecorder.add({ reason: 'workspace-path-error', path: identity.workspacePath, detail: error?.message })
          continue
        }
        const manifestPath = join(dir, identity.workspacePath, 'package.json')
        const manifest = existsSync(manifestPath) ? readJson(manifestPath) : null
        if (!manifest) limitations.push(`workspace-manifest-missing:${identity.workspacePath}`)
        const descriptor = {
          id: `workspace:${identity.workspacePath}`,
          path: identity.workspacePath,
          name: String(manifest?.name ?? identity.name ?? identity.workspacePath),
          version: String(manifest?.version ?? ''),
          workspace: {},
        }
        workspaces.byPath.set(identity.workspacePath, descriptor)
        if (!workspaces.byName.has(descriptor.name)) workspaces.byName.set(descriptor.name, descriptor)
      }
      continue
    }
    const metadata = tuple[2] ?? {}
    const evidence = metadataScriptEvidence(metadata)
    packageByKey.set(key, {
      key,
      name: identity.name,
      version: String(identity.version ?? ''),
      integrity: typeof tuple[3] === 'string' ? tuple[3] : null,
      resolved: typeof tuple[1] === 'string' && tuple[1] ? tuple[1] : null,
      metadata,
      peer: isPlainMap(metadata.peerDependencies) && Object.keys(metadata.peerDependencies).length > 0,
      ...evidence,
    })
  }

  const workspaceNodes = [...workspaces.byPath.values()].map((workspace) => ({
    id: workspace.id,
    name: workspace.name,
    version: workspace.version,
    ecosystem: 'bun',
    workspace: true,
    requestedAs: [],
    direct: false,
    dev: false,
    optional: false,
    peer: false,
    integrity: null,
    resolved: null,
    hasInstallScript: null,
    requiresBuild: false,
    scripts: null,
    parents: [],
    children: [],
  }))
  const packageNodes = [...packageByKey.values()].map((entry) => ({
    id: entry.key,
    name: entry.name,
    version: entry.version,
    ecosystem: 'bun',
    requestedAs: [],
    direct: false,
    dev: false,
    optional: false,
    peer: Boolean(entry.peer),
    integrity: entry.integrity,
    resolved: entry.resolved,
    hasInstallScript: entry.hasInstallScript,
    requiresBuild: Boolean(entry.requiresBuild),
    scripts: entry.scripts,
    parents: [],
    children: [],
  }))
  const nodes = [...workspaceNodes, ...packageNodes]
  const nodeById = new Map(nodes.map((node) => [node.id, node]))
  const edgeCount = [...workspaces.byPath.values()].reduce((total, workspace) => {
    let count = total
    for (const [kind, group] of normalizeDependencyGroups(workspace.workspace)) {
      if (kind === 'peer') continue
      count += Object.keys(group ?? {}).length
    }
    return count
  }, 0) + [...packageByKey.values()].reduce((total, entry) => (
    total
    + Object.keys(entry.metadata.dependencies ?? {}).length
    + Object.keys(entry.metadata.optionalDependencies ?? {}).length
  ), 0)
  if (nodes.length > maxNodes) {
    return {
      ...emptyGraph(lockfile, version),
      failures: [{ reason: 'graph-node-limit', path: lockfile, nodes: nodes.length, maxNodes }],
    }
  }
  if (edgeCount > maxEdges) {
    return {
      ...emptyGraph(lockfile, version),
      failures: [{ reason: 'graph-edge-limit', path: lockfile, edges: edgeCount, maxEdges }],
    }
  }

  const resolvePackage = (parentKey, name) => {
    const candidates = []
    if (parentKey) candidates.push(`${parentKey}/${name}`)
    candidates.push(name)
    return candidates.find((candidate) => packageByKey.has(candidate)) ?? null
  }
  const resolveTarget = (name, range, parentKey = null) => {
    const workspace = workspaceBySpec(workspaces, name, range)
    if (workspace) return workspace.id
    return resolvePackage(parentKey, name)
  }
  const markDirect = (targetId, name, kind) => {
    const node = nodeById.get(targetId)
    if (!node) return
    node.direct = true
    node.dev ||= kind === 'dev'
    node.optional ||= kind === 'optional'
    node.peer ||= kind === 'peer'
    if (name !== node.name) node.requestedAs = [...new Set([...node.requestedAs, name])].sort()
  }
  const edges = []
  const addEdge = (from, to, name, kind) => {
    edges.push({ from, to, name, kind })
    nodeById.get(from)?.children.push(to)
    nodeById.get(to)?.parents.push(from)
  }

  const rootWorkspace = workspaceSections[''] ?? {}
  const rootGroups = normalizeDependencyGroups(rootWorkspace)
  const hasRootLockGroups = rootGroups.some(([, group]) => group && Object.keys(group).length > 0)
  const effectiveRootGroups = hasRootLockGroups
    ? rootGroups
    : normalizeDependencyGroups(rootManifest)
  const rootNames = new Set()
  for (const [kind, group] of effectiveRootGroups) {
    for (const [name, range] of Object.entries(group ?? {})) {
      rootNames.add(name)
      const target = resolveTarget(name, range)
      if (!target) {
        failureRecorder.add({ reason: 'unresolved-dependency', from: 'importer:.', name })
        continue
      }
      markDirect(target, name, kind)
    }
  }

  for (const workspace of workspaces.byPath.values()) {
    for (const [kind, group] of normalizeDependencyGroups(workspace.workspace)) {
      for (const [name, range] of Object.entries(group ?? {})) {
        const target = resolveTarget(name, range)
        if (!target) {
          if (kind === 'peer') continue
          failureRecorder.add({ reason: 'unresolved-dependency', from: workspace.id, name })
          continue
        }
        if (kind === 'peer') continue
        addEdge(workspace.id, target, name, kind)
        if (kind === 'dev') nodeById.get(target).dev = true
        if (kind === 'optional') nodeById.get(target).optional = true
      }
    }
  }

  for (const entry of packageByKey.values()) {
    for (const [kind, group] of normalizeDependencyGroups(entry.metadata)) {
      for (const [name, range] of Object.entries(group ?? {})) {
        if (kind === 'peer') continue
        const target = resolvePackage(entry.key, name)
        if (!target) {
          failureRecorder.add({ reason: 'unresolved-dependency', from: entry.key, name })
          continue
        }
        addEdge(entry.key, target, name, kind)
        if (kind === 'optional') nodeById.get(target).optional = true
      }
    }
  }

  const graph = {
    ...emptyGraph(lockfile, version),
    root: {
      name: String(rootWorkspace.name ?? rootManifest.name ?? ''),
      version: String(rootWorkspace.version ?? rootManifest.version ?? ''),
      directDependencies: rootNames.size || directNames(rootManifest).size,
    },
    nodes,
    edges,
    failures: failureRecorder.finish(),
    installScriptEvidence: installScriptEvidence(nodes, 'bun'),
    limitations,
  }
  graph.complete = graph.failures.length === 0
  return attachBuildRequirements(
    graph,
    (node) => node.hasInstallScript === true || node.requiresBuild === true,
    (node) => (node.requiresBuild ? 'bun-requires-build' : 'bun-has-install-script'),
  )
}

function readBinaryGraph(file) {
  let buffer
  try {
    buffer = readFileSync(file)
  } catch {
    return { ...emptyGraph(BUN_BINARY_LOCKFILE), failures: [{ reason: 'read-error', path: BUN_BINARY_LOCKFILE }] }
  }
  const header = buffer.subarray(0, 256).toString('utf8')
  const lines = header.split('\n')
  const formatLine = lines.find((line) => /^bun-lockfile-format-v\d+$/.test(line.trim()))
  if (lines[0]?.trim() !== '#!/usr/bin/env bun' || !formatLine) {
    return {
      ...emptyGraph(BUN_BINARY_LOCKFILE, null),
      failures: [{
        reason: 'unsupported-binary-lockfile',
        path: BUN_BINARY_LOCKFILE,
        format: null,
        detail: 'unrecognized-binary-lockfile-header',
      }],
      degraded: true,
      format: null,
    }
  }
  const format = formatLine.trim()
  return {
    ...emptyGraph(BUN_BINARY_LOCKFILE, format.replace('bun-lockfile-format-', '')),
    failures: [{
      reason: 'unsupported-binary-lockfile',
      path: BUN_BINARY_LOCKFILE,
      format,
      detail: 'binary-lockfile-is-recognized-but-not-decoded',
    }],
    degraded: true,
    format,
    limitations: ['binary-lockfile-not-decoded'],
    installScriptEvidence: {
      status: 'unavailable',
      reason: 'bun-binary-lockfile-not-decoded',
    },
  }
}

export function buildBunGraph(dir, {
  lockfileName = BUN_TEXT_LOCKFILE,
  maxLines = LOCKFILE_GRAPH_MAX_LINES,
  ...options
} = {}) {
  if (lockfileName === BUN_BINARY_LOCKFILE) return readBinaryGraph(join(dir, BUN_BINARY_LOCKFILE))
  let text
  try {
    text = readFileSync(join(dir, BUN_TEXT_LOCKFILE), 'utf8')
  } catch {
    return { ...emptyGraph(BUN_TEXT_LOCKFILE), failures: [{ reason: 'read-error', path: BUN_TEXT_LOCKFILE }] }
  }
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1)
  const lines = text.length === 0 ? 0 : text.split(/\r\n|\r|\n/).length
  if (lines > maxLines) {
    return {
      ...emptyGraph(BUN_TEXT_LOCKFILE),
      failures: [{ reason: 'lockfile-line-limit', path: BUN_TEXT_LOCKFILE, lines, maxLines }],
    }
  }
  return buildTextGraph(dir, text, options)
}
