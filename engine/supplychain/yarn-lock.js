/** Normalize Yarn classic (v1) and Berry (v2-v4) lockfiles into a dependency graph. */

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { parseAllDocuments } from 'yaml'
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
  parseYarnDescriptor,
  parseYarnLocator,
  resolveAliasIdentity,
  splitSelectorList,
  unquoteYarnValue,
  versionSatisfies,
} from './lockfile-graph-utils.js'

const LOCKFILE = 'yarn.lock'
const BERRY_LOCKFILE_VERSIONS = /^(?:4|5|6|7|8)(?:\.|$)/

function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
  } catch {
    return null
  }
}

function readText(file, { maxLines = LOCKFILE_GRAPH_MAX_LINES } = {}) {
  let text
  try {
    text = readFileSync(file, 'utf8')
  } catch {
    return { error: { reason: 'read-error', path: LOCKFILE } }
  }
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1)
  const lines = text.length === 0 ? 0 : text.split(/\r\n|\r|\n/).length
  if (lines > maxLines) {
    return { error: { reason: 'lockfile-line-limit', path: LOCKFILE, lines, maxLines } }
  }
  return { text }
}

function emptyGraph(lockfileVersion = null) {
  return {
    ecosystem: 'yarn',
    lockfile: LOCKFILE,
    lockfileVersion,
    nodes: [],
    edges: [],
    failures: [],
    complete: false,
    buildRequirements: [],
  }
}

function detectFormat(text) {
  if (/^__metadata\s*:/m.test(text)) return 'berry'
  return 'classic'
}

function parseClassicDependency(line) {
  const trimmed = line.slice(4).trimEnd()
  if (!trimmed) return null
  let name = ''
  let rest = ''
  if (trimmed.startsWith('"') || trimmed.startsWith("'")) {
    const quote = trimmed[0]
    let escaped = false
    let end = -1
    for (let index = 1; index < trimmed.length; index += 1) {
      const character = trimmed[index]
      if (escaped) {
        escaped = false
        continue
      }
      if (character === '\\') {
        escaped = true
        continue
      }
      if (character === quote) {
        end = index
        break
      }
    }
    if (end < 0) return null
    name = unquoteYarnValue(trimmed.slice(0, end + 1))
    rest = trimmed.slice(end + 1).trim()
  } else {
    const separator = trimmed.search(/\s/)
    if (separator <= 0) return null
    name = trimmed.slice(0, separator)
    rest = trimmed.slice(separator + 1).trim()
  }
  if (!name || !rest) return null
  return { name, range: unquoteYarnValue(rest) }
}

/** Parse the indentation-sensitive Yarn classic format without guessing fields. */
function parseClassic(text) {
  const lines = text.split(/\r\n|\r|\n/)
  const rawEntries = []
  let current = null
  let section = null
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]
    if (!line.trim()) continue
    if (/^\s*#/.test(line)) continue
    if (/^\s/.test(line)) {
      if (!current) return { error: { reason: 'parse-error', path: LOCKFILE, line: index + 1 } }
      if (/^    /.test(line)) {
        if (section !== 'dependencies' && section !== 'optionalDependencies') {
          return { error: { reason: 'parse-error', path: LOCKFILE, line: index + 1 } }
        }
        const dependency = parseClassicDependency(line)
        if (!dependency) return { error: { reason: 'parse-error', path: LOCKFILE, line: index + 1 } }
        current[section][dependency.name] = dependency.range
        continue
      }
      const field = /^  ([^\s:]+)(?::(?:\s+(.*))?|\s+(.*))?$/.exec(line)
      if (!field) return { error: { reason: 'parse-error', path: LOCKFILE, line: index + 1 } }
      const key = field[1]
      if (key === 'dependencies' || key === 'optionalDependencies') {
        section = key
        continue
      }
      section = null
      current.fields[key] = unquoteYarnValue(field[2] ?? field[3] ?? '')
      continue
    }
    if (!line.endsWith(':')) return { error: { reason: 'parse-error', path: LOCKFILE, line: index + 1 } }
    const selectors = splitSelectorList(line.slice(0, -1)).map(unquoteYarnValue).filter(Boolean)
    if (selectors.length === 0) return { error: { reason: 'parse-error', path: LOCKFILE, line: index + 1 } }
    if (current) rawEntries.push(current)
    current = {
      line: index + 1,
      selectors,
      fields: {},
      dependencies: {},
      optionalDependencies: {},
    }
    section = null
  }
  if (current) rawEntries.push(current)
  if (rawEntries.length === 0) return { error: { reason: 'parse-error', path: LOCKFILE } }
  return { rawEntries, lockfileVersion: '1' }
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

function globToRegExp(pattern) {
  let source = '^'
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index]
    if (character === '*') {
      if (pattern[index + 1] === '*') {
        source += '.*'
        index += 1
      } else {
        source += '[^/]*'
      }
    } else if (character === '?') {
      source += '[^/]'
    } else {
      source += character.replace(/[|\\{}()[\]^$+?.]/g, '\\$&')
    }
  }
  return new RegExp(`${source}$`)
}

function staticGlobPrefix(pattern) {
  const wildcard = pattern.search(/[*?]/)
  const prefix = wildcard < 0 ? pattern : pattern.slice(0, wildcard)
  const slash = prefix.lastIndexOf('/')
  return slash < 0 ? '' : prefix.slice(0, slash)
}

function expandClassicWorkspaces(dir, manifest, failureRecorder, limitations) {
  const declared = Array.isArray(manifest?.workspaces)
    ? manifest.workspaces
    : Array.isArray(manifest?.workspaces?.packages)
      ? manifest.workspaces.packages
      : []
  const descriptors = new Map()
  const seenDirs = new Set()
  let visitedDirs = 0
  const maximumDirs = 5000

  const addManifest = (relativePath) => {
    const normalized = normalizeWorkspacePath(relativePath)
    if (!normalized || normalized === '.' || seenDirs.has(normalized)) return
    if (!workspacePathIsSafe(normalized)) {
      failureRecorder.add({ reason: 'workspace-path-error', path: normalized })
      return
    }
    seenDirs.add(normalized)
    if (!existsSync(join(dir, normalized))) return
    let workspaceRoot
    try {
      workspaceRoot = resolveInside(dir, normalized, { mustExist: true })
    } catch (error) {
      failureRecorder.add({ reason: 'workspace-path-error', path: normalized, detail: error?.message })
      return
    }
    try {
      if (!statSync(workspaceRoot).isDirectory()) return
    } catch (error) {
      failureRecorder.add({ reason: 'workspace-path-error', path: normalized, detail: error?.message })
      return
    }
    const workspaceManifest = readJson(join(workspaceRoot, 'package.json'))
    if (!workspaceManifest || typeof workspaceManifest !== 'object') {
      limitations.push(`workspace-manifest-missing:${normalized}`)
      return
    }
    const descriptor = {
      id: `workspace:${normalized}`,
      path: normalized,
      name: String(workspaceManifest.name ?? normalized),
      version: String(workspaceManifest.version ?? ''),
      manifest: workspaceManifest,
    }
    descriptors.set(normalized, descriptor)
  }

  const walk = (relativeRoot, matcher) => {
    if (visitedDirs >= maximumDirs) return
    let absoluteRoot
    try {
      absoluteRoot = relativeRoot
        ? resolveInside(dir, relativeRoot, { mustExist: true })
        : dir
    } catch {
      return
    }
    let entries
    try {
      entries = readdirSync(absoluteRoot, { withFileTypes: true })
    } catch {
      return
    }
    for (const entry of entries) {
      if (visitedDirs >= maximumDirs) return
      if (!entry.isDirectory()) continue
      if (entry.name === 'node_modules' || entry.name === '.git' || entry.name.startsWith('.')) continue
      const relativePath = relativeRoot ? `${relativeRoot}/${entry.name}` : entry.name
      visitedDirs += 1
      if (matcher(relativePath)) addManifest(relativePath)
      walk(relativePath, matcher)
    }
  }

  for (const patternValue of declared) {
    if (typeof patternValue !== 'string') {
      failureRecorder.add({ reason: 'schema-error', path: LOCKFILE, section: 'workspaces' })
      continue
    }
    const pattern = normalizeWorkspacePath(patternValue)
    if (!pattern || !workspacePathIsSafe(pattern)) {
      failureRecorder.add({ reason: 'workspace-path-error', path: String(patternValue) })
      continue
    }
    try {
      resolveInside(dir, pattern, { mustExist: false })
    } catch (error) {
      failureRecorder.add({ reason: 'workspace-path-error', path: String(patternValue), detail: error?.message })
      continue
    }
    if (!/[*?]/.test(pattern)) {
      addManifest(pattern)
      continue
    }
    const prefix = staticGlobPrefix(pattern)
    if (prefix) {
      if (!existsSync(join(dir, prefix))) continue
      try {
        resolveInside(dir, prefix, { mustExist: true })
      } catch (error) {
        failureRecorder.add({ reason: 'workspace-path-error', path: pattern, detail: error?.message })
        continue
      }
    }
    const matcher = globToRegExp(pattern)
    walk(prefix, (relativePath) => matcher.test(relativePath))
  }
  return descriptors
}

function workspaceBySpec(descriptors, name, value) {
  const byName = [...descriptors.values()].filter((workspace) => workspace.name === name)
  if (typeof value !== 'string') return null
  if (value.startsWith('workspace:')) {
    const payload = normalizeWorkspacePath(value.slice('workspace:'.length))
    if (!payload || payload === '*' || payload.startsWith('^') || payload.startsWith('~')) {
      return byName.length === 1 ? byName[0] : null
    }
    const target = normalizeWorkspacePath(payload)
    return descriptors.get(target) ?? (byName.length === 1 ? byName[0] : null)
  }
  if (value.startsWith('file:') || value.startsWith('link:') || value.startsWith('portal:')) {
    const target = normalizeWorkspacePath(value.slice(value.indexOf(':') + 1))
    return descriptors.get(target) ?? (byName.length === 1 ? byName[0] : null)
  }
  const workspace = byName.length === 1 ? byName[0] : null
  if (!workspace) return null
  if (versionSatisfies(workspace.version, value)) return workspace
  return null
}

function makeYarnNode(id, identity, flags = {}) {
  return {
    id,
    name: identity.name,
    version: identity.version,
    ecosystem: 'yarn',
    requestedAs: [],
    direct: false,
    dev: false,
    optional: false,
    peer: false,
    integrity: identity.integrity ?? null,
    resolved: identity.resolved ?? null,
    hasInstallScript: identity.hasInstallScript ?? null,
    requiresBuild: Boolean(identity.requiresBuild),
    scripts: identity.scripts ?? null,
    parents: [],
    children: [],
    ...flags,
  }
}

function buildClassic(dir, text, {
  maxNodes = LOCKFILE_GRAPH_MAX_NODES,
  maxEdges = LOCKFILE_GRAPH_MAX_EDGES,
} = {}) {
  const parsed = parseClassic(text)
  if (parsed.error) return { ...emptyGraph(null), failures: [parsed.error] }
  const failureRecorder = makeFailureRecorder(LOCKFILE_FAILURE_LIMIT, LOCKFILE)
  const root = readJson(join(dir, 'package.json')) ?? {}
  const limitations = []
  if (!root || Object.keys(root).length === 0) limitations.push('root-package-json-missing')

  const descriptors = new Map()
  const entries = []
  const entriesById = new Map()
  for (const raw of parsed.rawEntries) {
    if (!raw.fields.version) {
      return {
        ...emptyGraph('1'),
        failures: [{ reason: 'schema-error', path: LOCKFILE, section: `entry.${raw.selectors[0]}` }],
      }
    }
    const first = parseYarnDescriptor(raw.selectors[0])
    if (!first) {
      return {
        ...emptyGraph('1'),
        failures: [{ reason: 'schema-error', path: LOCKFILE, section: `entry.${raw.selectors[0]}` }],
      }
    }
    const alias = resolveAliasIdentity(first.name, first.range)
    const evidence = metadataScriptEvidence(raw.fields)
    const entry = {
      id: `${alias.name}@${raw.fields.version}`,
      name: alias.name,
      version: raw.fields.version,
      integrity: raw.fields.integrity ?? raw.fields.checksum ?? null,
      resolved: raw.fields.resolved ?? null,
      dependencies: raw.dependencies,
      optionalDependencies: raw.optionalDependencies,
      selectors: raw.selectors,
      ...evidence,
    }
    if (entriesById.has(entry.id)) {
      failureRecorder.add({ reason: 'duplicate-package-identity', path: LOCKFILE, id: entry.id })
      continue
    }
    entriesById.set(entry.id, entry)
    entries.push(entry)
    for (const selector of raw.selectors) {
      const descriptor = parseYarnDescriptor(selector)
      if (!descriptor) {
        failureRecorder.add({ reason: 'schema-error', path: LOCKFILE, section: `selector.${selector}` })
        continue
      }
      const previous = descriptors.get(descriptor.descriptor)
      if (previous && previous !== entry.id) {
        failureRecorder.add({ reason: 'ambiguous-dependency-descriptor', path: LOCKFILE, descriptor: descriptor.descriptor })
        continue
      }
      descriptors.set(descriptor.descriptor, entry.id)
    }
  }

  const workspaces = expandClassicWorkspaces(dir, root, failureRecorder, limitations)
  const workspaceNodes = [...workspaces.values()].map((workspace) => makeYarnNode(
    workspace.id,
    { name: workspace.name, version: workspace.version },
    { workspace: true },
  ))
  const packageNodes = entries.map((entry) => makeYarnNode(entry.id, entry))
  const nodes = [...workspaceNodes, ...packageNodes]
  const nodeById = new Map(nodes.map((node) => [node.id, node]))
  const edgeCount = entries.reduce((total, entry) => (
    total + Object.keys(entry.dependencies).length + Object.keys(entry.optionalDependencies).length
  ), 0) + [...workspaces.values()].reduce((total, workspace) => (
    total + Object.keys(workspace.manifest.dependencies ?? {}).length
    + Object.keys(workspace.manifest.optionalDependencies ?? {}).length
    + Object.keys(workspace.manifest.devDependencies ?? {}).length
  ), 0)
  if (nodes.length > maxNodes) {
    return { ...emptyGraph('1'), failures: [{ reason: 'graph-node-limit', path: LOCKFILE, nodes: nodes.length, maxNodes }] }
  }
  if (edgeCount > maxEdges) {
    return { ...emptyGraph('1'), failures: [{ reason: 'graph-edge-limit', path: LOCKFILE, edges: edgeCount, maxEdges }] }
  }

  const resolveTarget = (name, range) => {
    const workspace = workspaceBySpec(workspaces, name, range)
    if (workspace) return workspace.id
    return descriptors.get(`${name}@${range}`) ?? null
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

  for (const [kind, group] of [
    ['runtime', root.dependencies],
    ['optional', root.optionalDependencies],
    ['dev', root.devDependencies],
    ['peer', root.peerDependencies],
  ]) {
    for (const [name, range] of Object.entries(group ?? {})) {
      const target = resolveTarget(name, range)
      if (!target) {
        failureRecorder.add({ reason: 'unresolved-dependency', from: 'importer:.', name })
        continue
      }
      markDirect(target, name, kind)
    }
  }

  for (const workspace of workspaces.values()) {
    for (const [kind, group] of [
      ['runtime', workspace.manifest.dependencies],
      ['optional', workspace.manifest.optionalDependencies],
      ['dev', workspace.manifest.devDependencies],
      ['peer', workspace.manifest.peerDependencies],
    ]) {
      for (const [name, range] of Object.entries(group ?? {})) {
        const target = resolveTarget(name, range)
        if (!target) {
          failureRecorder.add({ reason: 'unresolved-dependency', from: workspace.id, name })
          continue
        }
        addEdge(workspace.id, target, name, kind)
        if (kind === 'dev') nodeById.get(target).dev = true
        if (kind === 'optional') nodeById.get(target).optional = true
      }
    }
  }

  for (const entry of entries) {
    for (const [kind, group] of [
      ['runtime', entry.dependencies],
      ['optional', entry.optionalDependencies],
    ]) {
      for (const [name, range] of Object.entries(group ?? {})) {
        const target = resolveTarget(name, range)
        if (!target) {
          failureRecorder.add({ reason: 'unresolved-dependency', from: entry.id, name })
          continue
        }
        addEdge(entry.id, target, name, kind)
        if (kind === 'optional') nodeById.get(target).optional = true
      }
    }
  }

  const graph = {
    ...emptyGraph('1'),
    root: {
      name: String(root.name ?? ''),
      version: String(root.version ?? ''),
      directDependencies: directNames(root).size,
    },
    nodes,
    edges,
    failures: failureRecorder.finish(),
    installScriptEvidence: installScriptEvidence(nodes, 'yarn'),
    limitations,
  }
  graph.complete = graph.failures.length === 0
  return attachBuildRequirements(
    graph,
    (node) => node.hasInstallScript === true || node.requiresBuild === true,
    (node) => (node.requiresBuild ? 'yarn-requires-build' : 'yarn-has-install-script'),
  )
}

function parseBerryDocument(text) {
  let documents
  try {
    documents = parseAllDocuments(text, { maxAliasCount: 100 })
  } catch {
    return { error: { reason: 'parse-error', path: LOCKFILE } }
  }
  let candidate = null
  let unsupportedVersion = null
  for (const document of documents) {
    if (document.errors.length > 0) return { error: { reason: 'parse-error', path: LOCKFILE } }
    let value
    try {
      value = document.toJS({ maxAliasCount: 100 })
    } catch {
      return { error: { reason: 'parse-error', path: LOCKFILE } }
    }
    if (!isPlainMap(value)) return { error: { reason: 'parse-error', path: LOCKFILE } }
    if (!isPlainMap(value.__metadata)) {
      return { error: { reason: 'schema-error', path: LOCKFILE, section: '__metadata' } }
    }
    const version = String(value.__metadata.version ?? '')
    if (!BERRY_LOCKFILE_VERSIONS.test(version)) {
      if (version && unsupportedVersion === null) unsupportedVersion = version
      continue
    }
    if (candidate) {
      return { error: { reason: 'ambiguous-lockfile-documents', path: LOCKFILE, candidates: 2 } }
    }
    candidate = { value, version }
  }
  if (candidate) return candidate
  if (unsupportedVersion !== null) {
    return { error: { reason: 'unsupported-lockfile-version', path: LOCKFILE, version: unsupportedVersion } }
  }
  return { error: { reason: 'parse-error', path: LOCKFILE } }
}

function validateBerrySchema(value) {
  for (const [key, entry] of Object.entries(value)) {
    if (key === '__metadata') continue
    if (!isPlainMap(entry)) return { reason: 'schema-error', path: LOCKFILE, section: key }
    for (const group of ['dependencies', 'optionalDependencies', 'devDependencies', 'peerDependencies']) {
      if (!Object.prototype.hasOwnProperty.call(entry, group)) continue
      if (!isPlainMap(entry[group])) {
        return { reason: 'schema-error', path: LOCKFILE, section: `${key}.${group}` }
      }
      for (const [name, range] of Object.entries(entry[group])) {
        if (typeof range !== 'string') {
          return { reason: 'schema-error', path: LOCKFILE, section: `${key}.${group}.${name}` }
        }
      }
    }
  }
  return null
}

function workspaceDescriptorFromBerry(dir, locator, entry, failureRecorder, limitations) {
  const path = normalizeWorkspacePath(locator.workspacePath)
  if (path === '.') return null
  if (!workspacePathIsSafe(path)) {
    failureRecorder.add({ reason: 'workspace-path-error', path })
    return null
  }
  try {
    resolveInside(dir, path, { mustExist: false })
  } catch (error) {
    failureRecorder.add({ reason: 'workspace-path-error', path, detail: error?.message })
    return null
  }
  const manifestPath = join(dir, path, 'package.json')
  const manifest = existsSync(manifestPath) ? readJson(manifestPath) : null
  if (!manifest) limitations.push(`workspace-manifest-missing:${path}`)
  return {
    id: `workspace:${path}`,
    path,
    name: String(manifest?.name ?? locator.actualName ?? path),
    version: String(manifest?.version ?? entry.version ?? ''),
    manifest: manifest ?? {},
    entry,
  }
}

function buildBerry(dir, text, {
  maxNodes = LOCKFILE_GRAPH_MAX_NODES,
  maxEdges = LOCKFILE_GRAPH_MAX_EDGES,
} = {}) {
  const parsed = parseBerryDocument(text)
  if (parsed.error) return { ...emptyGraph(parsed.error.version ?? null), failures: [parsed.error] }
  const schemaFailure = validateBerrySchema(parsed.value)
  if (schemaFailure) return { ...emptyGraph(parsed.version), failures: [schemaFailure] }
  const failureRecorder = makeFailureRecorder(LOCKFILE_FAILURE_LIMIT, LOCKFILE)
  const rootManifest = readJson(join(dir, 'package.json')) ?? {}
  const limitations = []
  if (!rootManifest || Object.keys(rootManifest).length === 0) limitations.push('root-package-json-missing')

  const descriptors = new Map()
  const workspaceByPath = new Map()
  const workspaceByName = new Map()
  const packageEntries = []
  const packageById = new Map()
  let rootEntry = null

  const mapDescriptor = (selector, id) => {
    const descriptor = parseYarnDescriptor(selector)
    if (!descriptor) {
      failureRecorder.add({ reason: 'schema-error', path: LOCKFILE, section: `selector.${selector}` })
      return
    }
    const previous = descriptors.get(descriptor.descriptor)
    if (previous && previous !== id) {
      failureRecorder.add({ reason: 'ambiguous-dependency-descriptor', path: LOCKFILE, descriptor: descriptor.descriptor })
      return
    }
    descriptors.set(descriptor.descriptor, id)
  }

  for (const [key, entry] of Object.entries(parsed.value)) {
    if (key === '__metadata') continue
    const selectors = splitSelectorList(key)
    if (selectors.length === 0) {
      return { ...emptyGraph(parsed.version), failures: [{ reason: 'schema-error', path: LOCKFILE, section: key }] }
    }
    for (const selector of selectors) {
      if (!parseYarnDescriptor(selector)) {
        return { ...emptyGraph(parsed.version), failures: [{ reason: 'schema-error', path: LOCKFILE, section: selector }] }
      }
    }
    const resolution = typeof entry.resolution === 'string' ? entry.resolution : null
    const locator = resolution ? parseYarnLocator(resolution) : null
    const first = parseYarnDescriptor(selectors[0])
    if (locator?.protocol === 'workspace') {
      const path = normalizeWorkspacePath(locator.workspacePath)
      if (path === '.') {
        rootEntry = { key, entry, locator, selectors }
        for (const selector of selectors) mapDescriptor(selector, '__root__')
        continue
      }
      const workspace = workspaceDescriptorFromBerry(dir, locator, entry, failureRecorder, limitations)
      if (!workspace) continue
      const existing = workspaceByPath.get(workspace.path)
      const workspaceEntry = existing ?? workspace
      if (!existing) {
        workspaceByPath.set(workspace.path, workspaceEntry)
        if (!workspaceByName.has(workspace.name)) workspaceByName.set(workspace.name, workspaceEntry)
      }
      for (const selector of selectors) mapDescriptor(selector, workspaceEntry.id)
      continue
    }

    const alias = locator
      ? { name: locator.actualName, version: entry.version ?? locator.actualVersion ?? '' }
      : resolveAliasIdentity(first.name, first.range)
    const version = String(entry.version ?? alias.version ?? '')
    const id = resolution ?? `${alias.name}@${version}`
    if (packageById.has(id)) {
      failureRecorder.add({ reason: 'duplicate-package-identity', path: LOCKFILE, id })
      for (const selector of selectors) mapDescriptor(selector, id)
      continue
    }
    const evidence = metadataScriptEvidence(entry)
    const packageEntry = {
      id,
      name: alias.name,
      version,
      integrity: entry.checksum ?? null,
      resolved: entry.resolved ?? null,
      dependencies: entry.dependencies ?? {},
      optionalDependencies: entry.optionalDependencies ?? {},
      devDependencies: entry.devDependencies ?? {},
      selectors,
      peer: /@virtual:/.test(resolution ?? '') || selectors.some((selector) => selector.includes('@virtual:')),
      ...evidence,
    }
    packageById.set(id, packageEntry)
    packageEntries.push(packageEntry)
    for (const selector of selectors) mapDescriptor(selector, id)
  }

  const workspaceNodes = [...workspaceByPath.values()].map((workspace) => makeYarnNode(
    workspace.id,
    { name: workspace.name, version: workspace.version },
    { workspace: true },
  ))
  const packageNodes = packageEntries.map((entry) => makeYarnNode(entry.id, entry))
  const nodes = [...workspaceNodes, ...packageNodes]
  const nodeById = new Map(nodes.map((node) => [node.id, node]))
  const edgeCount = packageEntries.reduce((total, entry) => (
    total + Object.keys(entry.dependencies).length
    + Object.keys(entry.optionalDependencies).length
    + Object.keys(entry.devDependencies).length
  ), 0) + [...workspaceByPath.values()].reduce((total, workspace) => (
    total + Object.keys(workspace.entry.dependencies ?? {}).length
    + Object.keys(workspace.entry.optionalDependencies ?? {}).length
    + Object.keys(workspace.entry.devDependencies ?? {}).length
  ), 0)
  if (nodes.length > maxNodes) {
    return {
      ...emptyGraph(parsed.version),
      failures: [{ reason: 'graph-node-limit', path: LOCKFILE, nodes: nodes.length, maxNodes }],
    }
  }
  if (edgeCount > maxEdges) {
    return {
      ...emptyGraph(parsed.version),
      failures: [{ reason: 'graph-edge-limit', path: LOCKFILE, edges: edgeCount, maxEdges }],
    }
  }

  const resolveTarget = (name, range) => {
    if (typeof range !== 'string') return null
    const direct = descriptors.get(`${name}@${range}`)
    if (direct) return direct
    if (!range.includes(':')) {
      const npm = descriptors.get(`${name}@npm:${range}`)
      if (npm) return npm
    }
    if (range.startsWith('workspace:')) {
      const path = normalizeWorkspacePath(range.slice('workspace:'.length))
      if (path === '.' || path === '*') return workspaceByName.get(name)?.id ?? null
      return workspaceByPath.get(path)?.id ?? workspaceByName.get(name)?.id ?? null
    }
    if (range.startsWith('link:') || range.startsWith('file:') || range.startsWith('portal:')) {
      const path = normalizeWorkspacePath(range.slice(range.indexOf(':') + 1))
      return workspaceByPath.get(path)?.id ?? workspaceByName.get(name)?.id ?? null
    }
    const local = workspaceByName.get(name)
    if (local && versionSatisfies(local.version, range)) return local.id
    return null
  }

  const markDirect = (targetId, name, kind) => {
    if (targetId === '__root__') return
    const node = nodeById.get(targetId)
    if (!node) return
    node.direct = true
    node.dev ||= kind === 'dev'
    node.optional ||= kind === 'optional'
    node.peer ||= kind === 'peer'
    if (name !== node.name) node.requestedAs = [...new Set([...node.requestedAs, name])].sort()
  }
  const addEdge = (from, to, name, kind) => {
    edges.push({ from, to, name, kind })
    nodeById.get(from)?.children.push(to)
    nodeById.get(to)?.parents.push(from)
  }
  const edges = []

  const rootEntryGroups = rootEntry
    ? [
      ['runtime', rootEntry.entry.dependencies],
      ['optional', rootEntry.entry.optionalDependencies],
      ['dev', rootEntry.entry.devDependencies],
      ['peer', rootEntry.entry.peerDependencies],
    ]
    : []
  const rootGroups = rootEntryGroups.some(([, group]) => group && Object.keys(group).length > 0)
    ? rootEntryGroups
    : [
      ['runtime', rootManifest.dependencies],
      ['optional', rootManifest.optionalDependencies],
      ['dev', rootManifest.devDependencies],
      ['peer', rootManifest.peerDependencies],
    ]
  const usedLockfileRootGroups = rootEntryGroups.some(([, group]) => group && Object.keys(group).length > 0)
  if (!rootEntry) limitations.push('root-workspace-entry-missing')
  else if (!usedLockfileRootGroups) limitations.push('root-workspace-dependencies-missing')
  const rootDeclarationNames = new Set()
  for (const [kind, group] of rootGroups) {
    for (const [name, range] of Object.entries(group ?? {})) {
      rootDeclarationNames.add(name)
      const target = resolveTarget(name, range)
      if (!target) {
        failureRecorder.add({ reason: 'unresolved-dependency', from: 'importer:.', name })
        continue
      }
      const manifestKind = dependencyKinds(rootManifest, name)
      const edgeKind = manifestKind.dev && kind !== 'optional' ? 'dev'
        : manifestKind.optional && kind !== 'dev' ? 'optional'
          : manifestKind.peer && kind === 'peer' ? 'peer'
            : kind
      markDirect(target, name, edgeKind)
    }
  }

  for (const workspace of workspaceByPath.values()) {
    const manifest = workspace.manifest ?? {}
    for (const [kind, group] of [
      ['runtime', workspace.entry.dependencies],
      ['optional', workspace.entry.optionalDependencies],
      ['dev', workspace.entry.devDependencies],
      ['peer', workspace.entry.peerDependencies],
    ]) {
      for (const [name, range] of Object.entries(group ?? {})) {
        const target = resolveTarget(name, range)
        if (!target) {
          failureRecorder.add({ reason: 'unresolved-dependency', from: workspace.id, name })
          continue
        }
        const manifestKind = dependencyKinds(manifest, name)
        const edgeKind = manifestKind.dev && kind !== 'optional' ? 'dev'
          : manifestKind.optional && kind !== 'dev' ? 'optional'
            : manifestKind.peer && kind === 'peer' ? 'peer'
              : kind
        addEdge(workspace.id, target, name, edgeKind)
        if (edgeKind === 'dev') nodeById.get(target).dev = true
        if (edgeKind === 'optional') nodeById.get(target).optional = true
      }
    }
  }

  for (const entry of packageEntries) {
    for (const [kind, group] of [
      ['runtime', entry.dependencies],
      ['optional', entry.optionalDependencies],
    ]) {
      for (const [name, range] of Object.entries(group ?? {})) {
        const target = resolveTarget(name, range)
        if (!target || target === '__root__') {
          failureRecorder.add({ reason: 'unresolved-dependency', from: entry.id, name })
          continue
        }
        addEdge(entry.id, target, name, kind)
        if (kind === 'optional') nodeById.get(target).optional = true
      }
    }
  }

  const graph = {
    ...emptyGraph(parsed.version),
    root: {
      name: String(rootManifest.name ?? rootEntry?.locator?.actualName ?? ''),
      version: String(rootManifest.version ?? rootEntry?.entry?.version ?? ''),
      directDependencies: usedLockfileRootGroups ? rootDeclarationNames.size : directNames(rootManifest).size,
    },
    nodes,
    edges,
    failures: failureRecorder.finish(),
    installScriptEvidence: installScriptEvidence(nodes, 'yarn'),
    limitations,
  }
  graph.complete = graph.failures.length === 0
  return attachBuildRequirements(
    graph,
    (node) => node.hasInstallScript === true || node.requiresBuild === true,
    (node) => (node.requiresBuild ? 'yarn-requires-build' : 'yarn-has-install-script'),
  )
}

export function buildYarnGraph(dir, options = {}) {
  const loaded = readText(join(dir, LOCKFILE), options)
  if (loaded.error) return { ...emptyGraph(null), failures: [loaded.error] }
  if (detectFormat(loaded.text) === 'berry') return buildBerry(dir, loaded.text, options)
  const headerVersion = /^#\s*yarn lockfile v(\S+)/m.exec(loaded.text)?.[1] ?? null
  if (headerVersion && headerVersion !== '1') {
    return {
      ...emptyGraph(headerVersion),
      failures: [{
        reason: 'unsupported-lockfile-version',
        path: LOCKFILE,
        version: headerVersion,
      }],
    }
  }
  return buildClassic(dir, loaded.text, options)
}
