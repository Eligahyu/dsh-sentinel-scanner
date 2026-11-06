/** Shared, parser-agnostic helpers for normalized dependency graphs. */

export const LOCKFILE_GRAPH_MAX_NODES = 20_000
export const LOCKFILE_GRAPH_MAX_EDGES = 100_000
export const LOCKFILE_GRAPH_MAX_LINES = 100_000
export const LOCKFILE_FAILURE_LIMIT = 1000

const LIFECYCLE_SCRIPTS = new Set([
  'preinstall',
  'install',
  'postinstall',
  'prepare',
  'prepublish',
])

export function isPlainMap(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

export function directNames(root) {
  return new Set([
    ...Object.keys(root?.dependencies ?? {}),
    ...Object.keys(root?.optionalDependencies ?? {}),
    ...Object.keys(root?.peerDependencies ?? {}),
    ...Object.keys(root?.devDependencies ?? {}),
  ])
}

export function dependencyKinds(root, name) {
  return {
    direct: directNames(root).has(name),
    dev: Object.prototype.hasOwnProperty.call(root?.devDependencies ?? {}, name),
    optional: Object.prototype.hasOwnProperty.call(root?.optionalDependencies ?? {}, name),
    peer: Object.prototype.hasOwnProperty.call(root?.peerDependencies ?? {}, name),
  }
}

export function makeFailureRecorder(limit = LOCKFILE_FAILURE_LIMIT, path = 'lockfile') {
  const failures = []
  let dropped = 0
  return {
    add(failure) {
      if (failures.length < Math.max(0, limit - 1)) failures.push(failure)
      else dropped += 1
    },
    finish() {
      if (dropped > 0) {
        failures.push({ reason: 'failure-truncated', path, dropped, maxFailures: limit })
      }
      return failures
    },
  }
}

export function pathLabel(node) {
  return node.peer ? node.id : `${node.name}@${node.version}`
}

export function buildShortestPathIndex(graph) {
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
      predecessor.set(child, child === id ? null : id)
      queue.push(child)
    }
  }
  return { nodeById, predecessor, distance }
}

export function shortestDependencyPath(index, targetId, root) {
  if (!index.distance.has(targetId)) return []
  const ids = []
  for (let current = targetId; current !== null; current = index.predecessor.get(current)) {
    ids.push(current)
  }
  const labels = ids.reverse().map((id) => pathLabel(index.nodeById.get(id)))
  if (root?.name) labels.unshift(`${root.name}@${root.version ?? ''}`)
  return labels
}

/**
 * Attach install-script/build evidence with a shortest root-to-package chain.
 * `evidence` may be a string or a function receiving the node.
 */
export function attachBuildRequirements(graph, predicate, evidence) {
  if (typeof graph.complete === 'boolean' && graph.complete === false) {
    graph.buildRequirements = []
    return graph
  }
  const pathIndex = buildShortestPathIndex(graph)
  const evidenceFor = typeof evidence === 'function' ? evidence : () => evidence
  graph.buildRequirements = graph.nodes
    .filter(predicate)
    .map((node) => ({
      id: node.id,
      name: node.name,
      version: node.version,
      evidence: evidenceFor(node),
      dependencyPaths: [shortestDependencyPath(pathIndex, node.id, graph.root)]
        .filter((path) => path.length > 0),
    }))
  return graph
}

/** Split a comma-separated Yarn selector list without breaking quoted commas. */
export function splitSelectorList(value) {
  const text = String(value)
  const parts = []
  let current = ''
  let quote = null
  let escaped = false
  for (const character of text) {
    if (escaped) {
      current += character
      escaped = false
      continue
    }
    if (quote) {
      if (character === '\\') escaped = true
      else if (character === quote) quote = null
      current += character
      continue
    }
    if (character === '"' || character === "'") {
      quote = character
      current += character
      continue
    }
    if (character === ',') {
      if (current.trim()) parts.push(current.trim())
      current = ''
      continue
    }
    current += character
  }
  if (current.trim()) parts.push(current.trim())
  return parts
}

/** Decode the quoted values used by the Yarn classic lockfile. */
export function unquoteYarnValue(value) {
  const text = String(value ?? '').trim()
  if (text.length < 2) return text
  const first = text[0]
  const last = text[text.length - 1]
  if (first === '"' && last === '"') {
    try {
      return JSON.parse(text)
    } catch {
      return text.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\')
    }
  }
  if (first === "'" && last === "'") return text.slice(1, -1).replace(/\\'/g, "'")
  return text
}

/** Parse `name@range` while retaining scoped package names. */
export function parseYarnDescriptor(value) {
  let text
  try {
    text = unquoteYarnValue(value)
  } catch {
    return null
  }
  if (!text) return null
  const separator = text.startsWith('@') ? text.indexOf('@', 1) : text.indexOf('@')
  if (separator <= 0) return null
  const name = text.slice(0, separator)
  const range = text.slice(separator + 1)
  if (!name || !range) return null
  return { name, range, descriptor: `${name}@${range}` }
}

/** Parse a Yarn locator such as `pkg@npm:1.2.3` or `pkg@workspace:packages/x`. */
export function parseYarnLocator(value) {
  const descriptor = parseYarnDescriptor(value)
  if (!descriptor) return null
  const { name, range } = descriptor
  if (range.startsWith('workspace:')) {
    return {
      ...descriptor,
      protocol: 'workspace',
      workspacePath: range.slice('workspace:'.length).replace(/\\/g, '/'),
      actualName: name,
      actualVersion: null,
    }
  }
  if (range.startsWith('npm:')) {
    const payload = range.slice('npm:'.length)
    const separator = payload.startsWith('@') ? payload.indexOf('@', 1) : payload.indexOf('@')
    if (separator > 0) {
      return {
        ...descriptor,
        protocol: 'npm',
        actualName: payload.slice(0, separator),
        actualVersion: payload.slice(separator + 1),
      }
    }
    return {
      ...descriptor,
      protocol: 'npm',
      actualName: name,
      actualVersion: payload,
    }
  }
  if (range.startsWith('virtual:') || range.startsWith('patch:')) {
    const hash = range.lastIndexOf('#npm:')
    return {
      ...descriptor,
      protocol: range.slice(0, range.indexOf(':')),
      actualName: name,
      actualVersion: hash >= 0 ? range.slice(hash + '#npm:'.length) : null,
    }
  }
  if (range.startsWith('link:') || range.startsWith('portal:') || range.startsWith('file:')) {
    return {
      ...descriptor,
      protocol: range.slice(0, range.indexOf(':')),
      actualName: name,
      actualVersion: null,
    }
  }
  return {
    ...descriptor,
    protocol: null,
    actualName: name,
    actualVersion: range,
  }
}

/** Resolve an npm alias (`compat@npm:real-package@^1`) to the installed identity. */
export function resolveAliasIdentity(name, range) {
  if (typeof range !== 'string' || !range.startsWith('npm:')) {
    return { name, versionRange: range }
  }
  const payload = range.slice('npm:'.length)
  const separator = payload.startsWith('@') ? payload.indexOf('@', 1) : payload.indexOf('@')
  if (separator > 0) {
    return { name: payload.slice(0, separator), versionRange: payload.slice(separator + 1) }
  }
  return { name, versionRange: payload }
}

/** Read explicit lifecycle-script metadata; never infer scripts from bins/os/cpu. */
export function metadataScriptEvidence(entry) {
  const scripts = isPlainMap(entry?.scripts) ? entry.scripts : null
  const lifecycle = scripts
    ? Object.keys(scripts).filter((name) => LIFECYCLE_SCRIPTS.has(name)).sort()
    : []
  let hasInstallScript = typeof entry?.hasInstallScript === 'boolean'
    ? entry.hasInstallScript
    : null
  if (hasInstallScript === null && lifecycle.length > 0) hasInstallScript = true
  if (hasInstallScript === null && typeof entry?.installScript === 'string' && entry.installScript.length > 0) {
    hasInstallScript = true
  }
  const requiresBuild = typeof entry?.requiresBuild === 'boolean'
    ? entry.requiresBuild
    : false
  return { hasInstallScript, requiresBuild, scripts, lifecycle }
}

export function installScriptEvidence(nodes, format) {
  const observed = nodes.some((node) => node.hasInstallScript === true || node.requiresBuild === true)
  if (observed) {
    return {
      status: 'observed',
      reason: `${format}-lockfile-explicit-build-metadata`,
    }
  }
  return {
    status: 'unavailable',
    reason: `${format}-lockfile-does-not-record-lifecycle-scripts`,
  }
}

function parseVersion(value) {
  const match = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+].*)?$/.exec(String(value ?? '').trim())
  if (!match) return null
  return {
    major: Number(match[1]),
    minor: Number(match[2] ?? 0),
    patch: Number(match[3] ?? 0),
    parts: match[2] === undefined ? 1 : match[3] === undefined ? 2 : 3,
  }
}

function compareVersions(left, right) {
  for (const key of ['major', 'minor', 'patch']) {
    if (left[key] !== right[key]) return left[key] < right[key] ? -1 : 1
  }
  return 0
}

function satisfiesComparator(version, comparator) {
  const match = /^(>=|<=|>|<|=)?\s*(.+)$/.exec(comparator)
  if (!match) return false
  const operator = match[1] ?? '='
  let baseText = match[2].trim()
  if (!baseText || baseText === '*' || /^x$/i.test(baseText)) return true
  const wildcard = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?\.(?:x|X|\*)$/.exec(baseText)
  if (wildcard) {
    const major = Number(wildcard[1])
    if (version.major !== major) return false
    if (wildcard[2] === undefined) return true
    if (version.minor !== Number(wildcard[2])) return false
    return true
  }
  const base = parseVersion(baseText)
  if (!base) return false
  const result = compareVersions(version, base)
  if (operator === '>=') return result >= 0
  if (operator === '>') return result > 0
  if (operator === '<=') return result <= 0
  if (operator === '<') return result < 0
  if (base.parts === 1) return version.major === base.major
  if (base.parts === 2) return version.major === base.major && version.minor === base.minor
  return result === 0
}

/**
 * Conservative semver-range check for locally declared workspace versions.
 * Unknown syntax returns false so a registry dependency is never silently
 * replaced by a same-named workspace.
 */
export function versionSatisfies(versionText, rangeText) {
  const version = parseVersion(versionText)
  if (!version) return false
  const range = String(rangeText ?? '').trim()
  if (!range || range === '*' || range === 'latest') return true
  if (range.startsWith('workspace:')) return true
  for (const alternative of range.split('||')) {
    const text = alternative.trim()
    if (!text) continue
    const caret = /^\^(.+)$/.exec(text)
    if (caret) {
      const base = parseVersion(caret[1])
      if (!base || compareVersions(version, base) < 0) continue
      const upper = { major: base.major, minor: base.minor, patch: base.patch, parts: 3 }
      if (base.parts === 1) upper.major += 1
      else if (base.major > 0) upper.major += 1
      else if (base.minor > 0 || base.parts === 2) upper.minor += 1
      else upper.patch += 1
      if (compareVersions(version, upper) < 0) return true
      continue
    }
    const tilde = /^~(.+)$/.exec(text)
    if (tilde) {
      const base = parseVersion(tilde[1])
      if (!base || compareVersions(version, base) < 0) continue
      const upper = base.parts === 1
        ? { major: base.major + 1, minor: 0, patch: 0, parts: 3 }
        : { major: base.major, minor: base.minor + 1, patch: 0, parts: 3 }
      if (compareVersions(version, upper) < 0) return true
      continue
    }
    const comparators = text.split(/\s+/).filter(Boolean)
    if (comparators.every((comparator) => satisfiesComparator(version, comparator))) return true
  }
  return false
}
