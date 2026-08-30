import { createHash } from 'node:crypto'
import { DYNAMIC_HARD_LIMITS } from './policy.js'

const COLLECTIONS = Object.freeze([
  'stages', 'networkAttempts', 'dnsQueries', 'processes', 'fileEvents',
  'canaryEvents', 'policyViolations', 'limitations', 'failures',
])

const ROOT_TEXT_FIELDS = Object.freeze(['stdout', 'stderr'])

const EVENT_FIELDS = new Set([
  'id', 'kind', 'name', 'stage', 'status', 'reason', 'code', 'message', 'detail',
  'details', 'destination', 'hostname', 'recordType', 'answers', 'protocol',
  'method', 'port', 'blocked', 'allowed', 'body', 'headers', 'request',
  'response', 'command', 'argv', 'cwd', 'pid', 'exitCode', 'signal', 'path',
  'operation', 'bytes', 'canaryId', 'canaryIds', 'boundary', 'source',
  'location', 'detected', 'timestamp', 'durationMs', 'eventCount', 'dropped',
  'maxEvents', 'maxListItems', 'maxTextBytes', 'maxEvidenceDepth', 'field',
  'type', 'value', 'address', 'domain', 'query', 'args', 'resource', 'action',
  'error',
])

const WINDOWS_ABSOLUTE_PATH = /[A-Za-z]:[\\/][^\s"'<>|]*/g
const POSIX_ABSOLUTE_PATH = /(?<![A-Za-z0-9:/])\/(?:[^/\s"'<>|]+\/)*[^/\s"'<>|]+/g

function boundedLimit(value, fallback, hardLimit) {
  const numeric = Number(value)
  if (!Number.isFinite(numeric)) return fallback
  return Math.min(hardLimit, Math.max(0, Math.floor(numeric)))
}

function normalizeLimits(input = {}) {
  return {
    maxEvents: boundedLimit(input.maxEvents, DYNAMIC_HARD_LIMITS.maxEvents, DYNAMIC_HARD_LIMITS.maxEvents),
    maxTextBytes: boundedLimit(input.maxTextBytes, DYNAMIC_HARD_LIMITS.maxTextBytes, DYNAMIC_HARD_LIMITS.maxTextBytes),
    maxListItems: boundedLimit(input.maxListItems, DYNAMIC_HARD_LIMITS.maxListItems, DYNAMIC_HARD_LIMITS.maxListItems),
    maxEvidenceDepth: boundedLimit(input.maxEvidenceDepth, DYNAMIC_HARD_LIMITS.maxEvidenceDepth, DYNAMIC_HARD_LIMITS.maxEvidenceDepth),
  }
}

function truncateUtf8(value, maxBytes) {
  const bytes = Buffer.from(value, 'utf8')
  if (bytes.length <= maxBytes) return { value, truncated: false }

  let result = bytes.subarray(0, maxBytes).toString('utf8')
  while (Buffer.byteLength(result, 'utf8') > maxBytes) result = result.slice(0, -1)
  return { value: result, truncated: true }
}

function redactHostPath(value) {
  return value
    .replace(WINDOWS_ABSOLUTE_PATH, '[HOST_PATH]')
    .replace(POSIX_ABSOLUTE_PATH, '[HOST_PATH]')
}

function canaryIndex(canaries) {
  const descriptorsByProperty = new Map()
  const values = canaries?.values
  const descriptors = Array.isArray(canaries?.descriptors) ? canaries.descriptors : []
  for (const descriptor of descriptors) {
    if (typeof descriptor?.id !== 'string' || typeof descriptor?.kind !== 'string') continue
    const value = values?.[descriptor.kind === 'api-key'
      ? 'apiKey'
      : descriptor.kind.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())]
    if (typeof value === 'string' && value.length > 0) {
      descriptorsByProperty.set(descriptor.id, { id: descriptor.id, value })
    }
  }
  if (descriptorsByProperty.size === 0 && values && typeof values === 'object') {
    for (const [property, value] of Object.entries(values)) {
      if (typeof value !== 'string' || value.length === 0) continue
      const id = property.replace(/[A-Z]/g, letter => `-${letter.toLowerCase()}`)
      descriptorsByProperty.set(id, { id, value })
    }
  }
  return [...descriptorsByProperty.values()].sort((left, right) => right.value.length - left.value.length)
}

function normalizeCanaryIds(value, knownIds) {
  const values = Array.isArray(value) ? value : [value]
  return [...new Set(values.filter(item => typeof item === 'string' && knownIds.has(item)))]
}

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(item => canonicalize(item)).join(',')}]`
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`
  }
  return JSON.stringify(value)
}

export function evidenceDigest(value) {
  return createHash('sha256').update(canonicalize(value), 'utf8').digest('hex')
}

export function normalizeDynamicEvidence(input = {}, { canaries, limits: rawLimits } = {}) {
  const limits = normalizeLimits(rawLimits)
  const canariesByValue = canaryIndex(canaries)
  const knownCanaryIds = new Set(canariesByValue.map(item => item.id))
  const notices = []
  const noticeKeys = new Set()

  const recordNotice = notice => {
    const key = JSON.stringify(notice)
    if (!noticeKeys.has(key)) {
      noticeKeys.add(key)
      notices.push(notice)
    }
  }

  const sanitizeText = (value, path, foundCanaries) => {
    let result = value
    for (const canary of canariesByValue) {
      if (!result.includes(canary.value)) continue
      result = result.split(canary.value).join(`[CANARY:${canary.id}]`)
      foundCanaries.add(canary.id)
    }
    result = redactHostPath(result)
    const bounded = truncateUtf8(result, limits.maxTextBytes)
    if (bounded.truncated) {
      recordNotice({ reason: 'evidence-truncated', kind: 'text', field: path, maxTextBytes: limits.maxTextBytes })
    }
    return bounded.value
  }

  const normalizeValue = (value, depth, path, foundCanaries, ancestors) => {
    if (depth > limits.maxEvidenceDepth) {
      recordNotice({ reason: 'evidence-truncated', kind: 'depth', field: path, maxEvidenceDepth: limits.maxEvidenceDepth })
      return '[DEPTH_LIMIT]'
    }
    if (typeof value === 'string') return sanitizeText(value, path, foundCanaries)
    if (value === null || typeof value === 'number' || typeof value === 'boolean') return value
    if (Array.isArray(value)) {
      if (ancestors.has(value)) {
        recordNotice({ reason: 'evidence-truncated', kind: 'cycle', field: path })
        return '[CYCLE]'
      }
      const nextAncestors = new Set(ancestors)
      nextAncestors.add(value)
      const result = value.slice(0, limits.maxListItems).map((item, index) => (
        normalizeValue(item, depth + 1, `${path}[${index}]`, foundCanaries, nextAncestors)
      ))
      if (value.length > limits.maxListItems) {
        recordNotice({ reason: 'evidence-truncated', kind: 'items', field: path, dropped: value.length - limits.maxListItems, maxListItems: limits.maxListItems })
      }
      return result
    }
    if (typeof value === 'object') {
      if (ancestors.has(value)) {
        recordNotice({ reason: 'evidence-truncated', kind: 'cycle', field: path })
        return '[CYCLE]'
      }
      const nextAncestors = new Set(ancestors)
      nextAncestors.add(value)
      const result = {}
      const entries = Object.entries(value)
      for (const [key, child] of entries.slice(0, limits.maxListItems)) {
        const safeKey = sanitizeText(key, `${path}.${key}`, foundCanaries)
        result[safeKey] = normalizeValue(child, depth + 1, `${path}.${safeKey}`, foundCanaries, nextAncestors)
      }
      if (entries.length > limits.maxListItems) {
        recordNotice({ reason: 'evidence-truncated', kind: 'items', field: path, dropped: entries.length - limits.maxListItems, maxListItems: limits.maxListItems })
      }
      return result
    }
    return null
  }

  const normalized = {}
  for (const field of COLLECTIONS) normalized[field] = []

  const root = input && typeof input === 'object' && !Array.isArray(input) ? input : {}
  const rootCanaries = new Set()
  for (const field of ROOT_TEXT_FIELDS) {
    if (typeof root[field] === 'string') normalized[field] = sanitizeText(root[field], field, rootCanaries)
  }

  const retained = []
  for (const field of COLLECTIONS) {
    const source = Array.isArray(root[field]) ? root[field] : []
    const itemLimit = Math.min(source.length, limits.maxListItems)
    if (source.length > limits.maxListItems) {
      recordNotice({ reason: 'evidence-truncated', kind: 'items', field, dropped: source.length - limits.maxListItems, maxListItems: limits.maxListItems })
    }
    for (let index = 0; index < itemLimit; index += 1) {
      const item = source[index]
      if (!item || typeof item !== 'object' || Array.isArray(item)) {
        recordNotice({ reason: 'evidence-truncated', kind: 'invalid-event', field })
        continue
      }
      const foundCanaries = new Set()
      const event = {}
      for (const [key, value] of Object.entries(item)) {
        if (!EVENT_FIELDS.has(key)) continue
        if (key === 'canaryIds' || key === 'canaryId') {
          const ids = normalizeCanaryIds(value, knownCanaryIds)
          if (ids.length > 0) event[key] = key === 'canaryId' ? ids[0] : ids
          continue
        }
        event[key] = normalizeValue(value, 0, `${field}[${index}].${key}`, foundCanaries, new Set())
      }
      if (foundCanaries.size > 0) {
        event.canaryIds = [...new Set([...(event.canaryIds ?? []), ...foundCanaries])]
      }
      retained.push({ field, event })
    }
  }

  const noticeLimit = Math.min(limits.maxListItems, limits.maxEvents)
  const noticeEvents = notices.slice(0, noticeLimit).map(event => ({ field: 'limitations', event }))
  if (limits.maxEvents === 0 && retained.length > 0) {
    recordNotice({ reason: 'evidence-truncated', kind: 'events', dropped: retained.length, maxEvents: limits.maxEvents })
  }
  const maxRetained = Math.max(0, limits.maxEvents - noticeEvents.length)
  if (retained.length > maxRetained) {
    recordNotice({ reason: 'evidence-truncated', kind: 'events', dropped: retained.length - maxRetained, maxEvents: limits.maxEvents })
  }
  const finalNotices = notices.slice(0, noticeLimit)
  const finalMaxRetained = Math.max(0, limits.maxEvents - finalNotices.length)
  const selected = retained.slice(0, finalMaxRetained)
  for (const field of COLLECTIONS) {
    const items = selected.filter(item => item.field === field)
    const slots = field === 'limitations'
      ? Math.max(0, limits.maxListItems - finalNotices.length)
      : limits.maxListItems
    for (const { event } of items.slice(0, slots)) normalized[field].push(event)
  }
  for (const notice of finalNotices) normalized.limitations.push(notice)

  return normalized
}
