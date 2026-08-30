import { createHash } from 'node:crypto'
import { DYNAMIC_HARD_LIMITS } from './policy.js'

const COLLECTIONS = Object.freeze([
  'stages', 'networkAttempts', 'dnsQueries', 'processes', 'fileEvents',
  'canaryEvents', 'policyViolations', 'limitations', 'failures',
])
const ROOT_TEXT_FIELDS = Object.freeze(['stdout', 'stderr'])
const TEXT = 'text'
const NUMBER = 'number'
const BOOLEAN = 'boolean'
const PAYLOAD = 'payload'
const TEXT_ARRAY = 'text-array'
const OMIT = Symbol('omit')

const CANARY_DEFINITIONS = Object.freeze([
  ['apiKey', 'api-key'],
  ['bearerToken', 'bearer-token'],
  ['environmentSecret', 'environment-secret'],
  ['sshFile', 'ssh-file'],
  ['workspaceDocument', 'workspace-document'],
  ['conversation', 'conversation'],
  ['memory', 'memory'],
  ['toolArgument', 'tool-argument'],
])

const PAYLOAD_SCHEMA = Object.freeze({
  content: TEXT, data: TEXT, encoding: TEXT, length: NUMBER, message: TEXT,
  name: TEXT, nested: TEXT, path: TEXT, reason: TEXT, text: TEXT, type: TEXT,
  value: TEXT,
})

const COLLECTION_SCHEMAS = Object.freeze({
  stages: Object.freeze({
    durationMs: NUMBER, name: TEXT, reason: TEXT, stage: TEXT, startedAt: TEXT,
    status: TEXT, timestamp: TEXT,
  }),
  networkAttempts: Object.freeze({
    allowed: BOOLEAN, blocked: BOOLEAN, body: PAYLOAD, bytes: NUMBER,
    destination: TEXT, headers: PAYLOAD, method: TEXT, port: NUMBER,
    protocol: TEXT, reason: TEXT, request: PAYLOAD, response: PAYLOAD,
    stage: TEXT, timestamp: TEXT,
  }),
  dnsQueries: Object.freeze({
    answers: TEXT_ARRAY, blocked: BOOLEAN, hostname: TEXT, recordType: TEXT,
    reason: TEXT, stage: TEXT, timestamp: TEXT,
  }),
  processes: Object.freeze({
    argv: TEXT_ARRAY, blocked: BOOLEAN, command: TEXT, cwd: TEXT,
    exitCode: NUMBER, pid: NUMBER, reason: TEXT, signal: TEXT, stage: TEXT,
    timestamp: TEXT,
  }),
  fileEvents: Object.freeze({
    blocked: BOOLEAN, bytes: NUMBER, operation: TEXT, path: TEXT, reason: TEXT,
    stage: TEXT, timestamp: TEXT,
  }),
  canaryEvents: Object.freeze({
    boundary: TEXT, detected: BOOLEAN, destination: TEXT, kind: TEXT,
    location: TEXT, operation: TEXT, source: TEXT, stage: TEXT, timestamp: TEXT,
  }),
  policyViolations: Object.freeze({
    action: TEXT, code: TEXT, detail: TEXT, details: PAYLOAD, reason: TEXT,
    stage: TEXT, timestamp: TEXT,
  }),
  limitations: Object.freeze({
    code: TEXT, detail: TEXT, dropped: NUMBER, kind: TEXT, location: TEXT,
    maxEvidenceDepth: NUMBER, maxEvents: NUMBER, maxListItems: NUMBER,
    maxTextBytes: NUMBER, reason: TEXT,
  }),
  failures: Object.freeze({
    code: TEXT, detail: TEXT, details: PAYLOAD, reason: TEXT, stage: TEXT,
    timestamp: TEXT,
  }),
})

const ROOT_OUTPUT_FIELDS = new Set([...COLLECTIONS, ...ROOT_TEXT_FIELDS])
const CANARY_IDS = new Set(CANARY_DEFINITIONS.map(([, id]) => id))
const SORTED_CANARY_IDS = Object.freeze([...CANARY_IDS].sort())

class EvidenceRejected extends Error {
  constructor(code) {
    super(code)
    this.code = code
  }
}

function invalidCanarySet() {
  return new EvidenceRejected('invalid-canary-set')
}

function unsafeInput() {
  return new EvidenceRejected('unsafe-input')
}

function isRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  try {
    const prototype = Object.getPrototypeOf(value)
    return prototype === Object.prototype || prototype === null
  } catch {
    throw unsafeInput()
  }
}

function isArray(value) {
  if (!Array.isArray(value)) return false
  try {
    return Object.getPrototypeOf(value) === Array.prototype
  } catch {
    throw unsafeInput()
  }
}

function ownDataProperty(value, key) {
  let descriptor
  try {
    descriptor = Object.getOwnPropertyDescriptor(value, key)
  } catch {
    throw unsafeInput()
  }
  if (!descriptor) return { present: false, value: undefined }
  if (!Object.hasOwn(descriptor, 'value')) throw unsafeInput()
  return { present: true, value: descriptor.value, enumerable: descriptor.enumerable }
}

function ownKeys(value) {
  try {
    return Reflect.ownKeys(value)
  } catch {
    throw unsafeInput()
  }
}

function exactStringKeys(value, expected) {
  const keys = ownKeys(value)
  if (keys.some(key => typeof key !== 'string')) throw invalidCanarySet()
  const actual = [...keys].sort()
  const wanted = [...expected].sort()
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw invalidCanarySet()
  }
}

function assertNormalizedArrayKeys(value, length) {
  const keys = ownKeys(value)
  const expected = new Set(['length', ...Array.from({ length }, (_, index) => String(index))])
  if (keys.length !== expected.size || keys.some(key => typeof key !== 'string' || !expected.has(key))) {
    throw new Error('invalid normalized evidence')
  }
  const lengthEntry = ownDataProperty(value, 'length')
  if (!lengthEntry.present || lengthEntry.enumerable !== false) throw new Error('invalid normalized evidence')
  for (let index = 0; index < length; index += 1) {
    const entry = ownDataProperty(value, String(index))
    if (!entry.present || entry.enumerable !== true) throw new Error('invalid normalized evidence')
  }
}

function sha256(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function validateCanaries(canaries) {
  try {
    if (!isRecord(canaries)) throw invalidCanarySet()
    exactStringKeys(canaries, ['values', 'descriptors'])
    const valuesEntry = ownDataProperty(canaries, 'values')
    const descriptorsEntry = ownDataProperty(canaries, 'descriptors')
    if (!valuesEntry.present || !isRecord(valuesEntry.value)) throw invalidCanarySet()
    if (!descriptorsEntry.present || !isArray(descriptorsEntry.value)) throw invalidCanarySet()

    exactStringKeys(valuesEntry.value, CANARY_DEFINITIONS.map(([property]) => property))
    const lengthEntry = ownDataProperty(descriptorsEntry.value, 'length')
    if (!lengthEntry.present || lengthEntry.value !== CANARY_DEFINITIONS.length) throw invalidCanarySet()
    exactStringKeys(descriptorsEntry.value, [
      'length', ...CANARY_DEFINITIONS.map((_, index) => String(index)),
    ])

    const mapping = []
    const seenValues = new Set()
    for (let index = 0; index < CANARY_DEFINITIONS.length; index += 1) {
      const [property, kind] = CANARY_DEFINITIONS[index]
      const valueEntry = ownDataProperty(valuesEntry.value, property)
      if (!valueEntry.present || typeof valueEntry.value !== 'string' || valueEntry.value.length === 0) {
        throw invalidCanarySet()
      }
      if (seenValues.has(valueEntry.value)) throw invalidCanarySet()
      seenValues.add(valueEntry.value)
      const descriptorEntry = ownDataProperty(descriptorsEntry.value, String(index))
      if (!descriptorEntry.present || !isRecord(descriptorEntry.value)) throw invalidCanarySet()
      exactStringKeys(descriptorEntry.value, ['digest', 'id', 'kind'])
      const idEntry = ownDataProperty(descriptorEntry.value, 'id')
      const kindEntry = ownDataProperty(descriptorEntry.value, 'kind')
      const digestEntry = ownDataProperty(descriptorEntry.value, 'digest')
      if (idEntry.value !== kind || kindEntry.value !== kind || typeof digestEntry.value !== 'string') {
        throw invalidCanarySet()
      }
      if (digestEntry.value !== sha256(valueEntry.value)) throw invalidCanarySet()
      mapping.push({ id: kind, value: valueEntry.value })
    }
    return mapping.sort((left, right) => right.value.length - left.value.length || left.id.localeCompare(right.id))
  } catch (error) {
    if (error instanceof EvidenceRejected) throw error
    throw unsafeInput()
  }
}

function boundedLimit(value, fallback, hardLimit) {
  const numeric = Number(value)
  if (!Number.isFinite(numeric)) return fallback
  return Math.min(hardLimit, Math.max(0, Math.floor(numeric)))
}

function normalizeLimits(input) {
  const source = input === undefined ? null : input
  if (source !== null && !isRecord(source)) throw unsafeInput()
  const get = (key, fallback, hardLimit) => {
    const entry = source === null ? { present: false } : ownDataProperty(source, key)
    if (!entry.present) return fallback
    if (typeof entry.value === 'object' && entry.value !== null) throw unsafeInput()
    return boundedLimit(entry.value, fallback, hardLimit)
  }
  return {
    maxEvents: get('maxEvents', DYNAMIC_HARD_LIMITS.maxEvents, DYNAMIC_HARD_LIMITS.maxEvents),
    maxTextBytes: get('maxTextBytes', DYNAMIC_HARD_LIMITS.maxTextBytes, DYNAMIC_HARD_LIMITS.maxTextBytes),
    maxListItems: get('maxListItems', DYNAMIC_HARD_LIMITS.maxListItems, DYNAMIC_HARD_LIMITS.maxListItems),
    maxEvidenceDepth: get('maxEvidenceDepth', DYNAMIC_HARD_LIMITS.maxEvidenceDepth, DYNAMIC_HARD_LIMITS.maxEvidenceDepth),
  }
}

function truncateUtf8(value, maxBytes) {
  const bytes = Buffer.from(value, 'utf8')
  if (bytes.length <= maxBytes) return { value, truncated: false }
  let result = bytes.subarray(0, maxBytes).toString('utf8')
  while (Buffer.byteLength(result, 'utf8') > maxBytes) result = result.slice(0, -1)
  return { value: result, truncated: true }
}

const PATH_NARRATIVE = '(?:failed|succeeded|blocked|allowed|denied|error|warning|because|during|after|before|while|read|write)'
const PATH_BOUNDARY = `(?=\\s+${PATH_NARRATIVE}\\b|\\s+(?:\\\\|[A-Za-z]:[\\/]|\/)|\\s*(?:\\r?$|\\r?\\n)|$)`
const UNC_PATH = new RegExp(`\\\\\\\\[^\\s\\\\/]+\\\\[^\\r\\n"'<>|]*?${PATH_BOUNDARY}`, 'g')
const DRIVE_PATH = new RegExp(`[A-Za-z]:[\\\\/][^\\r\\n"'<>|]*?${PATH_BOUNDARY}`, 'g')
const POSIX_PATH = new RegExp(`(?<![A-Za-z0-9:/])\\/(?:[^\\r\\n"'<>|]*?)${PATH_BOUNDARY}`, 'g')

function redactHostPaths(value, bounded = false) {
  let result = value
    .replace(UNC_PATH, '[HOST_PATH]')
    .replace(DRIVE_PATH, '[HOST_PATH]')
    .replace(POSIX_PATH, '[HOST_PATH]')
  if (bounded) {
    result = result
      .replace(/\\\\[^\s\\/]+\\\\[^\r\n"'<>|]*$/g, '[HOST_PATH]')
      .replace(/[A-Za-z]:[\\/][^\r\n"'<>|]*$/g, '[HOST_PATH]')
      .replace(/(?<![A-Za-z0-9:/])\/(?:[^\r\n"'<>|]*)$/g, '[HOST_PATH]')
  }
  return result
}

function emptyEvidence() {
  const evidence = {}
  for (const field of COLLECTIONS) evidence[field] = []
  return evidence
}

function rejectedEvidence(code) {
  const evidence = emptyEvidence()
  evidence.failures.push({ reason: 'evidence-rejected', code })
  return evidence
}

function sortedNotices(notices) {
  return [...notices].sort((left, right) => (
    `${left.kind}|${left.location}|${left.reason}`.localeCompare(`${right.kind}|${right.location}|${right.reason}`)
    || (left.dropped ?? 0) - (right.dropped ?? 0)
  ))
}

function canonicalize(value, ancestors = new Set()) {
  if (value === null) return 'null'
  if (typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number') return Object.is(value, -0) ? '-0' : String(value)
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (Array.isArray(value)) {
    if (ancestors.has(value)) throw new Error('invalid normalized evidence')
    const next = new Set(ancestors)
    next.add(value)
    const lengthEntry = ownDataProperty(value, 'length')
    if (!lengthEntry.present || !Number.isSafeInteger(lengthEntry.value)) throw new Error('invalid normalized evidence')
    const items = []
    for (let index = 0; index < lengthEntry.value; index += 1) {
      const entry = ownDataProperty(value, String(index))
      if (!entry.present) throw new Error('invalid normalized evidence')
      items.push(canonicalize(entry.value, next))
    }
    return `[${items.join(',')}]`
  }
  if (value && typeof value === 'object') {
    if (ancestors.has(value)) throw new Error('invalid normalized evidence')
    const next = new Set(ancestors)
    next.add(value)
    const parts = []
    for (const key of ownKeys(value).sort()) {
      if (typeof key !== 'string') throw new Error('invalid normalized evidence')
      const entry = ownDataProperty(value, key)
      if (!entry.present) throw new Error('invalid normalized evidence')
      parts.push(`${JSON.stringify(key)}:${canonicalize(entry.value, next)}`)
    }
    return `{${parts.join(',')}}`
  }
  throw new Error('invalid normalized evidence')
}

function validateNormalizedValue(value, schema, depth, ancestors, budget) {
  if (depth > DYNAMIC_HARD_LIMITS.maxEvidenceDepth) throw new Error('invalid normalized evidence')
  budget.nodes -= 1
  if (budget.nodes < 0) throw new Error('invalid normalized evidence')
  if (schema === TEXT) {
    if (typeof value !== 'string') throw new Error('invalid normalized evidence')
    budget.textBytes += Buffer.byteLength(value, 'utf8')
    if (budget.textBytes > DYNAMIC_HARD_LIMITS.maxTextBytes) throw new Error('invalid normalized evidence')
    return
  }
  if (schema === NUMBER) {
    if (typeof value !== 'number' || !Number.isFinite(value)) throw new Error('invalid normalized evidence')
    return
  }
  if (schema === BOOLEAN) {
    if (typeof value !== 'boolean') throw new Error('invalid normalized evidence')
    return
  }
  if (schema === TEXT_ARRAY) {
    if (!isArray(value) || ancestors.has(value)) throw new Error('invalid normalized evidence')
    const next = new Set(ancestors)
    next.add(value)
    const lengthEntry = ownDataProperty(value, 'length')
    if (!lengthEntry.present || lengthEntry.value > DYNAMIC_HARD_LIMITS.maxListItems) throw new Error('invalid normalized evidence')
    assertNormalizedArrayKeys(value, lengthEntry.value)
    budget.items += lengthEntry.value
    if (budget.items > DYNAMIC_HARD_LIMITS.maxListItems) throw new Error('invalid normalized evidence')
    for (let index = 0; index < lengthEntry.value; index += 1) {
      const entry = ownDataProperty(value, String(index))
      if (!entry.present) throw new Error('invalid normalized evidence')
      validateNormalizedValue(entry.value, TEXT, depth + 1, next, budget)
    }
    return
  }
  if (schema === PAYLOAD) {
    if (typeof value === 'string') {
      validateNormalizedValue(value, TEXT, depth, ancestors, budget)
      return
    }
    validateNormalizedRecord(value, PAYLOAD_SCHEMA, depth + 1, ancestors, budget)
    return
  }
  throw new Error('invalid normalized evidence')
}

function validateNormalizedRecord(value, schema, depth, ancestors, budget, extraKeys = []) {
  if (!isRecord(value) || ancestors.has(value)) throw new Error('invalid normalized evidence')
  const next = new Set(ancestors)
  next.add(value)
  const allowed = new Set([...Object.keys(schema), ...extraKeys])
  for (const key of ownKeys(value)) {
    if (typeof key !== 'string' || !allowed.has(key)) throw new Error('invalid normalized evidence')
    const entry = ownDataProperty(value, key)
    if (!entry.present || entry.enumerable !== true) throw new Error('invalid normalized evidence')
  }
  for (const key of Object.keys(schema).sort()) {
    const entry = ownDataProperty(value, key)
    if (entry.present) validateNormalizedValue(entry.value, schema[key], depth, next, budget)
  }
}

function validateNormalizedEvidence(value) {
  if (!isRecord(value)) throw new Error('invalid normalized evidence')
  const rootKeys = ownKeys(value)
  if (rootKeys.some(key => typeof key !== 'string' || !ROOT_OUTPUT_FIELDS.has(key))) {
    throw new Error('invalid normalized evidence')
  }
  for (const key of rootKeys) {
    const entry = ownDataProperty(value, key)
    if (!entry.present || entry.enumerable !== true) throw new Error('invalid normalized evidence')
  }
  for (const field of COLLECTIONS) {
    const entry = ownDataProperty(value, field)
    if (!entry.present || !isArray(entry.value)) throw new Error('invalid normalized evidence')
    const lengthEntry = ownDataProperty(entry.value, 'length')
    if (!lengthEntry.present || lengthEntry.value > DYNAMIC_HARD_LIMITS.maxListItems) {
      throw new Error('invalid normalized evidence')
    }
    assertNormalizedArrayKeys(entry.value, lengthEntry.value)
  }
  const budget = {
    nodes: DYNAMIC_HARD_LIMITS.maxEvents * 64 + DYNAMIC_HARD_LIMITS.maxListItems,
    items: 0,
    textBytes: 0,
  }
  let events = 0
  for (const field of COLLECTIONS) {
    const list = ownDataProperty(value, field).value
    const length = ownDataProperty(list, 'length').value
    events += length
    if (events > DYNAMIC_HARD_LIMITS.maxEvents) throw new Error('invalid normalized evidence')
    for (let index = 0; index < length; index += 1) {
      const eventEntry = ownDataProperty(list, String(index))
      if (!eventEntry.present || !isRecord(eventEntry.value)) throw new Error('invalid normalized evidence')
      const event = eventEntry.value
      const schema = COLLECTION_SCHEMAS[field]
      const eventKeys = ownKeys(event)
      for (const key of eventKeys) {
        if (typeof key !== 'string' || (key !== 'canaryIds' && !Object.hasOwn(schema, key))) {
          throw new Error('invalid normalized evidence')
        }
      }
      validateNormalizedRecord(event, schema, 0, new Set(), budget, ['canaryIds'])
      const canaryIdsEntry = ownDataProperty(event, 'canaryIds')
      if (canaryIdsEntry.present) {
        if (!isArray(canaryIdsEntry.value)) throw new Error('invalid normalized evidence')
        const ids = canaryIdsEntry.value
        const lengthEntry = ownDataProperty(ids, 'length')
        if (!lengthEntry.present || lengthEntry.value === 0 || lengthEntry.value > CANARY_IDS.size) {
          throw new Error('invalid normalized evidence')
        }
        assertNormalizedArrayKeys(ids, lengthEntry.value)
        for (let idIndex = 0; idIndex < lengthEntry.value; idIndex += 1) {
          const idEntry = ownDataProperty(ids, String(idIndex))
          if (!idEntry.present || idEntry.value !== SORTED_CANARY_IDS[idIndex]) {
            throw new Error('invalid normalized evidence')
          }
        }
      }
    }
  }
  for (const field of ROOT_TEXT_FIELDS) {
    const entry = ownDataProperty(value, field)
    if (entry.present) validateNormalizedValue(entry.value, TEXT, 0, new Set(), budget)
  }
}

export function evidenceDigest(value) {
  try {
    validateNormalizedEvidence(value)
    return createHash('sha256').update(canonicalize(value), 'utf8').digest('hex')
  } catch {
    throw new Error('invalid normalized evidence')
  }
}

export function normalizeDynamicEvidence(input = {}, options = {}) {
  try {
    const canariesEntry = isRecord(options) ? ownDataProperty(options, 'canaries') : { present: false }
    const limitsEntry = isRecord(options) ? ownDataProperty(options, 'limits') : { present: false }
    const canaries = canariesEntry.present ? validateCanaries(canariesEntry.value) : []
    const limits = normalizeLimits(limitsEntry.present ? limitsEntry.value : undefined)
    if (!isRecord(input)) throw unsafeInput()

    const normalized = emptyEvidence()
    const notices = []
    const noticeKeys = new Set()
    const state = {
      canaries,
      limits,
      notices,
      noticeKeys,
      textRemaining: limits.maxTextBytes,
      itemsRemaining: limits.maxListItems,
      nodesRemaining: limits.maxEvents * 64 + limits.maxListItems,
    }
    const addNotice = notice => {
      const key = JSON.stringify(notice)
      if (!noticeKeys.has(key)) {
        noticeKeys.add(key)
        notices.push(notice)
      }
    }
    state.addNotice = addNotice
    const maxCanaryLength = canaries.reduce(
      (maximum, canary) => Math.max(maximum, canary.value.length),
      0,
    )
    const textScanLimit = limits.maxTextBytes + maxCanaryLength + 256

    const sanitizeText = (value, location, foundCanaries = null) => {
      if (state.textRemaining <= 0) {
        if (value.length > 0) addNotice({ reason: 'evidence-truncated', kind: 'text', location, maxTextBytes: limits.maxTextBytes })
        return ''
      }
      const boundedInput = value.length > textScanLimit
      let result = boundedInput ? value.slice(0, textScanLimit) : value
      for (const canary of canaries) {
        if (!result.includes(canary.value)) continue
        result = result.split(canary.value).join(`[CANARY:${canary.id}]`)
        if (foundCanaries) foundCanaries.add(canary.id)
      }
      result = redactHostPaths(result, boundedInput)
      const bounded = truncateUtf8(result, state.textRemaining)
      state.textRemaining -= Buffer.byteLength(bounded.value, 'utf8')
      if (bounded.truncated) {
        addNotice({ reason: 'evidence-truncated', kind: 'text', location, maxTextBytes: limits.maxTextBytes })
      }
      return bounded.value
    }

    const consumeNode = location => {
      if (state.nodesRemaining <= 0) {
        addNotice({ reason: 'evidence-truncated', kind: 'nodes', location })
        return false
      }
      state.nodesRemaining -= 1
      return true
    }

    const consumeItem = location => {
      if (state.itemsRemaining <= 0) {
        addNotice({ reason: 'evidence-truncated', kind: 'items', location, maxListItems: limits.maxListItems })
        return false
      }
      state.itemsRemaining -= 1
      return true
    }

    const normalizeArray = (value, location, depth, foundCanaries) => {
      if (!isArray(value)) return OMIT
      if (depth > limits.maxEvidenceDepth) {
        addNotice({ reason: 'evidence-truncated', kind: 'depth', location, maxEvidenceDepth: limits.maxEvidenceDepth })
        const sentinel = '[DEPTH_LIMIT]'
        if (limits.maxListItems === 0 || state.itemsRemaining <= 0 || state.nodesRemaining <= 0) return []
        if (state.textRemaining < Buffer.byteLength(sentinel, 'utf8')) return []
        state.itemsRemaining -= 1
        state.nodesRemaining -= 1
        state.textRemaining -= Buffer.byteLength(sentinel, 'utf8')
        return [sentinel]
      }
      const lengthEntry = ownDataProperty(value, 'length')
      const length = lengthEntry.present && Number.isSafeInteger(lengthEntry.value) ? lengthEntry.value : 0
      const result = []
      const count = Math.min(length, limits.maxListItems)
      for (let index = 0; index < count; index += 1) {
        if (!consumeItem(`${location}[${index}]`)) break
        const entry = ownDataProperty(value, String(index))
        if (!entry.present) continue
        if (!consumeNode(`${location}[${index}]`)) break
        if (typeof entry.value === 'string') result.push(sanitizeText(entry.value, `${location}[${index}]`, foundCanaries))
      }
      if (length > count) {
        addNotice({ reason: 'evidence-truncated', kind: 'items', location, dropped: length - count, maxListItems: limits.maxListItems })
      }
      return result
    }

    const normalizeRecord = (value, schema, location, depth, foundCanaries, countItems) => {
      if (!isRecord(value)) return OMIT
      if (depth > limits.maxEvidenceDepth) {
        addNotice({ reason: 'evidence-truncated', kind: 'depth', location, maxEvidenceDepth: limits.maxEvidenceDepth })
        return '[DEPTH_LIMIT]'
      }
      const result = {}
      for (const key of Object.keys(schema).sort()) {
        const entry = ownDataProperty(value, key)
        if (!entry.present) continue
        if (countItems && !consumeItem(`${location}.${key}`)) break
        if (!consumeNode(`${location}.${key}`)) break
        const child = normalizeTyped(entry.value, schema[key], `${location}.${key}`, depth + 1, foundCanaries)
        if (child !== OMIT) result[key] = child
      }
      return result
    }

    const normalizeTyped = (value, schema, location, depth, foundCanaries) => {
      if (schema === TEXT) return typeof value === 'string' ? sanitizeText(value, location, foundCanaries) : OMIT
      if (schema === NUMBER) return typeof value === 'number' && Number.isFinite(value) ? value : OMIT
      if (schema === BOOLEAN) return typeof value === 'boolean' ? value : OMIT
      if (schema === PAYLOAD) {
        if (typeof value === 'string') return sanitizeText(value, location, foundCanaries)
        return normalizeRecord(value, PAYLOAD_SCHEMA, location, depth, foundCanaries, true)
      }
      if (schema === TEXT_ARRAY) return normalizeArray(value, location, depth, foundCanaries)
      return OMIT
    }

    for (const field of ROOT_TEXT_FIELDS) {
      const entry = ownDataProperty(input, field)
      if (entry.present && typeof entry.value === 'string') normalized[field] = sanitizeText(entry.value, field)
    }

    const selected = []
    let candidateCount = 0
    for (const field of COLLECTIONS) {
      const collectionEntry = ownDataProperty(input, field)
      if (!collectionEntry.present) continue
      if (!isArray(collectionEntry.value)) {
        addNotice({ reason: 'evidence-truncated', kind: 'invalid-collection', location: field })
        continue
      }
      const lengthEntry = ownDataProperty(collectionEntry.value, 'length')
      const length = lengthEntry.present && Number.isSafeInteger(lengthEntry.value) ? lengthEntry.value : 0
      const count = Math.min(length, limits.maxListItems)
      candidateCount += count
      if (length > count) {
        addNotice({ reason: 'evidence-truncated', kind: 'items', location: field, dropped: length - count, maxListItems: limits.maxListItems })
      }
      for (let index = 0; index < count && selected.length < limits.maxEvents; index += 1) {
        const eventEntry = ownDataProperty(collectionEntry.value, String(index))
        selected.push({ field, index, present: eventEntry.present, value: eventEntry.value })
      }
    }

    const normalizedEvents = []
    for (const selectedEvent of selected) {
      if (!selectedEvent.present || !isRecord(selectedEvent.value)) {
        addNotice({ reason: 'evidence-truncated', kind: 'invalid-event', location: `${selectedEvent.field}[${selectedEvent.index}]` })
        continue
      }
      const foundCanaries = new Set()
      const event = normalizeRecord(
        selectedEvent.value,
        COLLECTION_SCHEMAS[selectedEvent.field],
        `${selectedEvent.field}[${selectedEvent.index}]`,
        0,
        foundCanaries,
        false,
      )
      if (event === OMIT) continue
      if (foundCanaries.size > 0) event.canaryIds = [...foundCanaries].sort()
      normalizedEvents.push({ field: selectedEvent.field, event })
    }

    const noticeLimit = Math.min(limits.maxListItems, limits.maxEvents)
    const baseNotices = sortedNotices(notices).slice(0, noticeLimit)
    const baseCapacity = Math.max(0, limits.maxEvents - baseNotices.length)
    const eventNoticeNeeded = candidateCount > baseCapacity || normalizedEvents.length > baseCapacity
    let eventNotice = null
    if (eventNoticeNeeded && baseNotices.length < noticeLimit) {
      eventNotice = {
        reason: 'evidence-truncated',
        kind: 'events',
        location: 'events',
        dropped: 0,
        maxEvents: limits.maxEvents,
      }
    }
    const finalNotices = sortedNotices(eventNotice ? [...baseNotices, eventNotice] : baseNotices)
      .slice(0, noticeLimit)
    const eventCapacity = Math.max(0, limits.maxEvents - finalNotices.length)
    const retained = normalizedEvents.slice(0, eventCapacity)
    for (const field of COLLECTIONS) {
      const fieldEvents = retained.filter(item => item.field === field)
      const slots = field === 'limitations'
        ? Math.max(0, limits.maxListItems - finalNotices.length)
        : limits.maxListItems
      for (const item of fieldEvents.slice(0, slots)) normalized[field].push(item.event)
    }
    const retainedCount = COLLECTIONS.reduce((total, field) => total + normalized[field].length, 0)
    if (eventNotice) eventNotice.dropped = Math.max(0, candidateCount - retainedCount)
    for (const notice of finalNotices) normalized.limitations.push(notice)
    if (normalized.limitations.length > limits.maxListItems) normalized.limitations.length = limits.maxListItems
    return normalized
  } catch (error) {
    if (error instanceof EvidenceRejected) return rejectedEvidence(error.code)
    return rejectedEvidence('unsafe-input')
  }
}
