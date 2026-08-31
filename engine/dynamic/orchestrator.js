import { randomUUID } from 'node:crypto'
import { createCanarySet } from './canaries.js'
import { emptyDynamicLayer, normalizeDynamicLayer } from './contracts.js'
import { evidenceDigest, normalizeDynamicEvidence } from './evidence.js'
import { DYNAMIC_HARD_LIMITS, normalizeDynamicOptions } from './policy.js'
import { resolveDynamicBackend } from './backend-resolver.js'

export const DYNAMIC_STAGES = Object.freeze(['load', 'registration', 'invocation'])

const BACKEND_METHODS = Object.freeze(['available', 'prepare', 'runStage', 'collect', 'cleanup'])
const EVIDENCE_FIELDS = Object.freeze([
  'networkAttempts', 'dnsQueries', 'processes', 'fileEvents',
  'canaryEvents', 'policyViolations', 'limitations',
])
const QUIESCENCE_GRACE_MS = 50

function safeDescriptor(record, key) {
  try {
    if (!record || (typeof record !== 'object' && typeof record !== 'function')) return { found: false }
    const descriptor = Object.getOwnPropertyDescriptor(record, key)
    if (!descriptor) return { found: false }
    if (!Object.hasOwn(descriptor, 'value')) return { found: true, unsafe: true }
    return { found: true, value: descriptor.value, enumerable: descriptor.enumerable === true }
  } catch {
    return { found: false, unsafe: true }
  }
}

function ownValue(record, key) {
  const entry = safeDescriptor(record, key)
  return entry.unsafe ? undefined : entry.value
}

function resolveBackendMethods(backend) {
  try {
    if (!backend || (typeof backend !== 'object' && typeof backend !== 'function')) return null
    const methods = {}
    for (const name of BACKEND_METHODS) {
      let current = backend
      let method = null
      for (let depth = 0; current && depth < 8; depth += 1) {
        const entry = safeDescriptor(current, name)
        if (entry.unsafe) return null
        if (entry.found) {
          if (typeof entry.value !== 'function') return null
          method = entry.value
          break
        }
        current = Object.getPrototypeOf(current)
      }
      if (!method) return null
      methods[name] = method
    }
    return Object.freeze(methods)
  } catch {
    return null
  }
}

function isHighRiskBlocker(blocker) {
  if (blocker === 'high-risk') return true
  const highRisk = ownValue(blocker, 'highRisk')
  const risk = ownValue(blocker, 'risk')
  const severity = ownValue(blocker, 'severity')
  const code = ownValue(blocker, 'code')
  return highRisk === true || risk === 'high' || severity === 'high'
    || (typeof code === 'string' && code.startsWith('high-risk-'))
}

function hasResolvableEntrypoint(entrypoints) {
  if (!Array.isArray(entrypoints)) return false
  return entrypoints.some(entrypoint => {
    if (typeof entrypoint === 'string') return entrypoint.trim().length > 0
    return ownValue(entrypoint, 'resolved') === true
  })
}

export function evaluateDynamicPreflight({ scanComplete, entrypoints, blockers = [] } = {}) {
  if (scanComplete !== true) return Object.freeze({ allowed: false, code: 'static-scan-incomplete' })
  if (!hasResolvableEntrypoint(entrypoints)) return Object.freeze({ allowed: false, code: 'entrypoint-unresolved' })
  if (Array.isArray(blockers) && blockers.some(isHighRiskBlocker)) {
    return Object.freeze({ allowed: false, code: 'high-risk-blocker' })
  }
  return Object.freeze({ allowed: true, code: null })
}

const pause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds))

async function runBoundedOperation(invoke, timeoutMs, parentSignal = null) {
  if (parentSignal?.aborted) {
    return { kind: 'cancelled', quiesced: true, settled: Promise.resolve({ state: 'cancelled' }) }
  }
  const controller = new AbortController()
  let timer = null
  let removeParentAbort = null
  let resolveCancelled = null
  const cancelled = new Promise(resolve => { resolveCancelled = resolve })
  const abort = () => {
    controller.abort()
    resolveCancelled?.('cancelled')
  }
  if (parentSignal) {
    parentSignal.addEventListener('abort', abort, { once: true })
    removeParentAbort = () => parentSignal.removeEventListener('abort', abort)
  }
  const settled = Promise.resolve()
    .then(() => invoke(controller.signal))
    .then(value => ({ state: 'fulfilled', value }), error => ({ state: 'rejected', error }))
  const deadline = new Promise(resolve => { timer = setTimeout(() => resolve('timeout'), timeoutMs) })
  let first
  try {
    first = await Promise.race([settled, deadline, cancelled])
  } finally {
    clearTimeout(timer)
    removeParentAbort?.()
  }
  if (first && typeof first === 'object') {
    return { kind: first.state, value: first.value, quiesced: true, settled }
  }
  controller.abort()
  const late = await Promise.race([
    settled,
    pause(QUIESCENCE_GRACE_MS).then(() => ({ state: 'pending' })),
  ])
  if (late.state !== 'pending') return { kind: first, value: late.value, quiesced: true, settled }
  return { kind: first, quiesced: false, settled }
}

function cloneJson(value, seen = new Set(), depth = 0) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('invalid run spec')
    return value
  }
  if (!value || typeof value !== 'object' || seen.has(value) || depth > DYNAMIC_HARD_LIMITS.maxEvidenceDepth) {
    throw new Error('invalid run spec')
  }
  seen.add(value)
  try {
    if (Array.isArray(value)) {
      const lengthEntry = safeDescriptor(value, 'length')
      if (lengthEntry.unsafe || !Number.isSafeInteger(lengthEntry.value)
        || lengthEntry.value > DYNAMIC_HARD_LIMITS.maxListItems) throw new Error('invalid run spec')
      const keys = Reflect.ownKeys(value)
      if (keys.length !== lengthEntry.value + 1 || !keys.includes('length')) {
        throw new Error('invalid run spec')
      }
      const copy = []
      for (let index = 0; index < lengthEntry.value; index += 1) {
        const entry = safeDescriptor(value, String(index))
        if (entry.unsafe || !entry.found || !keys.includes(String(index))) throw new Error('invalid run spec')
        copy.push(cloneJson(entry.value, seen, depth + 1))
      }
      return Object.freeze(copy)
    }
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) throw new Error('invalid run spec')
    const keys = Reflect.ownKeys(value)
    if (keys.length > DYNAMIC_HARD_LIMITS.maxListItems || keys.some(key => typeof key !== 'string')) {
      throw new Error('invalid run spec')
    }
    const copy = {}
    for (const key of keys.sort()) {
      const entry = safeDescriptor(value, key)
      if (entry.unsafe || !entry.found || !entry.enumerable) throw new Error('invalid run spec')
      copy[key] = cloneJson(entry.value, seen, depth + 1)
    }
    return Object.freeze(copy)
  } finally {
    seen.delete(value)
  }
}

function copyArray(value, cap) {
  try {
    if (!Array.isArray(value)) return { values: [], rejected: true }
    const lengthEntry = safeDescriptor(value, 'length')
    if (lengthEntry.unsafe || !Number.isSafeInteger(lengthEntry.value) || lengthEntry.value > cap) {
      return { values: [], rejected: true }
    }
    const values = []
    for (let index = 0; index < lengthEntry.value; index += 1) {
      const entry = safeDescriptor(value, String(index))
      if (entry.unsafe || !entry.found) return { values: [], rejected: true }
      values.push(entry.value)
    }
    return { values, rejected: false }
  } catch {
    return { values: [], rejected: true }
  }
}

function collectEvidence(parts, completedStages) {
  const evidence = { stages: completedStages.map(stage => ({ stage, status: 'complete' })) }
  for (const field of EVIDENCE_FIELDS) evidence[field] = []
  let rejected = false
  const copyCollection = (part, field, destination) => {
    const entry = safeDescriptor(part, field)
    if (entry.unsafe) {
      rejected = true
      return
    }
    if (!entry.found) return
    const copied = copyArray(entry.value, DYNAMIC_HARD_LIMITS.maxListItems)
    if (copied.rejected) {
      rejected = true
      return
    }
    for (const value of copied.values) destination.push(value)
  }
  for (const part of parts) {
    copyCollection(part, 'stages', evidence.stages)
    for (const field of EVIDENCE_FIELDS) copyCollection(part, field, evidence[field])
    for (const field of ['stdout', 'stderr']) {
      const entry = safeDescriptor(part, field)
      if (entry.unsafe) rejected = true
      else if (entry.found && typeof entry.value === 'string') evidence[field] = entry.value
    }
  }
  return { evidence, rejected }
}

function exactCleanupComplete(value) {
  try {
    if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) return false
    const keys = Reflect.ownKeys(value)
    if (keys.length !== 1 || keys[0] !== 'complete') return false
    const entry = safeDescriptor(value, 'complete')
    return entry.found && !entry.unsafe && entry.enumerable && entry.value === true
  } catch {
    return false
  }
}

function layerFor({ status, options, backend, evidence = null, failures = [] }) {
  const source = { status, backend, profile: options.profile }
  if (evidence) {
    Object.assign(source, evidence)
    source.evidenceDigest = evidenceDigest(evidence)
  }
  if (failures.length > 0) source.failures = [...failures, ...(evidence?.failures ?? [])]
  return normalizeDynamicLayer(source)
}

const executionFailure = code => ({ reason: 'execution-incomplete', code })
const cleanupFailure = code => ({ reason: 'cleanup-uncertain', code })

async function availabilityFor(backend, methods, options, signal) {
  const result = await runBoundedOperation(
    operationSignal => methods.available.call(backend, operationSignal), options.timeoutMs, signal,
  )
  if (result.kind === 'cancelled') return { state: 'cancelled' }
  if (result.kind === 'timeout') return { state: 'unavailable', code: 'backend-timeout' }
  if (result.kind !== 'fulfilled' || ownValue(result.value, 'available') !== true) {
    return { state: 'unavailable', code: 'backend-unavailable' }
  }
  return { state: 'available' }
}

export async function runDynamicAnalysis({ target, options, backend = null, preflight, signal = null } = {}) {
  const normalizedOptions = normalizeDynamicOptions(options)
  if (!normalizedOptions.requested) return emptyDynamicLayer()
  const gate = evaluateDynamicPreflight(preflight)
  if (!gate.allowed) {
    return layerFor({ status: 'refused', options: normalizedOptions, backend: null, failures: [{ reason: 'preflight-refused', code: gate.code }] })
  }
  if (signal?.aborted) {
    return layerFor({ status: 'incomplete', options: normalizedOptions, backend: null, failures: [executionFailure('cancelled')] })
  }
  if (!backend) {
    const capability = resolveDynamicBackend({ backendName: normalizedOptions.backendName })
    return layerFor({ status: 'unavailable', options: normalizedOptions, backend: null, failures: [{ reason: 'backend-unavailable', code: capability.code }] })
  }
  const methods = resolveBackendMethods(backend)
  if (!methods) {
    return layerFor({ status: 'unavailable', options: normalizedOptions, backend: null, failures: [{ reason: 'backend-unavailable', code: 'backend-interface-invalid' }] })
  }
  const availability = await availabilityFor(backend, methods, normalizedOptions, signal)
  if (availability.state === 'cancelled') {
    return layerFor({ status: 'incomplete', options: normalizedOptions, backend: null, failures: [executionFailure('cancelled')] })
  }
  if (availability.state !== 'available') {
    return layerFor({ status: 'unavailable', options: normalizedOptions, backend: null, failures: [{ reason: 'backend-unavailable', code: availability.code }] })
  }

  let safeTarget
  let safeEntrypoints
  try {
    safeTarget = cloneJson(target)
    safeEntrypoints = cloneJson(preflight.entrypoints)
  } catch {
    return layerFor({ status: 'incomplete', options: normalizedOptions, backend: 'injected', failures: [executionFailure('run-spec-invalid')] })
  }
  const runId = randomUUID()
  const canaries = createCanarySet({ runId })
  const runSpec = Object.freeze({
    runId, target: safeTarget, profile: normalizedOptions.profile, entrypoints: safeEntrypoints, canaries,
  })
  const evidenceParts = []
  const completedStages = []
  const failures = []
  let handle = null
  let cleanupPromise = null
  let operation = null

  const cleanupOnce = resource => {
    if (cleanupPromise) return cleanupPromise
    cleanupPromise = runBoundedOperation(
      cleanupSignal => methods.cleanup.call(backend, resource, cleanupSignal), normalizedOptions.timeoutMs,
    ).then(result => {
      if (result.kind === 'timeout') return cleanupFailure('cleanup-timeout')
      if (result.kind !== 'fulfilled') return cleanupFailure('cleanup-failed')
      if (!exactCleanupComplete(result.value)) {
        return cleanupFailure(result.value && ownValue(result.value, 'complete') === false ? 'cleanup-incomplete' : 'cleanup-invalid')
      }
      return null
    }, () => cleanupFailure('cleanup-failed'))
    return cleanupPromise
  }

  const deferCleanup = (pendingOperation, lateHandle = false) => {
    failures.push(cleanupFailure('operation-not-quiesced'))
    void pendingOperation.settled.then(late => {
      const resource = lateHandle ? late.value : handle
      if (late.state === 'fulfilled' && resource !== null && resource !== undefined) return cleanupOnce(resource)
      return null
    }).catch(() => {})
  }

  try {
    operation = await runBoundedOperation(
      operationSignal => methods.prepare.call(backend, runSpec, operationSignal), normalizedOptions.timeoutMs, signal,
    )
    if (operation.kind !== 'fulfilled') {
      failures.push(executionFailure(operation.kind === 'cancelled' ? 'cancelled' : operation.kind === 'timeout' ? 'timeout' : 'prepare-failed'))
      if (!operation.quiesced) deferCleanup(operation, true)
    } else {
      handle = operation.value
      for (const name of DYNAMIC_STAGES) {
        operation = await runBoundedOperation(
          operationSignal => methods.runStage.call(backend, handle, Object.freeze({ name, signal: operationSignal })),
          normalizedOptions.timeoutMs, signal,
        )
        if (operation.kind !== 'fulfilled') {
          failures.push(executionFailure(operation.kind === 'cancelled' ? 'cancelled' : operation.kind === 'timeout' ? 'timeout' : 'stage-failed'))
          if (!operation.quiesced) deferCleanup(operation)
          break
        }
        evidenceParts.push(operation.value)
        completedStages.push(name)
      }
      if (failures.length === 0) {
        operation = await runBoundedOperation(
          operationSignal => methods.collect.call(backend, handle, operationSignal), normalizedOptions.timeoutMs, signal,
        )
        if (operation.kind !== 'fulfilled') {
          failures.push(executionFailure(operation.kind === 'cancelled' ? 'cancelled' : operation.kind === 'timeout' ? 'timeout' : 'collection-failed'))
          if (!operation.quiesced) deferCleanup(operation)
        } else evidenceParts.push(operation.value)
      }
    }
  } catch {
    failures.push(executionFailure('execution-failed'))
  } finally {
    if (handle !== null && handle !== undefined && !(operation && !operation.quiesced)) {
      const cleanupResult = await cleanupOnce(handle)
      if (cleanupResult) failures.push(cleanupResult)
    }
  }

  const collected = collectEvidence(evidenceParts, completedStages)
  let evidence
  try {
    evidence = normalizeDynamicEvidence(collected.evidence, { canaries, limits: DYNAMIC_HARD_LIMITS })
  } catch {
    evidence = normalizeDynamicEvidence({}, { canaries, limits: DYNAMIC_HARD_LIMITS })
    collected.rejected = true
  }
  if (collected.rejected || evidence.failures.some(item => item.reason === 'evidence-rejected')) {
    failures.push(executionFailure('evidence-invalid'))
  }
  return layerFor({
    status: failures.length > 0 ? 'incomplete' : 'complete', options: normalizedOptions,
    backend: 'injected', evidence, failures,
  })
}
