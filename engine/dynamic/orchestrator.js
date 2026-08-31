import { randomUUID } from 'node:crypto'
import { createCanarySet } from './canaries.js'
import { emptyDynamicLayer, normalizeDynamicLayer } from './contracts.js'
import { evidenceDigest, normalizeDynamicEvidence } from './evidence.js'
import { DYNAMIC_HARD_LIMITS, normalizeDynamicOptions } from './policy.js'
import { resolveDynamicBackend } from './backend-resolver.js'

export const DYNAMIC_STAGES = Object.freeze(['load', 'registration', 'invocation'])

const EVIDENCE_FIELDS = Object.freeze([
  'networkAttempts', 'dnsQueries', 'processes', 'fileEvents',
  'canaryEvents', 'policyViolations', 'limitations',
])

class DeadlineExceeded extends Error {}
class RunCancelled extends Error {}

function ownValue(record, key) {
  try {
    if (!record || typeof record !== 'object') return undefined
    const descriptor = Object.getOwnPropertyDescriptor(record, key)
    return descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined
  } catch {
    return undefined
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

function errorCode(error, fallback) {
  if (error instanceof DeadlineExceeded) return 'timeout'
  if (error instanceof RunCancelled) return 'cancelled'
  return fallback
}

async function withinDeadline(operation, timeoutMs, signal = null) {
  if (signal?.aborted) throw new RunCancelled()
  let timer = null
  let removeAbort = null
  try {
    return await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new DeadlineExceeded()), timeoutMs)
      const abort = () => reject(new RunCancelled())
      if (signal) {
        signal.addEventListener('abort', abort, { once: true })
        removeAbort = () => signal.removeEventListener('abort', abort)
      }
      Promise.resolve()
        .then(operation)
        .then(resolve, reject)
    })
  } finally {
    clearTimeout(timer)
    removeAbort?.()
  }
}

function collectEvidence(parts, completedStages) {
  const merged = {
    stages: completedStages.map(stage => ({ stage, status: 'complete' })),
  }
  for (const field of EVIDENCE_FIELDS) merged[field] = []
  for (const part of parts) {
    const stages = ownValue(part, 'stages')
    if (Array.isArray(stages)) merged.stages.push(...stages)
    for (const field of EVIDENCE_FIELDS) {
      const value = ownValue(part, field)
      if (Array.isArray(value)) merged[field].push(...value)
    }
    for (const field of ['stdout', 'stderr']) {
      const value = ownValue(part, field)
      if (typeof value === 'string') merged[field] = value
    }
  }
  return merged
}

function layerFor({ status, options, backend, evidence = null, failure = null }) {
  const source = {
    status,
    backend: typeof backend === 'string' ? backend : null,
    profile: options.profile,
  }
  if (evidence) {
    Object.assign(source, evidence)
    source.evidenceDigest = evidenceDigest(evidence)
  }
  if (failure) source.failures = [failure, ...(evidence?.failures ?? [])]
  return normalizeDynamicLayer(source)
}

async function availabilityFor(backend, options) {
  if (!backend) return resolveDynamicBackend({ backendName: options.backendName })
  try {
    const capability = await backend.available()
    if (!capability || capability.available !== true) {
      return Object.freeze({
        available: false,
        backend: null,
        code: 'backend-unavailable',
      })
    }
    return Object.freeze({
      available: true,
      backend,
      name: typeof capability.backend === 'string' ? capability.backend : options.backendName,
    })
  } catch {
    return Object.freeze({ available: false, backend: null, code: 'backend-unavailable' })
  }
}

export async function runDynamicAnalysis({
  target,
  options,
  backend = null,
  preflight,
  signal = null,
} = {}) {
  const normalizedOptions = normalizeDynamicOptions(options)
  if (!normalizedOptions.requested) return emptyDynamicLayer()

  const gate = evaluateDynamicPreflight(preflight)
  if (!gate.allowed) {
    return layerFor({
      status: 'refused', options: normalizedOptions, backend: null,
      failure: { reason: 'preflight-refused', code: gate.code },
    })
  }

  const capability = await availabilityFor(backend, normalizedOptions)
  if (!capability.available) {
    return layerFor({
      status: 'unavailable', options: normalizedOptions, backend: null,
      failure: { reason: 'backend-unavailable', code: capability.code },
    })
  }

  const runId = randomUUID()
  const canaries = createCanarySet({ runId })
  const runSpec = Object.freeze({
    runId,
    target,
    profile: normalizedOptions.profile,
    entrypoints: Object.freeze([...preflight.entrypoints]),
    canaries,
  })
  const evidenceParts = []
  const completedStages = []
  let handle = null
  let failure = null

  try {
    handle = await withinDeadline(
      () => capability.backend.prepare(runSpec), normalizedOptions.timeoutMs, signal,
    )
    for (const name of DYNAMIC_STAGES) {
      const stageSpec = Object.freeze({ name, signal })
      const stageEvidence = await withinDeadline(
        () => capability.backend.runStage(handle, stageSpec), normalizedOptions.timeoutMs, signal,
      )
      evidenceParts.push(stageEvidence)
      completedStages.push(name)
    }
    evidenceParts.push(await withinDeadline(
      () => capability.backend.collect(handle), normalizedOptions.timeoutMs, signal,
    ))
  } catch (error) {
    failure = { reason: 'execution-incomplete', code: errorCode(error, completedStages.length < DYNAMIC_STAGES.length ? 'stage-failed' : 'collection-failed') }
  } finally {
    if (handle !== null && handle !== undefined) {
      try {
        const cleanup = await withinDeadline(
          () => capability.backend.cleanup(handle), normalizedOptions.timeoutMs,
        )
        if (!cleanup || cleanup.complete !== true) {
          failure = { reason: 'execution-incomplete', code: 'cleanup-incomplete' }
        }
      } catch {
        failure = { reason: 'execution-incomplete', code: 'cleanup-incomplete' }
      }
    }
  }

  const evidence = normalizeDynamicEvidence(
    collectEvidence(evidenceParts, completedStages),
    { canaries, limits: DYNAMIC_HARD_LIMITS },
  )
  return layerFor({
    status: failure ? 'incomplete' : 'complete',
    options: normalizedOptions,
    backend: capability.name,
    evidence,
    failure,
  })
}
