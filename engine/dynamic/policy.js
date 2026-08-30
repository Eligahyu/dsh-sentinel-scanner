export const DYNAMIC_HARD_LIMITS = Object.freeze({
  defaultTimeoutMs: 15000,
  minTimeoutMs: 1000,
  maxTimeoutMs: 30000,
  maxEvents: 2000,
  maxTextBytes: 262144,
  maxListItems: 500,
  maxEvidenceDepth: 8,
})

const DYNAMIC_BACKENDS = Object.freeze(['auto', 'docker', 'podman'])
const DYNAMIC_PROFILES = Object.freeze(['observe'])

export function normalizeDynamicOptions(input = {}) {
  const backendName = input.dynamicBackend ?? 'auto'
  if (!DYNAMIC_BACKENDS.includes(backendName)) {
    throw new Error(`invalid dynamic backend: ${String(backendName)}`)
  }

  const profile = input.dynamicProfile ?? 'observe'
  if (!DYNAMIC_PROFILES.includes(profile)) {
    throw new Error(`invalid dynamic profile: ${String(profile)}`)
  }

  const rawTimeout = input.dynamicTimeoutMs === undefined
    ? DYNAMIC_HARD_LIMITS.defaultTimeoutMs
    : input.dynamicTimeoutMs
  let timeoutMs
  if (typeof rawTimeout === 'number') {
    if (!Number.isFinite(rawTimeout)) {
      throw new Error('invalid dynamic timeout: value must be finite')
    }
    timeoutMs = rawTimeout
  } else if (typeof rawTimeout === 'string' && rawTimeout.trim().length > 0) {
    timeoutMs = Number(rawTimeout)
    if (!Number.isFinite(timeoutMs)) {
      throw new Error('invalid dynamic timeout: value must be finite')
    }
  } else {
    throw new Error('invalid dynamic timeout: value must be finite')
  }

  return {
    requested: input.dynamic === true,
    backendName,
    profile,
    timeoutMs: Math.min(
      DYNAMIC_HARD_LIMITS.maxTimeoutMs,
      Math.max(DYNAMIC_HARD_LIMITS.minTimeoutMs, timeoutMs),
    ),
  }
}
