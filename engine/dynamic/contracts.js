export const DYNAMIC_STATUSES = Object.freeze([
  'not-requested',
  'unavailable',
  'refused',
  'complete',
  'incomplete',
])

const LIST_FIELDS = Object.freeze([
  'stages',
  'networkAttempts',
  'dnsQueries',
  'processes',
  'fileEvents',
  'canaryEvents',
  'policyViolations',
  'limitations',
  'failures',
])

export function emptyDynamicLayer() {
  return {
    status: 'not-requested', requested: false, complete: false,
    backend: null, profile: null, stages: [], networkAttempts: [],
    dnsQueries: [], processes: [], fileEvents: [], canaryEvents: [],
    policyViolations: [], limitations: [], failures: [], evidenceDigest: null,
  }
}

export function normalizeDynamicLayer(value = {}) {
  const input = value && typeof value === 'object' && !Array.isArray(value) ? value : {}
  const layer = emptyDynamicLayer()
  const status = DYNAMIC_STATUSES.includes(input.status) ? input.status : layer.status

  layer.status = status
  layer.requested = input.requested === true
  layer.complete = input.complete === true
  layer.backend = typeof input.backend === 'string' ? input.backend : null
  layer.profile = typeof input.profile === 'string' ? input.profile : null
  layer.evidenceDigest = typeof input.evidenceDigest === 'string' ? input.evidenceDigest : null

  for (const field of LIST_FIELDS) {
    layer[field] = Array.isArray(input[field]) ? [...input[field]] : []
  }

  if (status === 'not-requested') {
    layer.requested = false
    layer.complete = false
    layer.backend = null
    layer.profile = null
  } else if (status === 'complete') {
    layer.requested = true
    layer.complete = true
  } else {
    layer.requested = true
    layer.complete = false
  }

  return layer
}
