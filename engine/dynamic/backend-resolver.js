import { createContainerBackend } from './container-backend.js'
import {
  normalizeContainerPolicy,
  SUPPORTED_CONTAINER_ENGINES,
} from './container-policy.js'

const PHASE_B_UNAVAILABLE = Object.freeze({
  available: false,
  backend: null,
  code: 'trusted-image-unavailable',
})

const INVALID_PRODUCTION_BACKEND = Object.freeze({
  available: false,
  backend: null,
  code: 'backend-selection-refused',
})

// Deployment may add an exact digest here as a scanner-owned asset. An empty
// registry intentionally keeps this build unavailable until such an asset is
// shipped; callers cannot extend or replace it at runtime.
const APPROVED_PHASE_B_IMAGES = Object.freeze({
  docker: null,
  podman: null,
})

const STAGING_VALIDATION_IMAGE = `dsh-sentinel/staging-validation@sha256:${'0'.repeat(64)}`

function fixedUnavailable(code = PHASE_B_UNAVAILABLE.code) {
  return Object.freeze({ available: false, backend: null, code })
}

function stagingCapabilityOwned(value) {
  try {
    normalizeContainerPolicy({
      engine: 'docker',
      image: STAGING_VALIDATION_IMAGE,
      stagingCapability: value,
    })
    return true
  } catch {
    return false
  }
}

function createCandidate(engine, image, stagingCapability) {
  return createContainerBackend({
    engine,
    image,
    stagingCapability,
    requireLocalImage: true,
  })
}

function createAutoBackend(image, stagingCapability) {
  const candidates = SUPPORTED_CONTAINER_ENGINES.map(engine => ({
    engine,
    backend: createCandidate(engine, image, stagingCapability),
  }))
  let selected = null
  const delegate = (method, args) => {
    if (!selected) throw new Error('container-not-available')
    return selected.backend[method](...args)
  }
  return Object.freeze({
    async available(signal) {
      let last = fixedUnavailable('container-engine-unavailable')
      for (const candidate of candidates) {
        const result = await candidate.backend.available(signal)
        if (result?.available === true) {
          selected = candidate
          return result
        }
        last = result
      }
      return last
    },
    prepare(...args) { return delegate('prepare', args) },
    runStage(...args) { return delegate('runStage', args) },
    collect(...args) { return delegate('collect', args) },
    cleanup(...args) { return delegate('cleanup', args) },
  })
}

export function resolveDynamicBackend({ backendName = 'auto', stagingCapability } = {}) {
  if (!['auto', ...SUPPORTED_CONTAINER_ENGINES].includes(backendName)) return INVALID_PRODUCTION_BACKEND
  if (stagingCapability !== undefined && !stagingCapabilityOwned(stagingCapability)) {
    return INVALID_PRODUCTION_BACKEND
  }

  const image = backendName === 'auto'
    ? APPROVED_PHASE_B_IMAGES.docker ?? APPROVED_PHASE_B_IMAGES.podman
    : APPROVED_PHASE_B_IMAGES[backendName]
  if (typeof image !== 'string') return PHASE_B_UNAVAILABLE

  if (stagingCapability === undefined) {
    return Object.freeze({ available: true, backend: null, backendName })
  }

  const backend = backendName === 'auto'
    ? createAutoBackend(image, stagingCapability)
    : createCandidate(backendName, image, stagingCapability)
  return Object.freeze({ available: true, backend, backendName })
}
