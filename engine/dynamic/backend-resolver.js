import { createContainerBackend } from './container-backend.js'
import { REQUIRED_IMAGE_DIGEST, SUPPORTED_CONTAINER_ENGINES } from './container-policy.js'

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

const TRUSTED_IMAGE_DESCRIPTORS = new WeakSet()
const TRUSTED_IMAGE_OPTIONS = new WeakMap()

/** Symbol-only seam used by tests/deployment wiring; CLI/config cannot name it. */
export const TRUSTED_DYNAMIC_IMAGE = Symbol('dsh-sentinel.trusted-dynamic-image')

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function fixedUnavailable(code = PHASE_B_UNAVAILABLE.code) {
  return Object.freeze({ available: false, backend: null, code })
}

function createDescriptor(image, options = {}) {
  if (typeof image !== 'string' || !REQUIRED_IMAGE_DIGEST.test(image)) return null
  if (!isRecord(options)) return null
  const commandRunner = options.commandRunner
  const stagingFactory = options.stagingFactory
  const environment = options.environment
  if (commandRunner !== undefined && typeof commandRunner !== 'function') return null
  if (stagingFactory !== undefined && typeof stagingFactory !== 'function') return null
  if (environment !== undefined && !isRecord(environment)) return null
  const descriptor = Object.freeze({ image })
  TRUSTED_IMAGE_DESCRIPTORS.add(descriptor)
  TRUSTED_IMAGE_OPTIONS.set(descriptor, Object.freeze({
    ...(commandRunner ? { commandRunner } : {}),
    ...(stagingFactory ? { stagingFactory } : {}),
    ...(environment ? { environment } : {}),
  }))
  return descriptor
}

/** Build-time/deployment API for a scanner-owned immutable image descriptor. */
export function createTrustedDynamicImage(image) {
  return createDescriptor(image)
}

/** Test-only API; it can replace process execution and staging, but not policy. */
export function createTrustedDynamicImageForTests(image, options = {}) {
  return createDescriptor(image, options)
}

function trustedDescriptor(value) {
  return isRecord(value) && TRUSTED_IMAGE_DESCRIPTORS.has(value) ? value : null
}

function backendOptions(engine, descriptor, stagingCapability) {
  const options = TRUSTED_IMAGE_OPTIONS.get(descriptor) ?? {}
  return {
    engine,
    image: descriptor.image,
    stagingCapability,
    requireLocalImage: true,
    ...(options.commandRunner ? { commandRunner: options.commandRunner } : {}),
    ...(options.environment ? { environment: options.environment } : {}),
  }
}

function createCandidate(engine, descriptor, stagingCapability) {
  return createContainerBackend(backendOptions(engine, descriptor, stagingCapability))
}

function createAutoBackend(descriptor, stagingCapability) {
  const candidates = SUPPORTED_CONTAINER_ENGINES.map(engine => ({
    engine,
    backend: createCandidate(engine, descriptor, stagingCapability),
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

export { createContainerBackend }

/**
 * Resolve only scanner-owned production backends. `injectedBackend` is retained
 * for the existing test seam and is never consulted by CLI/config selection.
 */
export function resolveDynamicBackend({
  backendName = 'auto',
  injectedBackend,
  trustedImage,
  stagingCapability,
} = {}) {
  if (injectedBackend && typeof injectedBackend === 'object') {
    return Object.freeze({ available: true, backend: injectedBackend, backendName: 'injected' })
  }

  const descriptor = trustedDescriptor(trustedImage)
  if (!descriptor) return PHASE_B_UNAVAILABLE
  if (!['auto', ...SUPPORTED_CONTAINER_ENGINES].includes(backendName)) return INVALID_PRODUCTION_BACKEND

  // First pass validates trusted configuration without allocating a backend or
  // touching an engine. The orchestrator supplies the staging capability later.
  if (stagingCapability === undefined) {
    return Object.freeze({ available: true, backend: null, backendName })
  }

  const backend = backendName === 'auto'
    ? createAutoBackend(descriptor, stagingCapability)
    : createCandidate(backendName, descriptor, stagingCapability)
  return Object.freeze({ available: true, backend, backendName })
}

export function stagingFactoryForTrustedImage(trustedImage) {
  const descriptor = trustedDescriptor(trustedImage)
  return descriptor ? TRUSTED_IMAGE_OPTIONS.get(descriptor)?.stagingFactory : undefined
}
