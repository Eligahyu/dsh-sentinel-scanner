import { posix, win32 } from 'node:path'

export const CONTAINER_PHASE_B_LIMITS = Object.freeze({
  timeoutMs: 30000,
  memoryBytes: 512 * 1024 * 1024,
  pidsLimit: 64,
  outputBytes: 128 * 1024,
})

export const SUPPORTED_CONTAINER_ENGINES = Object.freeze(['docker', 'podman'])

export const REQUIRED_IMAGE_DIGEST = Object.freeze(/^[a-z0-9](?:[a-z0-9._/-]{0,254})@sha256:[a-f0-9]{64}$/)

const MAX_IMAGE_LENGTH = 512
const MAX_PATH_LENGTH = 512
const STAGING_SNAPSHOT_NAME = /^(?:snapshot|run)-[a-z0-9][a-z0-9._-]{7,95}$/i
const CONTROLLED_STAGING_ROOT_NAME = /^dsh-[a-z0-9._-]*staging(?:-[a-z0-9._-]+)?$/i
const FORBIDDEN_OPTIONS = Object.freeze([
  'args', 'command', 'engineSocket', 'extraArgs', 'flags', 'ipcSocket', 'mounts',
  'socket', 'volumes',
])
const STAGING_CAPABILITY_BRAND = Symbol('dsh-staging-capability')
const STAGING_CAPABILITY_VALUE = Object.freeze({})

function policyError(code) {
  const error = new Error(code)
  error.code = code
  return error
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function pathApi(value) {
  return /^[A-Za-z]:[\\/]/.test(value) ? win32 : posix
}

function isAbsolutePath(value) {
  return /^[A-Za-z]:[\\/]/.test(value) ? win32.isAbsolute(value) : posix.isAbsolute(value)
}

function validatePath(value, code = 'invalid-staged-root') {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_PATH_LENGTH) {
    throw policyError(code)
  }
  if (!isAbsolutePath(value) || /[,;=|\r\n\0'"`]/.test(value)) throw policyError(code)
  if (!/^[A-Za-z0-9._:\\\/-]+$/.test(value)) throw policyError(code)

  const api = pathApi(value)
  if (api.normalize(value) !== value) throw policyError(code)
  const segments = value.split(/[\\/]/)
  if (segments.some((segment) => segment === '.' || segment === '..')) throw policyError(code)
  if (segments.some((segment) => /(?:docker|podman)\.sock$/i.test(segment))) {
    throw policyError('engine-socket-path')
  }
  if (/(?:^|[\\/])(?:run|var[\\/]run)[\\/](?:docker|podman)(?:[\\/]|$)/i.test(value)) {
    throw policyError('engine-socket-path')
  }
  return value
}

function validateImage(image) {
  if (typeof image !== 'string' || image.length === 0 || image.length > MAX_IMAGE_LENGTH) {
    throw policyError('invalid-image')
  }
  if (!REQUIRED_IMAGE_DIGEST.test(image)) throw policyError('invalid-image')
  return image
}

function validateSnapshotName(snapshot) {
  const api = pathApi(snapshot)
  if (!STAGING_SNAPSHOT_NAME.test(api.basename(snapshot))) throw policyError('invalid-staged-root')
}

function isDescendant(root, snapshot) {
  const api = pathApi(root)
  const relative = api.relative(root, snapshot)
  return relative.length > 0 && relative !== '..'
    && !relative.startsWith(`..${api.sep}`) && !api.isAbsolute(relative)
}

function validateSnapshotPair(root, snapshot, { requireControlledRoot = false } = {}) {
  const normalizedRoot = validatePath(root, 'invalid-staging-root')
  const normalizedSnapshot = validatePath(snapshot)
  if (requireControlledRoot && !CONTROLLED_STAGING_ROOT_NAME.test(pathApi(normalizedRoot).basename(normalizedRoot))) {
    throw policyError('invalid-staging-root')
  }
  if (!isDescendant(normalizedRoot, normalizedSnapshot)) throw policyError('staging-capability-mismatch')
  validateSnapshotName(normalizedSnapshot)
  return { root: normalizedRoot, snapshot: normalizedSnapshot }
}

function readCapability(value) {
  if (!isRecord(value)) throw policyError('invalid-staging-capability')
  const brand = Object.getOwnPropertyDescriptor(value, STAGING_CAPABILITY_BRAND)
  const root = Object.getOwnPropertyDescriptor(value, 'root')
  const snapshot = Object.getOwnPropertyDescriptor(value, 'snapshot')
  if (!brand || brand.value !== STAGING_CAPABILITY_VALUE
    || !root || !Object.hasOwn(root, 'value')
    || !snapshot || !Object.hasOwn(snapshot, 'value')) {
    throw policyError('invalid-staging-capability')
  }
  return validateSnapshotPair(root.value, snapshot.value)
}

export function createStagingCapability({ root, snapshot } = {}) {
  const pair = validateSnapshotPair(root, snapshot, { requireControlledRoot: true })
  const capability = { root: pair.root, snapshot: pair.snapshot }
  Object.defineProperty(capability, STAGING_CAPABILITY_BRAND, {
    value: STAGING_CAPABILITY_VALUE,
    enumerable: false,
    writable: false,
    configurable: false,
  })
  return Object.freeze(capability)
}

function resolveStaging(input, stagedRoot) {
  if (input.stagingCapability !== undefined) {
    const capability = readCapability(input.stagingCapability)
    if (capability.snapshot !== stagedRoot) throw policyError('staging-capability-mismatch')
    return capability
  }
  if (input.stagingRoot !== undefined) {
    return validateSnapshotPair(input.stagingRoot, stagedRoot, { requireControlledRoot: true })
  }
  throw policyError('staging-capability-required')
}

function boundedLimit(value, name, maximum) {
  if (value === undefined) return maximum
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 1) {
    throw policyError(`invalid-container-${name}`)
  }
  return Math.min(maximum, Math.floor(value))
}

function normalizeLimits(input) {
  const source = input === undefined ? {} : input
  if (!isRecord(source)) throw policyError('invalid-container-limits')
  return Object.freeze({
    timeoutMs: boundedLimit(source.timeoutMs, 'timeout', CONTAINER_PHASE_B_LIMITS.timeoutMs),
    memoryBytes: boundedLimit(source.memoryBytes, 'memory', CONTAINER_PHASE_B_LIMITS.memoryBytes),
    pidsLimit: boundedLimit(source.pidsLimit, 'pids-limit', CONTAINER_PHASE_B_LIMITS.pidsLimit),
    outputBytes: boundedLimit(source.outputBytes, 'output', CONTAINER_PHASE_B_LIMITS.outputBytes),
  })
}

export function normalizeContainerPolicy(input = {}) {
  if (!isRecord(input)) throw policyError('invalid-container-policy')
  for (const key of FORBIDDEN_OPTIONS) {
    if (Object.hasOwn(input, key)) throw policyError('user-container-arguments')
  }

  const engine = input.engine ?? 'docker'
  if (!SUPPORTED_CONTAINER_ENGINES.includes(engine)) throw policyError('invalid-engine')
  const image = validateImage(input.image)
  const stagedRoot = validatePath(input.stagedRoot)
  const staging = resolveStaging(input, stagedRoot)

  const hasNetwork = input.network !== undefined
  const hasNetworkMode = input.networkMode !== undefined
  if (hasNetwork && hasNetworkMode && input.network !== input.networkMode) {
    throw policyError('conflicting-network-policy')
  }
  const network = hasNetwork ? input.network : hasNetworkMode ? input.networkMode : 'none'
  if (network !== 'none') throw policyError('host-network-not-allowed')
  if (input.pid !== undefined && input.pid !== 'private') throw policyError('host-pid-not-allowed')
  if (input.ipc !== undefined && input.ipc !== 'private') throw policyError('host-ipc-not-allowed')
  if (input.privileged !== undefined && input.privileged !== false) throw policyError('privileged-not-allowed')

  const limits = normalizeLimits(input.limits ?? input)
  return Object.freeze({
    engine,
    image,
    stagedRoot,
    stagingRoot: staging.root,
    network: 'none',
    pid: 'private',
    ipc: 'private',
    privileged: false,
    limits,
  })
}

// Stable aliases keep the policy vocabulary available to later backend layers.
export const CONTAINER_HARD_LIMITS = CONTAINER_PHASE_B_LIMITS
export const PHASE_B_LIMITS = CONTAINER_PHASE_B_LIMITS
export const SUPPORTED_ENGINES = SUPPORTED_CONTAINER_ENGINES
export const IMAGE_DIGEST_PATTERN = REQUIRED_IMAGE_DIGEST
