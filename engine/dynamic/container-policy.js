import { mkdirSync, mkdtempSync } from 'node:fs'
import { randomUUID } from 'node:crypto'
import { tmpdir } from 'node:os'
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
const FORBIDDEN_OPTIONS = Object.freeze([
  'args', 'command', 'engineSocket', 'extraArgs', 'flags', 'ipcSocket', 'mounts',
  'socket', 'volumes',
])
const TRUSTED_STAGING_CAPABILITIES = new WeakSet()

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

function validateSnapshotPair(root, snapshot) {
  const normalizedRoot = validatePath(root, 'invalid-staging-root')
  const normalizedSnapshot = validatePath(snapshot)
  if (!isDescendant(normalizedRoot, normalizedSnapshot)) throw policyError('staging-capability-mismatch')
  validateSnapshotName(normalizedSnapshot)
  return { root: normalizedRoot, snapshot: normalizedSnapshot }
}

function createOwnedStagingWorkspace() {
  const temporaryDirectory = tmpdir()
  const api = pathApi(temporaryDirectory)
  const base = api.resolve(temporaryDirectory)
  validatePath(base, 'invalid-staging-root')
  const root = mkdtempSync(api.join(base, 'dsh-sentinel-staging-'))
  const snapshot = api.join(root, `snapshot-${randomUUID().replaceAll('-', '')}`)
  mkdirSync(snapshot)
  return validateSnapshotPair(root, snapshot)
}

function isTrustedStagingCapability(value) {
  return isRecord(value) && TRUSTED_STAGING_CAPABILITIES.has(value)
}

function readCapability(value) {
  if (!isTrustedStagingCapability(value)) throw policyError('invalid-staging-capability')
  const root = Object.getOwnPropertyDescriptor(value, 'root')
  const snapshot = Object.getOwnPropertyDescriptor(value, 'snapshot')
  if (!root || !Object.hasOwn(root, 'value')
    || !snapshot || !Object.hasOwn(snapshot, 'value')) {
    throw policyError('invalid-staging-capability')
  }
  return validateSnapshotPair(root.value, snapshot.value)
}

export function createStagingCapability(...args) {
  if (args.length !== 0) throw policyError('staging-capability-factory-arguments')
  const pair = createOwnedStagingWorkspace()
  const capability = { root: pair.root, snapshot: pair.snapshot }
  Object.freeze(capability)
  TRUSTED_STAGING_CAPABILITIES.add(capability)
  return capability
}

function resolveStaging(input) {
  if (Object.hasOwn(input, 'stagedRoot')) throw policyError('raw-staged-root-not-allowed')
  if (Object.hasOwn(input, 'stagingRoot')) throw policyError('raw-staging-root-not-allowed')
  if (!Object.hasOwn(input, 'stagingCapability') || input.stagingCapability === undefined) {
    throw policyError('staging-capability-required')
  }
  const capability = readCapability(input.stagingCapability)
  return capability
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
  const staging = resolveStaging(input)
  const stagedRoot = staging.snapshot

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
