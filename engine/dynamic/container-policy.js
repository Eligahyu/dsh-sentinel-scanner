import { isAbsolute } from 'node:path'

export const CONTAINER_PHASE_B_LIMITS = Object.freeze({
  timeoutMs: 30000,
  memoryBytes: 512 * 1024 * 1024,
  pidsLimit: 64,
  outputBytes: 128 * 1024,
})

export const SUPPORTED_CONTAINER_ENGINES = Object.freeze(['docker', 'podman'])

export const REQUIRED_IMAGE_DIGEST = Object.freeze(/^\S+@sha256:[a-f0-9]{64}$/)

const FORBIDDEN_OPTIONS = Object.freeze([
  'args', 'command', 'engineSocket', 'extraArgs', 'flags', 'ipcSocket', 'mounts',
  'socket', 'volumes',
])

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function requiredString(value, name) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) {
    throw new Error(`invalid container ${name}`)
  }
  return value
}

function validateImage(image) {
  requiredString(image, 'image')
  if (!REQUIRED_IMAGE_DIGEST.test(image)) {
    throw new Error('container image must be immutable and digest-pinned')
  }
  return image
}

function validateStagedRoot(stagedRoot) {
  requiredString(stagedRoot, 'staged root')
  if (!isAbsolute(stagedRoot)) throw new Error('container staged root must be absolute')
  if (/[\r\n]/.test(stagedRoot)) throw new Error('invalid container staged root')
  if (/docker\.sock|podman\.sock|[/\\]var[/\\]run|[/\\]run[/\\](?:docker|podman)/i.test(stagedRoot)) {
    throw new Error('container engine socket path is not allowed')
  }
  return stagedRoot
}

function boundedLimit(value, name, maximum) {
  if (value === undefined) return maximum
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 1) {
    throw new Error(`invalid container ${name}`)
  }
  return Math.min(maximum, Math.floor(value))
}

function normalizeLimits(input) {
  const source = input === undefined ? {} : input
  if (!isRecord(source)) throw new Error('invalid container limits')
  return Object.freeze({
    timeoutMs: boundedLimit(source.timeoutMs, 'timeout', CONTAINER_PHASE_B_LIMITS.timeoutMs),
    memoryBytes: boundedLimit(source.memoryBytes, 'memory', CONTAINER_PHASE_B_LIMITS.memoryBytes),
    pidsLimit: boundedLimit(source.pidsLimit, 'pids limit', CONTAINER_PHASE_B_LIMITS.pidsLimit),
    outputBytes: boundedLimit(source.outputBytes, 'output', CONTAINER_PHASE_B_LIMITS.outputBytes),
  })
}

export function normalizeContainerPolicy(input = {}) {
  if (!isRecord(input)) throw new Error('invalid container policy')
  for (const key of FORBIDDEN_OPTIONS) {
    if (Object.hasOwn(input, key)) throw new Error(`container option is not allowed: ${key}`)
  }

  const engine = input.engine ?? 'docker'
  if (!SUPPORTED_CONTAINER_ENGINES.includes(engine)) {
    throw new Error(`invalid container engine: ${String(engine)}`)
  }
  const image = validateImage(input.image)
  const stagedRoot = validateStagedRoot(input.stagedRoot)
  const network = input.network ?? input.networkMode ?? 'none'
  if (network !== 'none') throw new Error('container network must be none')
  if (input.pid !== undefined && input.pid !== 'private') throw new Error('container pid namespace must be private')
  if (input.ipc !== undefined && input.ipc !== 'private') throw new Error('container ipc namespace must be private')
  if (input.privileged !== undefined && input.privileged !== false) throw new Error('privileged containers are not allowed')

  const limits = normalizeLimits(input.limits ?? input)
  const policy = {
    engine,
    image,
    stagedRoot,
    network: 'none',
    pid: 'private',
    ipc: 'private',
    privileged: false,
    limits,
  }
  return Object.freeze(policy)
}

// Stable aliases keep the policy vocabulary available to later backend layers.
export const CONTAINER_HARD_LIMITS = CONTAINER_PHASE_B_LIMITS
export const PHASE_B_LIMITS = CONTAINER_PHASE_B_LIMITS
export const SUPPORTED_ENGINES = SUPPORTED_CONTAINER_ENGINES
export const IMAGE_DIGEST_PATTERN = REQUIRED_IMAGE_DIGEST
