import {
  CONTAINER_PHASE_B_LIMITS,
  REQUIRED_IMAGE_DIGEST,
  SUPPORTED_CONTAINER_ENGINES,
  normalizeContainerPolicy,
} from './container-policy.js'

const ACTIONS = Object.freeze(new Set(['run']))
const DISALLOWED_KEYS = Object.freeze([
  'args', 'command', 'entrypoint', 'extraArgs', 'flags', 'hostConfig', 'mounts',
  'runtime', 'volumes',
])
const SAFE_LABEL = /^dsh-[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

export function validateEngineName(value) {
  if (!SUPPORTED_CONTAINER_ENGINES.includes(value)) throw commandError('invalid-engine')
  return value
}

function commandError(code) {
  const error = new Error(code)
  error.code = code
  return error
}

function validateLabel(value) {
  if (typeof value !== 'string' || value.length > 64 || !SAFE_LABEL.test(value)) throw commandError('invalid-label')
  return value
}

function rejectUnsafeOptions(input) {
  if (Object.hasOwn(input, 'stagedRoot')) throw commandError('raw-staged-root-not-allowed')
  if (Object.hasOwn(input, 'stagingRoot')) throw commandError('raw-staging-root-not-allowed')
  for (const key of DISALLOWED_KEYS) {
    if (Object.hasOwn(input, key)) throw commandError('user-container-arguments')
  }
  for (const key of ['engineSocket', 'socket', 'ipcSocket']) {
    if (Object.hasOwn(input, key)) throw commandError('engine-socket-path')
  }
}

export function buildEngineArgs(input = {}) {
  if (!isRecord(input)) throw commandError('invalid-container-command')
  rejectUnsafeOptions(input)

  const engine = validateEngineName(input.engine)
  const action = input.action
  if (!ACTIONS.has(action)) throw commandError('invalid-action')
  const label = validateLabel(input.label)
  const policy = normalizeContainerPolicy({
    engine,
    image: input.image,
    stagingCapability: input.stagingCapability,
    network: input.network,
    networkMode: input.networkMode,
    privileged: input.privileged,
    pid: input.pid,
    ipc: input.ipc,
    limits: input.limits ?? {
      timeoutMs: input.timeoutMs,
      memoryBytes: input.memoryBytes,
      pidsLimit: input.pidsLimit,
      outputBytes: input.outputBytes,
    },
  })

  if (!REQUIRED_IMAGE_DIGEST.test(policy.image)) throw commandError('invalid-image')
  const limits = policy.limits
  const args = [
    'run',
    '--detach',
    '--rm',
    '--network=none',
    '--pid=private',
    '--ipc=private',
    '--read-only',
    '--user=65532:65532',
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges',
    `--pids-limit=${limits.pidsLimit}`,
    `--memory=${limits.memoryBytes}b`,
    `--stop-timeout=${Math.max(1, Math.ceil(limits.timeoutMs / 1000))}`,
    '--label',
    `dsh.sentinel.run=${label}`,
    '--mount',
    `type=bind,source=${policy.stagedRoot},destination=/workspace,readonly`,
    policy.image,
  ]

  if (args.some((value) => typeof value !== 'string')) throw commandError('invalid-container-argv')
  return Object.freeze(args)
}

export { CONTAINER_PHASE_B_LIMITS }
