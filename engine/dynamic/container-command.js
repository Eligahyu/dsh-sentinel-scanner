import { isAbsolute } from 'node:path'
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
  if (!SUPPORTED_CONTAINER_ENGINES.includes(value)) {
    throw new Error(`invalid container engine: ${String(value)}`)
  }
  return value
}

function validateLabel(value) {
  if (typeof value !== 'string' || !SAFE_LABEL.test(value)) {
    throw new Error('invalid container label')
  }
  return value
}

function rejectUnsafeOptions(input) {
  for (const key of DISALLOWED_KEYS) {
    if (Object.hasOwn(input, key)) throw new Error(`container ${key} arguments are not allowed`)
  }
  if (input.network !== undefined && input.network !== 'none') {
    throw new Error('host or custom container network is not allowed')
  }
  if (input.networkMode !== undefined && input.networkMode !== 'none') {
    throw new Error('host or custom container network is not allowed')
  }
  if (input.privileged !== undefined && input.privileged !== false) {
    throw new Error('privileged containers are not allowed')
  }
  if (input.pid !== undefined && input.pid !== 'private') {
    throw new Error('host or custom pid namespace is not allowed')
  }
  if (input.ipc !== undefined && input.ipc !== 'private') {
    throw new Error('host or custom ipc namespace is not allowed')
  }
  for (const key of ['engineSocket', 'socket', 'ipcSocket']) {
    if (Object.hasOwn(input, key)) throw new Error('container engine socket path is not allowed')
  }
}

export function buildEngineArgs(input = {}) {
  if (!isRecord(input)) throw new Error('invalid container command')
  rejectUnsafeOptions(input)

  const engine = validateEngineName(input.engine)
  const action = input.action
  if (!ACTIONS.has(action)) throw new Error(`unsupported container action: ${String(action)}`)
  const label = validateLabel(input.label)
  if (typeof input.stagedRoot !== 'string' || !isAbsolute(input.stagedRoot)) {
    throw new Error('container staged root must be absolute')
  }
  const policy = normalizeContainerPolicy({
    engine,
    image: input.image,
    stagedRoot: input.stagedRoot,
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

  if (!REQUIRED_IMAGE_DIGEST.test(policy.image)) throw new Error('container image must be digest-pinned')
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

  if (args.some((value) => typeof value !== 'string')) throw new Error('container argv must contain strings')
  return Object.freeze(args)
}

export { CONTAINER_PHASE_B_LIMITS }
