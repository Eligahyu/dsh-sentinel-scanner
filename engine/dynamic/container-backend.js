import { execFile } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { promisify } from 'node:util'
import { buildEngineArgs } from './container-command.js'
import {
  CONTAINER_PHASE_B_LIMITS,
  REQUIRED_IMAGE_DIGEST,
  SUPPORTED_CONTAINER_ENGINES,
  normalizeContainerPolicy,
} from './container-policy.js'

const execFileAsync = promisify(execFile)
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i
const CONTAINER_ID = /^[a-f0-9]{12,64}$/
const SAFE_LABEL = /^dsh-[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/
const MAX_PROBE_RECORDS = 32
const MAX_RUN_SPEC_DEPTH = 8
const MAX_RUN_SPEC_ITEMS = 500
const REMOTE_ENGINE_ENVIRONMENT = Object.freeze([
  'DOCKER_HOST', 'CONTAINER_HOST', 'DOCKER_CONTEXT', 'CONTAINER_CONNECTION',
])
const DOCKER_CONTEXT_FIELDS = Object.freeze(new Set([
  'Name', 'Description', 'DockerEndpoint', 'KubernetesEndpoint', 'Current', 'StackOrchestrator',
]))
const PODMAN_CONNECTION_FIELDS = Object.freeze(new Set([
  'Name', 'URI', 'Identity', 'Default', 'ReadWrite', 'IsMachine',
]))
const RUN_SPEC_FIELDS = Object.freeze(new Set([
  'runId', 'target', 'profile', 'entrypoints', 'canaries',
]))

export const CONTAINER_BACKEND_LIMITS = Object.freeze({
  probeTimeoutMs: Math.min(5000, CONTAINER_PHASE_B_LIMITS.timeoutMs),
  probeOutputBytes: Math.min(8192, CONTAINER_PHASE_B_LIMITS.outputBytes),
})

function backendError(code) {
  const error = new Error(code)
  error.code = code
  return error
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function ownData(value, key) {
  try {
    if (value === null || (typeof value !== 'object' && typeof value !== 'function')) {
      return { safe: false, found: false }
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) return { safe: true, found: false }
    return { safe: true, found: true, value: descriptor.value }
  } catch {
    return { safe: false, found: false }
  }
}

function optionValue(options, key) {
  const entry = ownData(options, key)
  return entry.safe && entry.found ? entry.value : undefined
}

function fixedAvailability(engine, code) {
  return Object.freeze({ available: false, backend: engine ?? null, code, capabilities: null })
}

function availableResult(engine) {
  return Object.freeze({
    available: true,
    backend: engine,
    code: 'container-available',
    capabilities: Object.freeze({ context: 'local', image: 'immutable', network: 'none' }),
  })
}

function isLocalEndpoint(endpoint) {
  return typeof endpoint === 'string'
    && (endpoint.startsWith('unix:///') || endpoint.startsWith('npipe:////./pipe/'))
}

function parseJson(value) {
  try {
    return JSON.parse(value)
  } catch {
    return null
  }
}

function allowedJsonRecord(value, fields) {
  try {
    if (!isRecord(value) || Object.getPrototypeOf(value) !== Object.prototype) return false
    const keys = Reflect.ownKeys(value)
    return keys.length <= fields.size && keys.every(key => typeof key === 'string' && fields.has(key))
  } catch {
    return false
  }
}

function jsonValue(record, key) {
  const entry = ownData(record, key)
  return entry.safe && entry.found ? entry.value : undefined
}

function localDockerContext(stdout) {
  const lines = stdout.split(/\r?\n/).filter(line => line.length > 0)
  if (lines.length === 0 || lines.length > MAX_PROBE_RECORDS) return null
  let endpoint = null
  for (const line of lines) {
    const context = parseJson(line)
    if (!allowedJsonRecord(context, DOCKER_CONTEXT_FIELDS)) return null
    const current = jsonValue(context, 'Current')
    if (typeof current !== 'boolean') return null
    if (current) {
      if (endpoint !== null) return null
      const candidate = jsonValue(context, 'DockerEndpoint')
      if (typeof candidate !== 'string') return null
      endpoint = candidate
    }
  }
  if (endpoint === null) return null
  return isLocalEndpoint(endpoint)
}

function localPodmanContext(stdout) {
  const connections = parseJson(stdout)
  if (!Array.isArray(connections) || connections.length === 0 || connections.length > MAX_PROBE_RECORDS) {
    return null
  }
  let endpoint = null
  for (const connection of connections) {
    if (!allowedJsonRecord(connection, PODMAN_CONNECTION_FIELDS)) return null
    const current = jsonValue(connection, 'Default')
    if (typeof current !== 'boolean') return null
    if (current) {
      if (endpoint !== null) return null
      const candidate = jsonValue(connection, 'URI')
      if (typeof candidate !== 'string') return null
      endpoint = candidate
    }
  }
  if (endpoint === null) return null
  return isLocalEndpoint(endpoint)
}

function parseLocalContext(engine, stdout) {
  return engine === 'docker' ? localDockerContext(stdout) : localPodmanContext(stdout)
}

function outputWithinLimit(value, limit) {
  return typeof value === 'string' && Buffer.byteLength(value, 'utf8') <= limit
}

function commandOutput(result, outputBytes) {
  const stdout = ownData(result, 'stdout')
  const stderr = ownData(result, 'stderr')
  if (!stdout.safe || !stdout.found || !stderr.safe || !stderr.found) return { kind: 'invalid' }
  if (!outputWithinLimit(stdout.value, outputBytes) || !outputWithinLimit(stderr.value, outputBytes)) {
    return { kind: 'too-large' }
  }

  const exitCode = ownData(result, 'exitCode')
  const code = ownData(result, 'code')
  if (!exitCode.safe || !code.safe) return { kind: 'invalid' }
  let status = 0
  if (exitCode.found) {
    if (!Number.isSafeInteger(exitCode.value) || exitCode.value < 0) return { kind: 'invalid' }
    status = exitCode.value
  }
  if (code.found) {
    if (!Number.isSafeInteger(code.value) || code.value < 0 || (exitCode.found && code.value !== status)) {
      return { kind: 'invalid' }
    }
    status = code.value
  }
  if (status !== 0) return { kind: 'failed' }
  return { kind: 'success', stdout: stdout.value }
}

function isOutputLimitError(error) {
  try {
    return error?.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'
  } catch {
    return false
  }
}

async function runCommand(commandRunner, engine, args, { timeout, outputBytes }) {
  const options = Object.freeze({
    shell: false,
    timeout,
    maxBuffer: outputBytes,
    windowsHide: true,
  })
  try {
    const result = await commandRunner(engine, Object.freeze([...args]), options)
    return commandOutput(result, outputBytes)
  } catch (error) {
    return { kind: isOutputLimitError(error) ? 'too-large' : 'failed' }
  }
}

async function productionCommandRunner(file, args, options) {
  return execFileAsync(file, args, options)
}

function hasRemoteEnvironment(environment) {
  for (const key of REMOTE_ENGINE_ENVIRONMENT) {
    const entry = ownData(environment, key)
    if (!entry.safe) return true
    if (entry.found && (typeof entry.value !== 'string' || entry.value.length > 0)) return true
  }
  return false
}

function frozenJson(value, seen = new Set(), depth = 0) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true
  if (typeof value === 'number') return Number.isFinite(value)
  if (!value || typeof value !== 'object' || depth > MAX_RUN_SPEC_DEPTH || seen.has(value)) return false
  try {
    if (!Object.isFrozen(value)) return false
    const array = Array.isArray(value)
    const prototype = Object.getPrototypeOf(value)
    if (array ? prototype !== Array.prototype : prototype !== Object.prototype) return false
    const keys = Reflect.ownKeys(value)
    if (keys.length > MAX_RUN_SPEC_ITEMS || keys.some(key => typeof key !== 'string')) return false
    seen.add(value)
    if (array) {
      const length = ownData(value, 'length')
      if (!length.safe || !length.found || !Number.isSafeInteger(length.value)
        || length.value < 0 || length.value > MAX_RUN_SPEC_ITEMS || keys.length !== length.value + 1) {
        return false
      }
      for (let index = 0; index < length.value; index += 1) {
        const entry = ownData(value, String(index))
        if (!entry.safe || !entry.found || !frozenJson(entry.value, seen, depth + 1)) return false
      }
      return true
    }
    for (const key of keys) {
      const entry = ownData(value, key)
      if (!entry.safe || !entry.found || !frozenJson(entry.value, seen, depth + 1)) return false
    }
    return true
  } catch {
    return false
  } finally {
    seen.delete(value)
  }
}

function validRunSpec(runSpec) {
  try {
    if (!isRecord(runSpec) || Object.getPrototypeOf(runSpec) !== Object.prototype || !Object.isFrozen(runSpec)) {
      return null
    }
    const keys = Reflect.ownKeys(runSpec)
    if (keys.length !== RUN_SPEC_FIELDS.size || keys.some(key => typeof key !== 'string' || !RUN_SPEC_FIELDS.has(key))) {
      return null
    }
    const values = {}
    for (const key of RUN_SPEC_FIELDS) {
      const entry = ownData(runSpec, key)
      if (!entry.safe || !entry.found) return null
      values[key] = entry.value
    }
    if (typeof values.runId !== 'string' || !UUID.test(values.runId) || values.profile !== 'observe') return null
    if (!frozenJson(values.target) || !frozenJson(values.entrypoints) || !frozenJson(values.canaries)) return null
    return values
  } catch {
    return null
  }
}

function resourceIdFromOutput(stdout) {
  const match = /^([a-f0-9]{12,64})\r?\n?$/.exec(stdout)
  return match ? match[1] : null
}

function verifiedOwnership(stdout, label) {
  const labels = parseJson(stdout)
  if (!allowedJsonRecord(labels, new Set(['dsh.sentinel.run']))) return false
  return jsonValue(labels, 'dsh.sentinel.run') === label
}

function createLabel(labels) {
  try {
    const label = `dsh-run-${randomUUID().replaceAll('-', '')}`
    if (!SAFE_LABEL.test(label) || labels.has(label)) throw backendError('container-label-generation-failed')
    labels.add(label)
    return label
  } catch (error) {
    if (error?.code === 'container-label-generation-failed') throw error
    throw backendError('container-label-generation-failed')
  }
}

function preparedPolicy({ engine, image, stagingCapability, limits }) {
  try {
    return normalizeContainerPolicy({ engine, image, stagingCapability, limits })
  } catch {
    throw backendError('container-prepare-refused')
  }
}

/**
 * Create the Phase B local-container adapter. It is intentionally not wired into
 * backend resolution yet; callers must opt in and provide a factory-owned staging capability.
 */
export function createContainerBackend(options = {}) {
  const engine = optionValue(options, 'engine') ?? 'docker'
  const image = optionValue(options, 'image')
  const stagingCapability = optionValue(options, 'stagingCapability')
  const limits = optionValue(options, 'limits')
  const commandRunner = typeof optionValue(options, 'commandRunner') === 'function'
    ? optionValue(options, 'commandRunner')
    : productionCommandRunner
  const environment = optionValue(options, 'environment') ?? process.env
  const handles = new WeakMap()
  const labels = new Set()
  let lastAvailability = null

  const available = async () => {
    if (!SUPPORTED_CONTAINER_ENGINES.includes(engine)) {
      lastAvailability = fixedAvailability(null, 'container-engine-invalid')
      return lastAvailability
    }
    if (typeof image !== 'string' || !REQUIRED_IMAGE_DIGEST.test(image)) {
      lastAvailability = fixedAvailability(engine, 'container-image-invalid')
      return lastAvailability
    }
    if (hasRemoteEnvironment(environment)) {
      lastAvailability = fixedAvailability(engine, 'container-remote-context')
      return lastAvailability
    }

    const args = engine === 'docker'
      ? ['context', 'ls', '--format', '{{json .}}']
      : ['system', 'connection', 'list', '--format', 'json']
    const result = await runCommand(commandRunner, engine, args, {
      timeout: CONTAINER_BACKEND_LIMITS.probeTimeoutMs,
      outputBytes: CONTAINER_BACKEND_LIMITS.probeOutputBytes,
    })
    if (result.kind === 'too-large') {
      lastAvailability = fixedAvailability(engine, 'container-probe-output-too-large')
      return lastAvailability
    }
    if (result.kind !== 'success') {
      lastAvailability = fixedAvailability(engine, 'container-engine-unavailable')
      return lastAvailability
    }
    const local = parseLocalContext(engine, result.stdout)
    if (local === false) {
      lastAvailability = fixedAvailability(engine, 'container-remote-context')
      return lastAvailability
    }
    if (local !== true) {
      lastAvailability = fixedAvailability(engine, 'container-probe-invalid')
      return lastAvailability
    }
    lastAvailability = availableResult(engine)
    return lastAvailability
  }

  const prepare = async runSpec => {
    const spec = validRunSpec(runSpec)
    if (!spec) throw backendError('container-run-spec-invalid')
    if (lastAvailability?.available !== true || hasRemoteEnvironment(environment)) {
      throw backendError('container-not-available')
    }
    const policy = preparedPolicy({ engine, image, stagingCapability, limits })
    const label = createLabel(labels)
    let args
    try {
      args = buildEngineArgs({
        engine: policy.engine,
        action: 'run',
        label,
        image: policy.image,
        stagingCapability,
        limits: policy.limits,
      })
    } catch {
      throw backendError('container-prepare-refused')
    }
    const created = await runCommand(commandRunner, policy.engine, args, {
      timeout: policy.limits.timeoutMs,
      outputBytes: policy.limits.outputBytes,
    })
    if (created.kind === 'too-large') throw backendError('container-prepare-output-too-large')
    if (created.kind !== 'success') throw backendError('container-prepare-failed')
    const resourceId = resourceIdFromOutput(created.stdout)
    if (!resourceId) throw backendError('container-prepare-output-invalid')

    const inspected = await runCommand(commandRunner, policy.engine, [
      'container', 'inspect', '--format', '{{json .Config.Labels}}', resourceId,
    ], {
      timeout: policy.limits.timeoutMs,
      outputBytes: policy.limits.outputBytes,
    })
    if (inspected.kind === 'too-large') throw backendError('container-ownership-unverified')
    if (inspected.kind !== 'success' || !verifiedOwnership(inspected.stdout, label)) {
      throw backendError('container-ownership-unverified')
    }

    const ownership = Object.freeze({ runId: spec.runId, label, resourceId })
    const handle = Object.freeze({ ownership })
    handles.set(handle, { engine: policy.engine, resourceId, limits: policy.limits, cleaned: false })
    return handle
  }

  const runStage = async handle => {
    if (!handles.has(handle)) throw backendError('container-handle-invalid')
    throw backendError('container-stage-not-implemented')
  }

  const collect = async handle => {
    if (!handles.has(handle)) throw backendError('container-handle-invalid')
    throw backendError('container-collection-not-implemented')
  }

  const cleanup = async handle => {
    const state = handles.get(handle)
    if (!state) return Object.freeze({ complete: false })
    if (state.cleaned) return Object.freeze({ complete: true })
    const result = await runCommand(commandRunner, state.engine, ['rm', '--force', state.resourceId], {
      timeout: state.limits.timeoutMs,
      outputBytes: state.limits.outputBytes,
    })
    if (result.kind !== 'success') return Object.freeze({ complete: false })
    state.cleaned = true
    return Object.freeze({ complete: true })
  }

  return Object.freeze({ available, prepare, runStage, collect, cleanup })
}
