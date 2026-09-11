import { execFile } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { dirname, isAbsolute, normalize } from 'node:path'
import { promisify } from 'node:util'
import { buildEngineArgs } from './container-command.js'
import { DYNAMIC_STAGES } from './contracts.js'
import { normalizeDynamicEvidence } from './evidence.js'
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
const MAX_ACTIVE_LABELS = 256
const MAX_RECOVERY_OUTPUT_BYTES = 256
const MAX_OWNERSHIP_LABELS = 32
const MAX_OWNERSHIP_LABEL_KEY_BYTES = 128
const MAX_OWNERSHIP_LABEL_VALUE_BYTES = 512
const MAX_OWNERSHIP_LABEL_BYTES = 4096
const REMOTE_ENGINE_ENVIRONMENT = Object.freeze([
  'DOCKER_HOST', 'CONTAINER_HOST', 'DOCKER_CONTEXT', 'CONTAINER_CONNECTION',
])
const CONFIG_SELECTOR_ENVIRONMENT = Object.freeze([
  ...REMOTE_ENGINE_ENVIRONMENT,
  'DOCKER_CONFIG', 'CONTAINERS_CONF', 'CONTAINERS_STORAGE_CONF',
  'PODMAN_CONNECTIONS_CONF', 'XDG_CONFIG_HOME',
])
const REMOTE_ENGINE_ENVIRONMENT_SET = new Set(REMOTE_ENGINE_ENVIRONMENT)
const CONFIG_SELECTOR_ENVIRONMENT_SET = new Set(CONFIG_SELECTOR_ENVIRONMENT)
const TRUSTED_ENGINE_PATHS = Object.freeze({
  docker: Object.freeze(process.platform === 'win32'
    ? ['C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe']
    : ['/usr/bin/docker', '/usr/local/bin/docker']),
  podman: Object.freeze(process.platform === 'win32'
    ? ['C:\\Program Files\\RedHat\\Podman\\podman.exe', 'C:\\Program Files\\Podman\\podman.exe']
    : ['/usr/bin/podman', '/usr/local/bin/podman']),
})
const CONTROLLED_ENGINE_CWD = dirname(process.execPath)
const DOCKER_CONTEXT_FIELDS = Object.freeze(new Set([
  'Name', 'Description', 'DockerEndpoint', 'KubernetesEndpoint', 'Current', 'StackOrchestrator',
]))
const PODMAN_CONNECTION_FIELDS = Object.freeze(new Set([
  'Name', 'URI', 'Identity', 'Default', 'ReadWrite', 'IsMachine',
]))
const RUN_SPEC_FIELDS = Object.freeze(new Set([
  'runId', 'target', 'profile', 'entrypoints', 'canaries',
]))
const STAGE_FIELDS = Object.freeze(new Set(['name']))
const EVIDENCE_FIELDS = Object.freeze([
  'stages', 'networkAttempts', 'dnsQueries', 'processes', 'fileEvents',
  'canaryEvents', 'policyViolations', 'limitations', 'failures',
])

export const CONTAINER_BACKEND_LIMITS = Object.freeze({
  probeTimeoutMs: Math.min(5000, CONTAINER_PHASE_B_LIMITS.timeoutMs),
  probeOutputBytes: Math.min(8192, CONTAINER_PHASE_B_LIMITS.outputBytes),
  maxActiveResources: MAX_ACTIVE_LABELS,
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
  return isLocalEndpoint(endpoint) ? endpoint : false
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
  return isLocalEndpoint(endpoint) ? endpoint : false
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
  const code = ownData(error, 'code')
  return code.safe && code.found && code.value === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'
}

function boundedRejectedStdout(error, outputBytes) {
  const stdout = ownData(error, 'stdout')
  if (!stdout.safe || !stdout.found || typeof stdout.value !== 'string') return undefined
  const limit = Math.min(MAX_RECOVERY_OUTPUT_BYTES, outputBytes)
  return outputWithinLimit(stdout.value, limit) ? stdout.value : undefined
}

function rejectedCommandKind(error, signal) {
  const code = ownData(error, 'code')
  const name = ownData(error, 'name')
  const killed = ownData(error, 'killed')
  const terminationSignal = ownData(error, 'signal')
  if (signal?.aborted || (code.safe && code.found && code.value === 'ABORT_ERR')
    || (name.safe && name.found && name.value === 'AbortError')) return 'cancelled'
  if ((code.safe && code.found && code.value === 'ETIMEDOUT')
    || (killed.safe && killed.found && killed.value === true)
    || (terminationSignal.safe && terminationSignal.found && terminationSignal.value === 'SIGTERM')) {
    return 'timeout'
  }
  return 'failed'
}

async function runCommand(commandRunner, binding, args, { timeout, outputBytes, signal = null }) {
  if (signal?.aborted) return { kind: 'cancelled' }
  const options = {
    shell: false,
    timeout,
    maxBuffer: outputBytes,
    windowsHide: true,
    env: binding.env,
  }
  if (binding.cwd !== undefined) options.cwd = binding.cwd
  if (signal !== null) options.signal = signal
  Object.freeze(options)
  try {
    const result = await commandRunner(binding.commandFile, Object.freeze([...args]), options)
    const output = commandOutput(result, outputBytes)
    if (signal?.aborted) {
      return output.kind === 'success'
        ? { kind: 'cancelled', stdout: output.stdout }
        : { kind: 'cancelled' }
    }
    return output
  } catch (error) {
    const kind = isOutputLimitError(error)
      ? 'too-large'
      : rejectedCommandKind(error, signal)
    const stdout = kind === 'too-large' || kind === 'cancelled' || kind === 'timeout'
      ? boundedRejectedStdout(error, outputBytes)
      : undefined
    return stdout === undefined ? { kind } : { kind, stdout }
  }
}

async function productionCommandRunner(file, args, options) {
  return execFileAsync(file, args, options)
}

function environmentEntries(environment) {
  if (environment === null || (typeof environment !== 'object' && typeof environment !== 'function')) {
    return null
  }
  const entries = []
  try {
    for (const key of Reflect.ownKeys(environment)) {
      if (typeof key !== 'string') continue
      const descriptor = Object.getOwnPropertyDescriptor(environment, key)
      if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) return null
      if (typeof descriptor.value !== 'string') return null
      entries.push(Object.freeze({ key, canonicalKey: key.toUpperCase(), value: descriptor.value }))
    }
    return Object.freeze(entries)
  } catch {
    return null
  }
}

function sanitizedEnvironment(entries, executablePath = null) {
  if (!Array.isArray(entries)) return null
  const safe = {}
  try {
    for (const entry of entries) {
      if (CONFIG_SELECTOR_ENVIRONMENT_SET.has(entry.canonicalKey)) continue
      if (executablePath !== null && entry.canonicalKey === 'PATH') continue
      safe[entry.key] = entry.value
    }
    if (executablePath !== null) safe.PATH = dirname(executablePath)
    return Object.freeze(safe)
  } catch {
    return null
  }
}

function hasRemoteEnvironment(entries) {
  if (!Array.isArray(entries)) return true
  return entries.some(entry => REMOTE_ENGINE_ENVIRONMENT_SET.has(entry.canonicalKey) && entry.value.length > 0)
}

function trustedEnginePath(engine, configuredPath) {
  const candidates = TRUSTED_ENGINE_PATHS[engine] ?? []
  if (configuredPath === undefined) return candidates[0] ?? null
  if (typeof configuredPath !== 'string' || !isAbsolute(configuredPath) || normalize(configuredPath) !== configuredPath) {
    return null
  }
  const normalized = process.platform === 'win32' ? configuredPath.toLowerCase() : configuredPath
  return candidates.find(candidate => {
    const comparable = process.platform === 'win32' ? candidate.toLowerCase() : candidate
    return comparable === normalized
  }) ?? null
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

// The backend contract validates shape and immutability only. It deliberately
// does not claim that an object-shaped run spec carries caller provenance.
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

function validStageSpec(stageSpec) {
  try {
    if (!isRecord(stageSpec) || Object.getPrototypeOf(stageSpec) !== Object.prototype || !Object.isFrozen(stageSpec)) {
      return null
    }
    const keys = Reflect.ownKeys(stageSpec)
    if (keys.length !== STAGE_FIELDS.size || keys.some(key => typeof key !== 'string' || !STAGE_FIELDS.has(key))) {
      return null
    }
    const name = ownData(stageSpec, 'name')
    if (!name.safe || !name.found || !DYNAMIC_STAGES.includes(name.value)) return null
    return name.value
  } catch {
    return null
  }
}

function stageExitCode(stdout) {
  if (typeof stdout !== 'string' || !/^\d{1,4}\r?\n?$/.test(stdout)) return null
  const value = Number.parseInt(stdout, 10)
  return Number.isSafeInteger(value) && value >= 0 ? value : null
}

function parseStageEvidence(stdout, canaries, limits) {
  if (typeof stdout !== 'string') return null
  let parsed
  try {
    parsed = JSON.parse(stdout)
  } catch {
    return null
  }
  try {
    const evidence = normalizeDynamicEvidence(parsed, { canaries, limits })
    return Object.freeze(evidence)
  } catch {
    return null
  }
}

function resourceIdFromOutput(stdout) {
  const match = /^([a-f0-9]{12,64})\r?\n?$/.exec(stdout)
  return match ? match[1] : null
}

function boundedOwnershipLabels(value) {
  if (!isRecord(value) || Object.getPrototypeOf(value) !== Object.prototype) return null
  let totalBytes = 0
  const keys = Reflect.ownKeys(value)
  if (keys.length === 0 || keys.length > MAX_OWNERSHIP_LABELS) return null
  for (const key of keys) {
    if (typeof key !== 'string') return null
    const entry = ownData(value, key)
    if (!entry.safe || !entry.found || typeof entry.value !== 'string') return null
    const keyBytes = Buffer.byteLength(key, 'utf8')
    const valueBytes = Buffer.byteLength(entry.value, 'utf8')
    if (keyBytes > MAX_OWNERSHIP_LABEL_KEY_BYTES || valueBytes > MAX_OWNERSHIP_LABEL_VALUE_BYTES) return null
    totalBytes += keyBytes + valueBytes
    if (totalBytes > MAX_OWNERSHIP_LABEL_BYTES) return null
  }
  return value
}

function verifiedOwnership(stdout, label) {
  const labels = parseJson(stdout)
  if (!boundedOwnershipLabels(labels)) return false
  return jsonValue(labels, 'dsh.sentinel.run') === label
}

function boundEngineArgs(engine, endpoint, args) {
  const prefix = engine === 'docker' ? ['--host', endpoint] : ['--url', endpoint]
  return [...prefix, ...args]
}

function fixedCleanupResult(complete) {
  return Object.freeze({ complete })
}

function createLabel(labels) {
  try {
    if (labels.size >= MAX_ACTIVE_LABELS) throw backendError('container-label-generation-failed')
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
  const injectedCommandRunner = optionValue(options, 'commandRunner')
  const injectedExecFile = optionValue(options, 'execFile')
  const usesInjectedRunner = typeof injectedCommandRunner === 'function'
  const executablePath = usesInjectedRunner
    ? null
    : trustedEnginePath(engine, optionValue(options, 'trustedEnginePath'))
  const commandFile = usesInjectedRunner
    ? engine
    : executablePath
  const commandRunner = usesInjectedRunner
    ? injectedCommandRunner
    : typeof injectedExecFile === 'function'
      ? async (file, args, commandOptions) => injectedExecFile(file, args, commandOptions)
      : productionCommandRunner
  const environment = optionValue(options, 'environment') ?? process.env
  const handles = new WeakMap()
  const labels = new Set()
  const orphanResources = new Map()
  let lastAvailability = null
  let verifiedBinding = null

  const bindingForUse = () => {
    const currentEnvironment = environmentEntries(environment)
    if (lastAvailability?.available !== true || verifiedBinding === null || hasRemoteEnvironment(currentEnvironment)) {
      return null
    }
    return verifiedBinding
  }

  const cleanupCreatedResource = async (binding, resourceId, policy) => {
    const result = await runCommand(commandRunner, binding, boundEngineArgs(
      binding.engine,
      binding.endpoint,
      ['rm', '--force', resourceId],
    ), {
      timeout: policy.limits.timeoutMs,
      outputBytes: policy.limits.outputBytes,
    })
    return fixedCleanupResult(result.kind === 'success')
  }

  const stageResourceRecord = (binding, resourceId, label, policy, ownershipVerified = false) => Object.freeze({
    engine: binding.engine,
    endpoint: binding.endpoint,
    env: binding.env,
    cwd: binding.cwd,
    commandFile: binding.commandFile,
    resourceId,
    label,
    limits: policy.limits,
    ownershipVerified,
  })

  const discoverStageResource = async resource => {
    const result = await runCommand(commandRunner, resource, boundEngineArgs(
      resource.engine,
      resource.endpoint,
      ['ps', '--all', '--filter', `label=dsh.sentinel.run=${resource.label}`, '--format', '{{.ID}}'],
    ), {
      timeout: resource.limits.timeoutMs,
      outputBytes: Math.min(resource.limits.outputBytes, MAX_RECOVERY_OUTPUT_BYTES),
    })
    if (result.kind !== 'success') return null
    return resourceIdFromOutput(result.stdout)
  }

  const verifyStageOwnership = async (resource, resourceId) => {
    const result = await runCommand(commandRunner, resource, boundEngineArgs(
      resource.engine,
      resource.endpoint,
      ['container', 'inspect', '--format', '{{json .Config.Labels}}', resourceId],
    ), {
      timeout: resource.limits.timeoutMs,
      outputBytes: resource.limits.outputBytes,
    })
    return result.kind === 'success' && verifiedOwnership(result.stdout, resource.label)
  }

  const cleanupStageResource = async (state, resource) => {
    let resourceId = resource.resourceId
    if (resourceId === null) resourceId = await discoverStageResource(resource)
    if (resourceId === null) {
      state.pendingResources.set(resource.label, resource)
      orphanResources.set(resource.label, resource)
      return fixedCleanupResult(false)
    }

    let ownershipVerified = resource.ownershipVerified === true
    if (!ownershipVerified) ownershipVerified = await verifyStageOwnership(resource, resourceId)
    if (!ownershipVerified) {
      const retained = stageResourceRecord(
        resource,
        resourceId,
        resource.label,
        { limits: resource.limits },
        false,
      )
      state.pendingResources.set(resource.label, retained)
      orphanResources.set(resource.label, retained)
      return fixedCleanupResult(false)
    }

    const result = await cleanupCreatedResource(resource, resourceId, {
      limits: resource.limits,
    })
    if (result.complete) {
      state.pendingResources.delete(resource.label)
      orphanResources.delete(resource.label)
      labels.delete(resource.label)
      return result
    }
    const retained = stageResourceRecord(
      resource,
      resourceId,
      resource.label,
      { limits: resource.limits },
      ownershipVerified,
    )
    state.pendingResources.set(resource.label, retained)
    orphanResources.set(resource.label, retained)
    return result
  }

  const stageErrorFor = (kind) => {
    if (kind === 'cancelled') return backendError('container-stage-cancelled')
    if (kind === 'timeout') return backendError('container-stage-timeout')
    if (kind === 'too-large') return backendError('container-stage-output-too-large')
    return backendError('container-stage-failed')
  }

  const retainFailedRollback = async (binding, resourceId, label, policy) => {
    const result = await cleanupCreatedResource(binding, resourceId, policy)
    if (result.complete) {
      orphanResources.delete(label)
      labels.delete(label)
    } else {
      orphanResources.set(label, Object.freeze({
        engine: binding.engine,
        endpoint: binding.endpoint,
        env: binding.env,
        resourceId,
        label,
        limits: policy.limits,
      }))
    }
    return result
  }

  const available = async () => {
    verifiedBinding = null
    lastAvailability = null
    if (!SUPPORTED_CONTAINER_ENGINES.includes(engine)) {
      lastAvailability = fixedAvailability(null, 'container-engine-invalid')
      return lastAvailability
    }
    if (typeof image !== 'string' || !REQUIRED_IMAGE_DIGEST.test(image)) {
      lastAvailability = fixedAvailability(engine, 'container-image-invalid')
      return lastAvailability
    }
    const initialEnvironment = environmentEntries(environment)
    if (initialEnvironment === null) {
      lastAvailability = fixedAvailability(engine, 'container-environment-invalid')
      return lastAvailability
    }
    if (hasRemoteEnvironment(initialEnvironment)) {
      lastAvailability = fixedAvailability(engine, 'container-remote-context')
      return lastAvailability
    }
    if (commandFile === null) {
      lastAvailability = fixedAvailability(engine, 'container-executable-unavailable')
      return lastAvailability
    }
    const env = sanitizedEnvironment(initialEnvironment, executablePath)
    if (env === null) {
      lastAvailability = fixedAvailability(engine, 'container-environment-invalid')
      return lastAvailability
    }

    const args = engine === 'docker'
      ? ['context', 'ls', '--format', '{{json .}}']
      : ['system', 'connection', 'list', '--format', 'json']
    const probeBinding = Object.freeze({
      engine,
      executablePath,
      commandFile,
      cwd: usesInjectedRunner ? undefined : CONTROLLED_ENGINE_CWD,
      env,
    })
    const result = await runCommand(commandRunner, probeBinding, args, {
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
    if (typeof local !== 'string') {
      lastAvailability = fixedAvailability(engine, 'container-probe-invalid')
      return lastAvailability
    }
    const verifiedEnvironment = environmentEntries(environment)
    if (verifiedEnvironment === null) {
      lastAvailability = fixedAvailability(engine, 'container-environment-invalid')
      return lastAvailability
    }
    if (hasRemoteEnvironment(verifiedEnvironment)) {
      lastAvailability = fixedAvailability(engine, 'container-remote-context')
      return lastAvailability
    }
    verifiedBinding = Object.freeze({ ...probeBinding, endpoint: local })
    lastAvailability = availableResult(engine)
    return lastAvailability
  }

  const prepare = async runSpec => {
    const spec = validRunSpec(runSpec)
    if (!spec) throw backendError('container-run-spec-invalid')
    const binding = bindingForUse()
    if (binding === null) {
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
      labels.delete(label)
      throw backendError('container-prepare-refused')
    }
    const created = await runCommand(commandRunner, binding, boundEngineArgs(
      binding.engine,
      binding.endpoint,
      args,
    ), {
      timeout: policy.limits.timeoutMs,
      outputBytes: policy.limits.outputBytes,
    })
    if (created.kind === 'too-large') {
      labels.delete(label)
      throw backendError('container-prepare-output-too-large')
    }
    if (created.kind !== 'success') {
      labels.delete(label)
      throw backendError('container-prepare-failed')
    }
    const resourceId = resourceIdFromOutput(created.stdout)
    if (!resourceId) {
      labels.delete(label)
      throw backendError('container-prepare-output-invalid')
    }

    const inspectBinding = bindingForUse()
    if (inspectBinding === null) {
      await retainFailedRollback(binding, resourceId, label, policy)
      throw backendError('container-not-available')
    }

    const inspected = await runCommand(commandRunner, inspectBinding, boundEngineArgs(
      inspectBinding.engine,
      inspectBinding.endpoint,
      ['container', 'inspect', '--format', '{{json .Config.Labels}}', resourceId],
    ), {
      timeout: policy.limits.timeoutMs,
      outputBytes: policy.limits.outputBytes,
    })
    if (inspected.kind === 'too-large' || inspected.kind !== 'success' || !verifiedOwnership(inspected.stdout, label)) {
      await retainFailedRollback(binding, resourceId, label, policy)
      throw backendError('container-ownership-unverified')
    }

    const ownership = Object.freeze({ runId: spec.runId, label, resourceId })
    const handle = Object.freeze({ ownership })
    handles.set(handle, {
      binding,
      engine: policy.engine,
      endpoint: binding.endpoint,
      commandFile: binding.commandFile,
      cwd: binding.cwd,
      env: binding.env,
      resourceId,
      policy,
      limits: policy.limits,
      label,
      runId: spec.runId,
      canaries: spec.canaries,
      stageEvidence: new Map(),
      completedStages: new Set(),
      pendingResources: new Map(),
      running: false,
      baseCleaned: false,
      cleaned: false,
      cleanupPromise: null,
    })
    return handle
  }

  const runStage = async (handle, stageSpec, signal = null) => {
    const state = handles.get(handle)
    if (!state || state.cleaned) throw backendError('container-handle-invalid')
    const name = validStageSpec(stageSpec)
    if (name === null || state.completedStages.has(name) || state.running) {
      throw backendError('container-stage-invalid')
    }
    const binding = bindingForUse()
    if (binding === null) throw backendError('container-not-available')

    const label = createLabel(labels)
    let resourceId = null
    let resource = null
    let ownershipVerified = false
    let submittedAttempt = false
    let failure = null
    state.running = true
    try {
      let args
      try {
        args = buildEngineArgs({
          engine: state.policy.engine,
          action: 'run',
          label,
          image: state.policy.image,
          stagingCapability,
          limits: state.policy.limits,
        }).filter(value => value !== '--rm')
        args = Object.freeze([...args, name])
      } catch {
        failure = backendError('container-stage-invalid')
      }

      if (!failure && signal?.aborted) {
        failure = stageErrorFor('cancelled')
      }

      if (!failure) {
        submittedAttempt = true
        const created = await runCommand(commandRunner, binding, boundEngineArgs(
          binding.engine,
          binding.endpoint,
          args,
        ), {
          timeout: state.limits.timeoutMs,
          outputBytes: state.limits.outputBytes,
          signal,
        })
        if (created.kind !== 'success') {
          if (created.stdout !== undefined) resourceId = resourceIdFromOutput(created.stdout)
          resource = stageResourceRecord(binding, resourceId, label, state.policy, false)
          failure = stageErrorFor(created.kind)
        }
        else {
          resourceId = resourceIdFromOutput(created.stdout)
          if (!resourceId) {
            resource = stageResourceRecord(binding, null, label, state.policy, false)
            failure = backendError('container-stage-output-invalid')
          }
        }
      }

      if (!failure) {
        const inspected = await runCommand(commandRunner, binding, boundEngineArgs(
          binding.engine,
          binding.endpoint,
          ['container', 'inspect', '--format', '{{json .Config.Labels}}', resourceId],
        ), {
          timeout: state.limits.timeoutMs,
          outputBytes: state.limits.outputBytes,
          signal,
        })
        if (inspected.kind !== 'success' || !verifiedOwnership(inspected.stdout, label)) {
          failure = backendError('container-stage-ownership-unverified')
        } else {
          ownershipVerified = true
        }
      }

      if (!failure) {
        const waited = await runCommand(commandRunner, binding, boundEngineArgs(
          binding.engine,
          binding.endpoint,
          ['wait', resourceId],
        ), {
          timeout: state.limits.timeoutMs,
          outputBytes: Math.min(state.limits.outputBytes, 256),
          signal,
        })
        if (waited.kind !== 'success') failure = stageErrorFor(waited.kind)
        else {
          const exitCode = stageExitCode(waited.stdout)
          if (exitCode === null || exitCode !== 0) failure = backendError('container-stage-nonzero')
        }
      }

      if (!failure) {
        const logs = await runCommand(commandRunner, binding, boundEngineArgs(
          binding.engine,
          binding.endpoint,
          ['logs', resourceId],
        ), {
          timeout: state.limits.timeoutMs,
          outputBytes: state.limits.outputBytes,
          signal,
        })
        if (logs.kind !== 'success') failure = stageErrorFor(logs.kind)
        else {
          const evidence = parseStageEvidence(logs.stdout, state.canaries, state.limits)
          if (evidence === null) failure = backendError('container-stage-evidence-invalid')
          else {
            state.stageEvidence.set(name, evidence)
            state.completedStages.add(name)
          }
        }
      }
    } catch {
      failure = backendError('container-stage-failed')
    } finally {
      state.running = false
      if (submittedAttempt) {
        if (resource === null) {
          resource = stageResourceRecord(binding, resourceId, label, state.policy, ownershipVerified)
        }
        const cleaned = await cleanupStageResource(state, resource)
        if (!cleaned.complete) failure = backendError('container-stage-cleanup-incomplete')
      } else {
        labels.delete(label)
      }
    }
    if (failure) throw failure
    return state.stageEvidence.get(name)
  }

  const collect = async handle => {
    const state = handles.get(handle)
    if (!state || state.cleaned) throw backendError('container-handle-invalid')
    if (state.pendingResources.size > 0 || state.running
      || DYNAMIC_STAGES.some(name => !state.completedStages.has(name))) {
      throw backendError('container-collection-incomplete')
    }
    const merged = {}
    for (const field of EVIDENCE_FIELDS) merged[field] = []
    try {
      for (const name of DYNAMIC_STAGES) {
        const evidence = state.stageEvidence.get(name)
        if (!evidence) throw new Error('missing evidence')
        for (const field of EVIDENCE_FIELDS) {
          const value = ownData(evidence, field)
          if (!value.safe || !value.found || !Array.isArray(value.value)) throw new Error('invalid evidence')
          merged[field].push(...value.value)
        }
      }
      return Object.freeze(normalizeDynamicEvidence(merged, {
        canaries: state.canaries,
        limits: state.limits,
      }))
    } catch {
      throw backendError('container-collection-invalid')
    }
  }

  const cleanup = async handle => {
    const state = handles.get(handle)
    if (!state) return fixedCleanupResult(false)
    if (state.cleaned) return fixedCleanupResult(true)
    if (state.cleanupPromise !== null) return state.cleanupPromise

    state.cleanupPromise = (async () => {
      if (state.running) return fixedCleanupResult(false)
      let complete = true
      for (const resource of [...state.pendingResources.values()]) {
        const result = await cleanupStageResource(state, resource)
        if (!result.complete) complete = false
      }
      if (!state.baseCleaned) {
        const result = await cleanupCreatedResource(state.binding, state.resourceId, state.policy)
        if (result.complete) {
          state.baseCleaned = true
          orphanResources.delete(state.label)
          labels.delete(state.label)
        } else {
          complete = false
          const resource = stageResourceRecord(state.binding, state.resourceId, state.label, state.policy)
          orphanResources.set(state.label, resource)
        }
      }
      if (!complete) return fixedCleanupResult(false)
      state.cleaned = true
      return fixedCleanupResult(true)
    })()
    const result = state.cleanupPromise
    void result.then(value => {
      if (!value.complete) state.cleanupPromise = null
    })
    return result
  }

  return Object.freeze({ available, prepare, runStage, collect, cleanup })
}
