import assert from 'node:assert/strict'
import test from 'node:test'
import {
  CONTAINER_PHASE_B_LIMITS,
  REQUIRED_IMAGE_DIGEST,
  SUPPORTED_CONTAINER_ENGINES,
  normalizeContainerPolicy,
} from '../engine/dynamic/container-policy.js'
import { buildEngineArgs, validateEngineName } from '../engine/dynamic/container-command.js'

const DIGEST = 'a'.repeat(64)
const IMAGE = `registry.example/dsh-runner@sha256:${DIGEST}`
const STAGED_ROOT = 'C:\\dsh\\staged\\run-123'

function request(overrides = {}) {
  return {
    engine: 'docker',
    action: 'run',
    label: 'dsh-run-123',
    image: IMAGE,
    stagedRoot: STAGED_ROOT,
    ...overrides,
  }
}

test('container policy accepts only immutable sha256 image references', () => {
  assert.equal(Object.isFrozen(REQUIRED_IMAGE_DIGEST), true)
  assert.equal(REQUIRED_IMAGE_DIGEST.test(IMAGE), true)
  assert.deepEqual([...SUPPORTED_CONTAINER_ENGINES], ['docker', 'podman'])

  const normalized = normalizeContainerPolicy({
    engine: 'docker',
    image: IMAGE,
    stagedRoot: STAGED_ROOT,
  })

  assert.equal(normalized.engine, 'docker')
  assert.equal(normalized.image, IMAGE)
  assert.equal(normalized.stagedRoot, STAGED_ROOT)
  assert.equal(Object.isFrozen(normalized), true)
  assert.equal(Object.isFrozen(normalized.limits), true)

  for (const image of ['registry.example/dsh-runner:latest', 'registry.example/dsh-runner', 'dsh-runner@sha256:short']) {
    assert.throws(
      () => normalizeContainerPolicy({ engine: 'docker', image, stagedRoot: STAGED_ROOT }),
      /immutable|digest|image/i,
    )
  }
})

test('container policy clamps requests to fixed Phase B limits', () => {
  const normalized = normalizeContainerPolicy({
    engine: 'podman',
    image: IMAGE,
    stagedRoot: STAGED_ROOT,
    timeoutMs: Number.MAX_SAFE_INTEGER,
    memoryBytes: Number.MAX_SAFE_INTEGER,
    pidsLimit: Number.MAX_SAFE_INTEGER,
    outputBytes: Number.MAX_SAFE_INTEGER,
  })

  assert.deepEqual(normalized.limits, CONTAINER_PHASE_B_LIMITS)
  assert.equal(CONTAINER_PHASE_B_LIMITS.timeoutMs > 0, true)
  assert.equal(CONTAINER_PHASE_B_LIMITS.memoryBytes > 0, true)
  assert.equal(CONTAINER_PHASE_B_LIMITS.pidsLimit > 0, true)
  assert.equal(CONTAINER_PHASE_B_LIMITS.outputBytes > 0, true)
})

test('Docker and Podman produce the same hardened argv contract', () => {
  const docker = buildEngineArgs(request({ engine: 'docker' }))
  const podman = buildEngineArgs(request({ engine: 'podman' }))

  assert.deepEqual(docker, podman)
  assert.equal(Array.isArray(docker), true)
  assert.equal(docker.every((value) => typeof value === 'string'), true)
  assert.equal(docker.includes('--network=none'), true)
  assert.equal(docker.includes('--privileged'), false)
  assert.equal(docker.includes('--pid=host'), false)
  assert.equal(docker.includes('--ipc=host'), false)
  assert.equal(docker.some((value) => value.includes('docker.sock')), false)
  assert.equal(docker.at(-1), IMAGE)
})

test('engine validation and command construction reject shell strings and user flags', () => {
  assert.equal(validateEngineName('docker'), 'docker')
  assert.equal(validateEngineName('podman'), 'podman')
  assert.throws(() => validateEngineName('docker --privileged'), /engine/i)
  assert.throws(() => buildEngineArgs(request({ flags: ['--privileged'] })), /flag/i)
  assert.throws(() => buildEngineArgs(request({ args: ['--network=host'] })), /argument|flag/i)
  assert.throws(() => buildEngineArgs(request({ label: 'dsh-run-123 --privileged' })), /label/i)
})

test('command construction rejects host networking, namespaces, sockets, and unsafe mounts', () => {
  for (const overrides of [
    { network: 'host' },
    { networkMode: 'host' },
    { privileged: true },
    { pid: 'host' },
    { ipc: 'host' },
    { mounts: [{ source: 'C:\\var\\run\\docker.sock', destination: '/run/docker.sock' }] },
    { mounts: [{ source: 'C:\\dsh\\outside', destination: '/workspace' }] },
  ]) {
    assert.throws(() => buildEngineArgs(request(overrides)), /network|privileged|namespace|mount|socket|host/i)
  }
})
