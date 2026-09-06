import assert from 'node:assert/strict'
import test from 'node:test'
import {
  CONTAINER_PHASE_B_LIMITS,
  REQUIRED_IMAGE_DIGEST,
  SUPPORTED_CONTAINER_ENGINES,
  createStagingCapability,
  normalizeContainerPolicy,
} from '../engine/dynamic/container-policy.js'
import { buildEngineArgs, validateEngineName } from '../engine/dynamic/container-command.js'

const DIGEST = 'a'.repeat(64)
const IMAGE = `registry.example/dsh-runner@sha256:${DIGEST}`
const STAGING_ROOT = 'C:\\dsh\\dsh-sentinel-staging'
const STAGED_ROOT = `${STAGING_ROOT}\\snapshot-0123456789abcdef`
const STAGING_CAPABILITY = createStagingCapability({ root: STAGING_ROOT, snapshot: STAGED_ROOT })

function request(overrides = {}) {
  return {
    engine: 'docker',
    action: 'run',
    label: 'dsh-run-123',
    image: IMAGE,
    stagingCapability: STAGING_CAPABILITY,
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
    stagingCapability: STAGING_CAPABILITY,
  })

  assert.equal(normalized.engine, 'docker')
  assert.equal(normalized.image, IMAGE)
  assert.equal(normalized.stagedRoot, STAGED_ROOT)
  assert.equal(Object.isFrozen(normalized), true)
  assert.equal(Object.isFrozen(normalized.limits), true)

  assert.throws(
    () => normalizeContainerPolicy({
      engine: 'docker', image: IMAGE, stagedRoot: STAGED_ROOT,
      stagingCapability: STAGING_CAPABILITY,
    }),
    (error) => error?.code === 'raw-staged-root-not-allowed',
  )
  assert.throws(
    () => normalizeContainerPolicy({
      engine: 'docker', image: IMAGE, stagingRoot: STAGING_ROOT,
      stagingCapability: STAGING_CAPABILITY,
    }),
    (error) => error?.code === 'raw-staging-root-not-allowed',
  )

  for (const image of ['registry.example/dsh-runner:latest', 'registry.example/dsh-runner', 'dsh-runner@sha256:short']) {
    assert.throws(
      () => normalizeContainerPolicy({ engine: 'docker', image }),
      /immutable|digest|image/i,
    )
  }
})

test('container policy requires a trusted staging capability for the snapshot mount', () => {
  assert.throws(
    () => normalizeContainerPolicy({ engine: 'docker', image: IMAGE }),
    (error) => error?.code === 'staging-capability-required',
  )
  assert.throws(
    () => normalizeContainerPolicy({ engine: 'docker', image: IMAGE, stagedRoot: STAGED_ROOT }),
    (error) => error?.code === 'raw-staged-root-not-allowed',
  )
  assert.throws(
    () => normalizeContainerPolicy({
      engine: 'docker', image: IMAGE,
      stagingCapability: { root: STAGING_ROOT, snapshot: STAGED_ROOT },
    }),
    (error) => error?.code === 'invalid-staging-capability',
  )

  const copiedCapability = Object.create(
    Object.getPrototypeOf(STAGING_CAPABILITY),
    Object.getOwnPropertyDescriptors(STAGING_CAPABILITY),
  )
  assert.notEqual(copiedCapability, STAGING_CAPABILITY)
  assert.throws(
    () => normalizeContainerPolicy({
      engine: 'docker', image: IMAGE,
      stagingCapability: copiedCapability,
    }),
    (error) => error?.code === 'invalid-staging-capability',
  )

  const symlinkShapedSnapshot = `${STAGING_ROOT}\\link-to-host\\snapshot-0123456789abcdef`
  assert.throws(
    () => normalizeContainerPolicy({
      engine: 'docker', image: IMAGE, stagedRoot: symlinkShapedSnapshot,
      stagingCapability: STAGING_CAPABILITY,
    }),
    (error) => error?.code === 'raw-staged-root-not-allowed',
  )
  assert.throws(
    () => normalizeContainerPolicy({
      engine: 'docker', image: IMAGE, stagingRoot: STAGING_ROOT,
      stagingCapability: STAGING_CAPABILITY,
    }),
    (error) => error?.code === 'raw-staging-root-not-allowed',
  )
  assert.throws(
    () => createStagingCapability({
      root: STAGING_ROOT,
      snapshot: `${STAGED_ROOT},readonly=false`,
    }),
    (error) => error?.code === 'invalid-staged-root',
  )

  const invalidCapabilities = [
    { root: 42, snapshot: STAGED_ROOT },
    { root: STAGING_ROOT, snapshot: 42 },
    { root: `${STAGING_ROOT},extra`, snapshot: STAGED_ROOT },
    { root: STAGING_ROOT, snapshot: `${STAGED_ROOT};extra` },
    { root: `${STAGING_ROOT}\\..\\outside`, snapshot: STAGED_ROOT },
    { root: `${STAGING_ROOT}${'r'.repeat(520)}`, snapshot: STAGED_ROOT },
  ]
  for (const candidate of invalidCapabilities) {
    assert.throws(
      () => createStagingCapability(candidate),
      (error) => ['invalid-staging-root', 'invalid-staged-root', 'staging-capability-mismatch'].includes(error?.code),
    )
  }
})

test('staging validation rejects host paths, non-canonical paths, mount separators, and sockets', () => {
  const hostileRoots = [
    'C:\\Users\\Administrator\\.ssh',
    'C:\\Users\\Administrator\\Desktop\\code\\dsh-sentinel',
    `${STAGING_ROOT}\\..\\.ssh`,
    `${STAGED_ROOT},readonly=false`,
    `${STAGED_ROOT};--mount=type=bind`,
    `${STAGED_ROOT}=host`,
    `${STAGED_ROOT}\r\n--network=host`,
    `${STAGING_ROOT}\\snapshot-0123456789abcdef\\docker.sock`,
  ]

  for (const stagedRoot of hostileRoots) {
    assert.throws(
      () => buildEngineArgs(request({ stagedRoot })),
      (error) => error?.code === 'raw-staged-root-not-allowed',
      `rejects unsafe staged root ${JSON.stringify(stagedRoot)}`,
    )
  }
})

test('container policy rejects contradictory network fields instead of applying precedence', () => {
  assert.throws(
    () => normalizeContainerPolicy({
      engine: 'docker', image: IMAGE,
      stagingCapability: STAGING_CAPABILITY, network: 'none', networkMode: 'host',
    }),
    (error) => error?.code === 'conflicting-network-policy',
  )
})

test('container inputs are bounded and invalid enum errors never stringify attacker values', () => {
  const oversizedImage = `${'r'.repeat(300)}@sha256:${DIGEST}`
  const oversizedRoot = `${STAGING_ROOT}\\${'s'.repeat(500)}`
  assert.throws(
    () => normalizeContainerPolicy({
      engine: 'docker', image: oversizedImage,
      stagingCapability: STAGING_CAPABILITY,
    }),
    (error) => error?.code === 'invalid-image',
  )
  assert.throws(
    () => buildEngineArgs(request({ stagedRoot: oversizedRoot })),
    (error) => error?.code === 'raw-staged-root-not-allowed',
  )
  assert.throws(
    () => buildEngineArgs(request({ label: `dsh-${'x'.repeat(70)}` })),
    (error) => error?.code === 'invalid-label',
  )

  let stringifyCalls = 0
  const hostile = { toString() { stringifyCalls += 1; throw new Error('attacker toString') } }
  assert.throws(() => validateEngineName(hostile), (error) => error?.code === 'invalid-engine')
  assert.throws(() => buildEngineArgs(request({ action: hostile })), (error) => error?.code === 'invalid-action')
  assert.equal(stringifyCalls, 0)
})

test('container policy clamps requests to fixed Phase B limits', () => {
  const normalized = normalizeContainerPolicy({
    engine: 'podman',
    image: IMAGE,
    stagingCapability: STAGING_CAPABILITY,
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
  const argv = buildEngineArgs(request())
  assert.equal(Object.isFrozen(argv), true)
  const originalFirst = argv[0]
  assert.throws(() => { argv[0] = 'evil' }, TypeError)
  assert.throws(() => Object.defineProperty(argv, '0', { value: 'evil' }), TypeError)
  assert.equal(argv[0], originalFirst)
})

test('engine validation and command construction reject shell strings and user flags', () => {
  assert.equal(validateEngineName('docker'), 'docker')
  assert.equal(validateEngineName('podman'), 'podman')
  assert.throws(() => validateEngineName('docker --privileged'), /engine/i)
  assert.throws(() => buildEngineArgs(request({ flags: ['--privileged'] })), (error) => error?.code === 'user-container-arguments')
  assert.throws(() => buildEngineArgs(request({ args: ['--network=host'] })), (error) => error?.code === 'user-container-arguments')
  assert.throws(() => buildEngineArgs(request({ label: 'dsh-run-123 --privileged' })), (error) => error?.code === 'invalid-label')
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
    assert.throws(
      () => buildEngineArgs(request(overrides)),
      (error) => ['host-network-not-allowed', 'privileged-not-allowed', 'host-pid-not-allowed',
        'host-ipc-not-allowed', 'user-container-arguments'].includes(error?.code),
    )
  }
})
