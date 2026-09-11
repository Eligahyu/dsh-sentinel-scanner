import assert from 'node:assert/strict'
import fs, { existsSync } from 'node:fs'
import { syncBuiltinESMExports } from 'node:module'
import { tmpdir } from 'node:os'
import { basename, dirname, isAbsolute, join } from 'node:path'
import test, { after } from 'node:test'
import {
  CONTAINER_PHASE_B_LIMITS,
  REQUIRED_IMAGE_DIGEST,
  SUPPORTED_CONTAINER_ENGINES,
  createStagingCapability,
  disposeStagingCapability,
  normalizeContainerPolicy,
} from '../engine/dynamic/container-policy.js'
import { buildEngineArgs, validateEngineName } from '../engine/dynamic/container-command.js'
import { CONTAINER_BACKEND_LIMITS, createContainerBackend } from '../engine/dynamic/container-backend.js'
import {
  STAGING_SNAPSHOT_LIMITS,
  createStagingSnapshot,
  isVcsMetadataName,
} from '../engine/dynamic/staging.js'
import { resolveLexicallyInside } from '../engine/path-safety.js'

const DIGEST = 'a'.repeat(64)
const IMAGE = `registry.example/dsh-runner@sha256:${DIGEST}`
const TEST_STAGING_CAPABILITIES = new Set()

function createTestStagingCapability() {
  const capability = createStagingCapability()
  TEST_STAGING_CAPABILITIES.add(capability)
  return capability
}

function disposeTestStagingCapability(capability) {
  try {
    disposeStagingCapability(capability)
  } finally {
    TEST_STAGING_CAPABILITIES.delete(capability)
  }
}

after(() => {
  const errors = []
  for (const capability of [...TEST_STAGING_CAPABILITIES]) {
    try {
      disposeStagingCapability(capability)
    } catch (error) {
      errors.push(error)
    } finally {
      TEST_STAGING_CAPABILITIES.delete(capability)
    }
  }
  if (errors.length === 1) throw errors[0]
  if (errors.length > 1) throw new AggregateError(errors, 'staging capability cleanup failed')
})

const STAGING_CAPABILITY = createTestStagingCapability()
const STAGING_ROOT = STAGING_CAPABILITY.root
const STAGED_ROOT = STAGING_CAPABILITY.snapshot

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

function createSnapshotSource(t) {
  const root = fs.mkdtempSync(join(tmpdir(), 'dsh-staging-source-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  return root
}

function hasDescriptorRelativeStagingSupport() {
  if (process.platform !== 'linux') return false
  const { O_DIRECTORY, O_NOFOLLOW, O_RDONLY } = fs.constants
  if (!Number.isInteger(O_DIRECTORY) || !Number.isInteger(O_NOFOLLOW)) return false
  let fd
  try {
    fd = fs.openSync('/proc/self/fd', O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    return fs.fstatSync(fd).isDirectory()
  } catch {
    return false
  } finally {
    if (fd !== undefined) fs.closeSync(fd)
  }
}

const HAS_DESCRIPTOR_RELATIVE_STAGING = hasDescriptorRelativeStagingSupport()

function linuxStagingTest(name, fn) {
  return test(name, {
    skip: HAS_DESCRIPTOR_RELATIVE_STAGING
      ? false
      : 'requires usable Linux O_DIRECTORY/O_NOFOLLOW /proc/self/fd traversal',
  }, fn)
}

function assertRejectedAndOwnerDisposed(callback, code) {
  const originalMkdtemp = fs.mkdtempSync
  let ownerRoot
  fs.mkdtempSync = (prefix, ...args) => {
    const created = originalMkdtemp(prefix, ...args)
    if (typeof prefix === 'string' && prefix.includes('dsh-sentinel-staging-')) ownerRoot = created
    return created
  }
  syncBuiltinESMExports()
  try {
    assert.throws(callback, error => error?.code === code && error.message === code)
  } finally {
    fs.mkdtempSync = originalMkdtemp
    syncBuiltinESMExports()
  }
  assert.equal(typeof ownerRoot, 'string')
  assert.equal(existsSync(ownerRoot), false)
}

test('staging snapshot fails closed before capability allocation without descriptor-relative traversal', t => {
  if (process.platform === 'linux' && HAS_DESCRIPTOR_RELATIVE_STAGING) {
    t.skip('Linux has usable descriptor-relative traversal support')
    return
  }
  const source = createSnapshotSource(t)
  fs.writeFileSync(join(source, 'safe.txt'), 'safe')
  const originalMkdtemp = fs.mkdtempSync
  let stagingFactoryCalls = 0
  let unexpectedSnapshot
  fs.mkdtempSync = (prefix, ...args) => {
    if (typeof prefix === 'string' && prefix.includes('dsh-sentinel-staging-')) stagingFactoryCalls += 1
    return originalMkdtemp(prefix, ...args)
  }
  syncBuiltinESMExports()
  try {
    assert.throws(
      () => { unexpectedSnapshot = createStagingSnapshot(source) },
      error => error?.code === 'staging-descriptor-unavailable' && error.message === 'staging-descriptor-unavailable',
    )
    assert.equal(stagingFactoryCalls, 0)
  } finally {
    unexpectedSnapshot?.cleanup()
    fs.mkdtempSync = originalMkdtemp
    syncBuiltinESMExports()
  }
})

test('staging snapshot defines an independent capped traversal-entry budget', () => {
  assert.equal(STAGING_SNAPSHOT_LIMITS.maxEntries, 4096)
})

linuxStagingTest('staging snapshot copies nested regular files into a factory-owned capability', t => {
  const source = createSnapshotSource(t)
  fs.mkdirSync(join(source, 'lib', 'nested'), { recursive: true })
  fs.writeFileSync(join(source, 'index.js'), 'export const value = 1\n')
  fs.writeFileSync(join(source, 'lib', 'nested', 'value.txt'), 'nested value\n')

  const staged = createStagingSnapshot(source)
  t.after(staged.cleanup)

  assert.notEqual(staged.snapshot, source)
  assert.equal(staged.root, staged.capability.root)
  assert.equal(staged.snapshot, staged.capability.snapshot)
  assert.equal(fs.readFileSync(join(staged.snapshot, 'index.js'), 'utf8'), 'export const value = 1\n')
  assert.equal(fs.readFileSync(join(staged.snapshot, 'lib', 'nested', 'value.txt'), 'utf8'), 'nested value\n')
  assert.deepEqual(staged.manifest.files.map(file => file.path), ['index.js', 'lib/nested/value.txt'])
  assert.equal(staged.manifest.files.every(file => !file.path.includes(source)), true)
  assert.equal(Object.isFrozen(staged.manifest), true)
  assert.equal(Object.isFrozen(staged.manifest.files), true)

  const argv = buildEngineArgs(request({ stagingCapability: staged.capability }))
  assert.equal(argv.some(value => value.includes(staged.snapshot)), true)
  assert.equal(argv.some(value => value.includes(source)), false)
  assert.equal(fs.readFileSync(join(source, 'index.js'), 'utf8'), 'export const value = 1\n')
})

linuxStagingTest('staging snapshot rejects a real symlink escape and disposes its owner root', t => {
  const source = createSnapshotSource(t)
  const escape = join(source, 'escape.txt')
  fs.writeFileSync(join(source, 'outside.txt'), 'outside')
  fs.symlinkSync(join(source, 'outside.txt'), escape, 'file')

  assertRejectedAndOwnerDisposed(() => createStagingSnapshot(source), 'staging-symlink')
})

linuxStagingTest('staging snapshot rejects real hardlinked regular files and disposes its owner root', t => {
  const source = createSnapshotSource(t)
  const original = join(source, 'original.txt')
  fs.writeFileSync(original, 'duplicate inode')
  fs.linkSync(original, join(source, 'hardlink.txt'))

  assertRejectedAndOwnerDisposed(() => createStagingSnapshot(source), 'staging-hardlink')
})

linuxStagingTest('staging snapshot rejects socket and device-shaped entries before opening them', t => {
  const source = createSnapshotSource(t)
  const special = join(source, 'special')
  fs.writeFileSync(special, 'not read')

  for (const [kind, predicate] of [
    ['socket', () => true],
    ['device', () => false],
  ]) {
    const originalLstat = fs.lstatSync
    fs.lstatSync = (candidate, ...args) => {
      const stat = originalLstat(candidate, ...args)
      if (typeof candidate !== 'string' || !candidate.endsWith('/special')) return stat
      return Object.assign(Object.create(stat), {
        isFile: () => false,
        isSymbolicLink: () => false,
        isDirectory: () => false,
        isSocket: predicate,
        isCharacterDevice: () => kind === 'device',
        isBlockDevice: () => false,
        isFIFO: () => false,
      })
    }
    try {
      assertRejectedAndOwnerDisposed(() => createStagingSnapshot(source), 'staging-special-file')
    } finally {
      fs.lstatSync = originalLstat
    }
  }
})

test('VCS metadata policy is case-insensitive', () => {
  for (const name of ['.git', '.GIT', '.GiT']) assert.equal(isVcsMetadataName(name), true)
  assert.equal(isVcsMetadataName('.gits'), false)
})

linuxStagingTest('staging snapshot excludes case-insensitive VCS metadata and nested worktrees', t => {
  const source = createSnapshotSource(t)
  fs.mkdirSync(join(source, '.GIT'), { recursive: true })
  fs.writeFileSync(join(source, '.GIT', 'config'), '[core]')
  fs.mkdirSync(join(source, 'nested-worktree'), { recursive: true })
  fs.writeFileSync(join(source, 'nested-worktree', '.GiT'), 'gitdir: /private/worktrees/nested')
  fs.writeFileSync(join(source, 'nested-worktree', 'ignored.js'), 'ignored')
  fs.writeFileSync(join(source, 'kept.js'), 'kept')

  const staged = createStagingSnapshot(source)
  t.after(staged.cleanup)

  assert.equal(existsSync(join(staged.snapshot, '.GIT')), false)
  assert.equal(existsSync(join(staged.snapshot, 'nested-worktree')), false)
  assert.equal(fs.readFileSync(join(staged.snapshot, 'kept.js'), 'utf8'), 'kept')
  assert.deepEqual(staged.manifest.excluded, { git: 1, worktrees: 1 })
})

test('lexical containment rejects a source-relative escape', t => {
  const source = createSnapshotSource(t)
  assert.throws(
    () => resolveLexicallyInside(source, '../outside'),
    error => error?.name === 'PathEscapeError',
  )
})

linuxStagingTest('staging snapshot enforces every caller-tightened resource limit incrementally', t => {
  const source = createSnapshotSource(t)
  fs.writeFileSync(join(source, 'one.txt'), 'abcdef')
  fs.writeFileSync(join(source, 'two.txt'), 'ghijkl')
  fs.writeFileSync(join(source, 'long-name.txt'), 'x')
  for (const [options, code] of [
    [{ maxFiles: 1 }, 'staging-file-count-limit'],
    [{ maxTotalBytes: 5 }, 'staging-total-bytes-limit'],
    [{ maxFileBytes: 5 }, 'staging-file-bytes-limit'],
    [{ maxPathLength: 4 }, 'staging-path-length-limit'],
  ]) {
    assertRejectedAndOwnerDisposed(() => createStagingSnapshot(source, options), code)
  }
})

linuxStagingTest('staging snapshot stops at a caller-tightened traversal-entry budget without whole-directory readdir', t => {
  const source = createSnapshotSource(t)
  const maxEntries = 4
  for (let index = 0; index <= maxEntries; index += 1) {
    fs.mkdirSync(join(source, `entry-${index}`))
  }

  const originalReaddir = fs.readdirSync
  fs.readdirSync = () => {
    throw new Error('whole-directory readdir is forbidden during staging traversal')
  }
  try {
    assertRejectedAndOwnerDisposed(
      () => createStagingSnapshot(source, { maxEntries }),
      'staging-entry-budget-limit',
    )
  } finally {
    fs.readdirSync = originalReaddir
  }
})

linuxStagingTest('staging snapshot cleanup delegates factory disposal and is idempotent', t => {
  const source = createSnapshotSource(t)
  fs.writeFileSync(join(source, 'safe.txt'), 'safe')
  const staged = createStagingSnapshot(source)
  t.after(staged.cleanup)

  assert.equal(existsSync(staged.root), true)
  staged.cleanup()
  assert.equal(existsSync(staged.root), false)
  assert.doesNotThrow(() => staged.cleanup())
  assert.equal(existsSync(staged.snapshot), false)
})

linuxStagingTest('staging snapshot retains the already-open source root across a pathname replacement race', t => {
  const source = createSnapshotSource(t)
  const replacement = createSnapshotSource(t)
  const displaced = fs.mkdtempSync(join(tmpdir(), 'dsh-staging-displaced-'))
  fs.rmSync(displaced, { recursive: true, force: true })
  t.after(() => fs.rmSync(displaced, { recursive: true, force: true }))
  fs.writeFileSync(join(source, 'safe.txt'), 'safe source content')
  fs.writeFileSync(join(replacement, 'secret.txt'), 'outside replacement content')
  const originalOpen = fs.openSync
  let replaced = false
  fs.openSync = (candidate, ...args) => {
    const fd = originalOpen(candidate, ...args)
    if (!replaced && typeof candidate === 'string' && basename(candidate).startsWith('snapshot-')) {
      fs.renameSync(source, displaced)
      fs.renameSync(replacement, source)
      replaced = true
    }
    return fd
  }
  let staged
  try {
    staged = createStagingSnapshot(source)
  } finally {
    fs.openSync = originalOpen
  }
  t.after(staged.cleanup)

  assert.equal(replaced, true)
  assert.equal(fs.readFileSync(join(staged.snapshot, 'safe.txt'), 'utf8'), 'safe source content')
  assert.equal(existsSync(join(staged.snapshot, 'secret.txt')), false)
})

linuxStagingTest('staging snapshot rolls back its tracked owner root after a full I/O failure', t => {
  const source = createSnapshotSource(t)
  fs.writeFileSync(join(source, 'safe.txt'), 'safe')
  const originalRead = fs.readSync
  fs.readSync = () => {
    const error = new Error('simulated I/O failure')
    error.code = 'EIO'
    throw error
  }
  try {
    assertRejectedAndOwnerDisposed(() => createStagingSnapshot(source), 'staging-copy-failed')
  } finally {
    fs.readSync = originalRead
  }
})

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
  assert.doesNotThrow(() => createTestStagingCapability())
  assert.throws(
    () => createStagingCapability({
      root: 'C:\\Users\\Administrator\\.ssh',
      snapshot: 'C:\\Users\\Administrator\\.ssh\\snapshot-0123456789abcdef',
    }),
    (error) => error?.code === 'staging-capability-factory-arguments',
  )
  assert.throws(
    () => createStagingCapability(STAGING_ROOT, STAGED_ROOT),
    (error) => error?.code === 'staging-capability-factory-arguments',
  )

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
  assert.throws(
    () => disposeStagingCapability(copiedCapability),
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
  for (const key of ['stagedRoot', 'stagingRoot']) {
    const code = key === 'stagedRoot'
      ? 'raw-staged-root-not-allowed'
      : 'raw-staging-root-not-allowed'
    assert.throws(
      () => normalizeContainerPolicy({
        engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, [key]: undefined,
      }),
      (error) => error?.code === code,
    )
    assert.throws(
      () => buildEngineArgs(request({ [key]: undefined })),
      (error) => error?.code === code,
    )
  }
  const proxiedCapability = new Proxy(STAGING_CAPABILITY, {})
  assert.throws(
    () => normalizeContainerPolicy({
      engine: 'docker', image: IMAGE, stagingCapability: proxiedCapability,
    }),
    (error) => error?.code === 'invalid-staging-capability',
  )

  const ownedCapability = createTestStagingCapability()
  assert.equal(Object.isFrozen(ownedCapability), true)
  assert.equal(ownedCapability.root.startsWith('C:\\Users\\Administrator\\.ssh'), false)
  assert.equal(ownedCapability.snapshot.startsWith('C:\\Users\\Administrator\\.ssh'), false)
  const ownedArgv = buildEngineArgs(request({ stagingCapability: ownedCapability }))
  assert.equal(ownedArgv.some((value) => value.includes(ownedCapability.snapshot)), true)
  assert.equal(ownedArgv.some((value) => value.includes('\\.ssh')), false)
  assert.throws(
    () => createStagingCapability({
      root: STAGING_ROOT,
      snapshot: `${STAGED_ROOT},readonly=false`,
    }),
    (error) => error?.code === 'staging-capability-factory-arguments',
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
      (error) => error?.code === 'staging-capability-factory-arguments',
    )
  }
})

test('staging capability cleanup removes its complete factory-owned workspace', () => {
  const capability = createTestStagingCapability()
  try {
    assert.equal(existsSync(capability.root), true)
    assert.equal(existsSync(capability.snapshot), true)

    disposeStagingCapability(capability)

    assert.equal(existsSync(capability.root), false)
    assert.equal(existsSync(capability.snapshot), false)
  } finally {
    disposeTestStagingCapability(capability)
  }
})

test('staging capability cleanup is safe to repeat', () => {
  const capability = createTestStagingCapability()
  try {
    disposeStagingCapability(capability)
    assert.equal(existsSync(capability.root), false)

    assert.doesNotThrow(() => disposeStagingCapability(capability))
    assert.equal(existsSync(capability.root), false)
  } finally {
    disposeTestStagingCapability(capability)
  }
})

test('staging capability factory rolls back its owner root when snapshot creation fails', () => {
  const originalMkdirSync = fs.mkdirSync
  let failedRoot
  fs.mkdirSync = (...args) => {
    const [candidate] = args
    if (basename(candidate).startsWith('snapshot-')) {
      failedRoot = dirname(candidate)
      const error = new Error('simulated snapshot creation failure')
      error.code = 'EACCES'
      throw error
    }
    return originalMkdirSync(...args)
  }
  syncBuiltinESMExports()

  try {
    assert.throws(
      () => createStagingCapability(),
      (error) => error?.code === 'staging-capability-factory-failed',
    )
    assert.equal(typeof failedRoot, 'string')
    assert.equal(existsSync(failedRoot), false)
  } finally {
    fs.mkdirSync = originalMkdirSync
    syncBuiltinESMExports()
    if (failedRoot !== undefined) fs.rmSync(failedRoot, { recursive: true, force: true })
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
  assert.equal(docker.includes('--pull=never'), true)
  assert.equal(docker.includes('--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m'), true)
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

const CONTAINER_ID_A = 'a'.repeat(64)
const CONTAINER_ID_B = 'b'.repeat(64)
const LOCAL_DOCKER_ENDPOINT = 'npipe:////./pipe/docker_engine'
const LOCAL_PODMAN_ENDPOINT = 'unix:///run/user/1000/podman/podman.sock'
const LOCAL_DOCKER_CONTEXT = `${JSON.stringify({
  Name: 'default', Current: true, DockerEndpoint: LOCAL_DOCKER_ENDPOINT,
})}\n`
const LOCAL_PODMAN_CONNECTIONS = JSON.stringify([{
  Name: 'podman-machine-default', URI: LOCAL_PODMAN_ENDPOINT, Default: true,
}])

function immutableContainerRunSpec(runId = '123e4567-e89b-12d3-a456-426614174000') {
  return Object.freeze({
    runId,
    target: Object.freeze({ fixture: 'dynamic-target' }),
    profile: 'observe',
    entrypoints: Object.freeze(['index.js']),
    canaries: Object.freeze({ runId }),
  })
}

function createCommandRunner(responses) {
  const calls = []
  const runner = async (file, args, options) => {
    calls.push({ file, args: [...args], options: { ...options } })
    let response = responses.shift()
    if (typeof response === 'function') response = await response({ file, args, options, calls })
    if (response instanceof Error) throw response
    return response
  }
  return { runner, calls }
}

function localProbeFor(engine) {
  return engine === 'docker'
    ? { stdout: LOCAL_DOCKER_CONTEXT, stderr: '' }
    : { stdout: LOCAL_PODMAN_CONNECTIONS, stderr: '' }
}

function generatedRunnerLabel(call) {
  const encoded = call.args.at(call.args.indexOf('--label') + 1)
  return encoded.slice('dsh.sentinel.run='.length)
}

function endpointPrefix(engine, endpoint) {
  return engine === 'docker' ? ['--host', endpoint] : ['--url', endpoint]
}

test('container backend detects a bounded local Docker or Podman context through an argv runner', async () => {
  for (const engine of ['docker', 'podman']) {
    const command = createCommandRunner([localProbeFor(engine)])
    const backend = createContainerBackend({
      engine, image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
    })

    const result = await backend.available()

    assert.deepEqual(result, {
      available: true,
      backend: engine,
      code: 'container-available',
      capabilities: { context: 'local', image: 'immutable', network: 'none' },
    })
    assert.equal(command.calls.length, 1)
    assert.equal(command.calls[0].file, engine)
    assert.equal(command.calls[0].options.shell, false)
    assert.equal(command.calls[0].options.timeout, CONTAINER_BACKEND_LIMITS.probeTimeoutMs)
    assert.equal(command.calls[0].options.maxBuffer, CONTAINER_BACKEND_LIMITS.probeOutputBytes)
    assert.equal(Object.isFrozen(command.calls[0].options.env), true)
    for (const key of ['DOCKER_HOST', 'CONTAINER_HOST', 'DOCKER_CONTEXT', 'CONTAINER_CONNECTION']) {
      assert.equal(Object.hasOwn(command.calls[0].options.env, key), false)
    }
    assert.equal(command.calls[0].args.includes('context'), engine === 'docker')
  }
})

test('container backend binds a verified local environment before later commands', async () => {
  const environment = {
    PATH: 'C:\\safe-bin',
    DSH_TEST_SAFE: 'retained',
    DOCKER_HOST: '',
    CONTAINER_HOST: '',
    DOCKER_CONTEXT: '',
    CONTAINER_CONNECTION: '',
  }
  const command = createCommandRunner([
    localProbeFor('docker'),
    { stdout: `${CONTAINER_ID_A}\n`, stderr: '' },
    ({ calls }) => ({
      stdout: JSON.stringify({ 'dsh.sentinel.run': generatedRunnerLabel(calls[1]) }), stderr: '',
    }),
  ])
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY,
    commandRunner: command.runner, environment,
  })

  assert.equal((await backend.available()).available, true)
  environment.DOCKER_HOST = 'ssh://remote.example'

  await assert.rejects(
    () => backend.prepare(immutableContainerRunSpec()),
    error => error?.code === 'container-not-available',
  )
  assert.equal(command.calls.length, 1)

  environment.DOCKER_HOST = ''
  const handle = await backend.prepare(immutableContainerRunSpec())
  assert.ok(handle)
  for (const call of command.calls) {
    assert.equal(Object.isFrozen(call.options.env), true)
    assert.equal(call.options.env.PATH, 'C:\\safe-bin')
    assert.equal(call.options.env.DSH_TEST_SAFE, 'retained')
    for (const key of ['DOCKER_HOST', 'CONTAINER_HOST', 'DOCKER_CONTEXT', 'CONTAINER_CONNECTION']) {
      assert.equal(Object.hasOwn(call.options.env, key), false)
    }
  }
})

test('container backend binds the probed local endpoint across create, inspect, and cleanup', async () => {
  for (const engine of ['docker', 'podman']) {
    let simulatedDefaultEndpoint = engine === 'docker' ? LOCAL_DOCKER_ENDPOINT : LOCAL_PODMAN_ENDPOINT
    const environment = {
      PATH: 'C:\\safe-bin',
      DOCKER_CONFIG: 'C:\\remote-docker-config',
      CONTAINERS_CONF: 'C:\\remote-containers.conf',
      PODMAN_CONNECTIONS_CONF: 'C:\\remote-connections.conf',
      XDG_CONFIG_HOME: 'C:\\remote-config-home',
    }
    const command = createCommandRunner([
      localProbeFor(engine),
      { stdout: `${CONTAINER_ID_A}\n`, stderr: '' },
      ({ calls }) => ({
        stdout: JSON.stringify({ 'dsh.sentinel.run': generatedRunnerLabel(calls[1]) }), stderr: '',
      }),
      { stdout: '', stderr: '' },
    ])
    const backend = createContainerBackend({
      engine, image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
      environment,
    })

    assert.equal((await backend.available()).available, true)
    simulatedDefaultEndpoint = 'ssh://remote.example'
    environment.PATH = 'C:\\redirected-bin'
    const handle = await backend.prepare(immutableContainerRunSpec())
    await backend.cleanup(handle)

    const endpoint = engine === 'docker' ? LOCAL_DOCKER_ENDPOINT : LOCAL_PODMAN_ENDPOINT
    for (const call of command.calls.slice(1)) {
      assert.deepEqual(call.args.slice(0, 2), endpointPrefix(engine, endpoint))
      assert.equal(call.args.includes(simulatedDefaultEndpoint), false)
      assert.equal(call.options.env.PATH, 'C:\\safe-bin')
      assert.equal(Object.hasOwn(call.options.env, 'DOCKER_CONFIG'), false)
      assert.equal(Object.hasOwn(call.options.env, 'CONTAINERS_CONF'), false)
      assert.equal(Object.hasOwn(call.options.env, 'PODMAN_CONNECTIONS_CONF'), false)
      assert.equal(Object.hasOwn(call.options.env, 'XDG_CONFIG_HOME'), false)
    }
  }
})

test('container backend production execFile path receives a frozen sanitized environment', async () => {
  const calls = []
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY,
    environment: {
      PATH: 'C:\\safe-bin',
      DOCKER_HOST: '',
      CONTAINER_HOST: '',
      DOCKER_CONTEXT: '',
      CONTAINER_CONNECTION: '',
    },
    execFile: async (file, args, options) => {
      calls.push({ file, args: [...args], options })
      return localProbeFor('docker')
    },
  })

  assert.equal((await backend.available()).available, true)
  assert.equal(calls.length, 1)
  assert.equal(isAbsolute(calls[0].file), true)
  assert.equal(calls[0].file.toLowerCase().includes(process.cwd().toLowerCase()), false)
  assert.equal(isAbsolute(calls[0].options.cwd), true)
  assert.notEqual(calls[0].options.cwd, process.cwd())
  assert.equal(Object.isFrozen(calls[0].options.env), true)
  assert.equal(calls[0].options.env.PATH.toLowerCase().includes(process.cwd().toLowerCase()), false)
  for (const key of ['DOCKER_HOST', 'CONTAINER_HOST', 'DOCKER_CONTEXT', 'CONTAINER_CONNECTION']) {
    assert.equal(Object.hasOwn(calls[0].options.env, key), false)
  }
})

test('container backend production execFile binds trusted absolute engine paths for Docker and Podman', async () => {
  for (const engine of ['docker', 'podman']) {
    const calls = []
    const backend = createContainerBackend({
      engine, image: IMAGE, stagingCapability: STAGING_CAPABILITY,
      environment: { PATH: `${process.cwd()};C:\\fake-bin` },
      execFile: async (file, args, options) => {
        calls.push({ file, args: [...args], options })
        return localProbeFor(engine)
      },
    })

    assert.equal((await backend.available()).available, true)
    assert.equal(calls.length, 1)
    assert.equal(isAbsolute(calls[0].file), true)
    assert.notEqual(calls[0].file, engine)
    assert.equal(calls[0].file.toLowerCase().includes(process.cwd().toLowerCase()), false)
    assert.equal(isAbsolute(calls[0].options.cwd), true)
    assert.notEqual(calls[0].options.cwd, process.cwd())
    assert.equal(calls[0].options.env.PATH.toLowerCase().includes(process.cwd().toLowerCase()), false)
  }
})

test('container backend fails closed for an untrusted executable path without probing', async () => {
  const calls = []
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY,
    trustedEnginePath: `${process.cwd()}\\fake-docker.exe`,
    execFile: async (...args) => {
      calls.push(args)
      return localProbeFor('docker')
    },
  })

  assert.deepEqual(await backend.available(), {
    available: false, backend: 'docker', code: 'container-executable-unavailable', capabilities: null,
  })
  assert.equal(calls.length, 0)
})

test('container backend refuses Docker host overrides before probing an engine', async () => {
  const command = createCommandRunner([])
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY,
    commandRunner: command.runner, environment: { DOCKER_HOST: 'ssh://remote.example' },
  })

  assert.deepEqual(await backend.available(), {
    available: false, backend: 'docker', code: 'container-remote-context', capabilities: null,
  })
  assert.equal(command.calls.length, 0)
})

test('container backend refuses every configured remote context override before probing an engine', async () => {
  for (const key of ['DOCKER_HOST', 'CONTAINER_HOST', 'DOCKER_CONTEXT', 'CONTAINER_CONNECTION']) {
    const command = createCommandRunner([])
    const backend = createContainerBackend({
      engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY,
      commandRunner: command.runner, environment: { [key]: 'remote-context' },
    })

    assert.deepEqual(await backend.available(), {
      available: false, backend: 'docker', code: 'container-remote-context', capabilities: null,
    })
    assert.equal(command.calls.length, 0)
  }
})

test('container backend rejects lowercase and mixed-case remote selector variants before probing', async () => {
  for (const selector of ['DOCKER_HOST', 'CONTAINER_HOST', 'DOCKER_CONTEXT', 'CONTAINER_CONNECTION']) {
    for (const key of [selector.toLowerCase(), `${selector[0].toLowerCase()}${selector.slice(1)}`]) {
      const command = createCommandRunner([])
      const backend = createContainerBackend({
        engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY,
        commandRunner: command.runner, environment: { [key]: 'ssh://remote.example' },
      })

      assert.deepEqual(await backend.available(), {
        available: false, backend: 'docker', code: 'container-remote-context', capabilities: null,
      })
      assert.equal(command.calls.length, 0)
    }
  }
})

test('container backend removes case variants of config selectors from the production environment', async () => {
  const calls = []
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY,
    environment: {
      PATH: 'C:\\safe-bin',
      pAtH: 'C:\\fake-bin',
      docker_config: 'C:\\lower-docker-config',
      DoCkEr_CoNfIg: 'C:\\mixed-docker-config',
      containers_conf: 'C:\\lower-containers.conf',
      CoNtAiNeRs_CoNf: 'C:\\mixed-containers.conf',
      containers_storage_conf: 'C:\\lower-storage.conf',
      podman_connections_conf: 'C:\\lower-connections.conf',
      xdg_config_home: 'C:\\lower-config-home',
      dOcKeR_HoSt: '',
      cOnTaInEr_HoSt: '',
      dOcKeR_CoNtExT: '',
      cOnTaInEr_CoNnEcTiOn: '',
    },
    execFile: async (file, args, options) => {
      calls.push({ file, args: [...args], options })
      return localProbeFor('docker')
    },
  })

  assert.equal((await backend.available()).available, true)
  assert.equal(calls.length, 1)
  const childEnvironment = calls[0].options.env
  const configSelectors = [
    'DOCKER_HOST', 'CONTAINER_HOST', 'DOCKER_CONTEXT', 'CONTAINER_CONNECTION',
    'DOCKER_CONFIG', 'CONTAINERS_CONF', 'CONTAINERS_STORAGE_CONF',
    'PODMAN_CONNECTIONS_CONF', 'XDG_CONFIG_HOME',
  ]
  for (const key of Object.keys(childEnvironment)) {
    assert.equal(configSelectors.includes(key.toUpperCase()), false, `unexpected config selector ${key}`)
  }
  assert.deepEqual(Object.keys(childEnvironment).filter(key => key.toUpperCase() === 'PATH'), ['PATH'])
  assert.equal(childEnvironment.PATH.toLowerCase().includes(process.cwd().toLowerCase()), false)
})

test('container backend refuses a remote engine context returned by the bounded probe', async () => {
  const command = createCommandRunner([{
    stdout: `${JSON.stringify({ Name: 'remote', Current: true, DockerEndpoint: 'ssh://remote.example' })}\n`,
    stderr: '',
  }])
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
  })

  assert.deepEqual(await backend.available(), {
    available: false, backend: 'docker', code: 'container-remote-context', capabilities: null,
  })
})

test('container backend refuses mutable images and normalizes engine probe failures', async () => {
  const mutableCommand = createCommandRunner([])
  const mutable = createContainerBackend({
    engine: 'docker', image: 'registry.example/dsh-runner:latest',
    stagingCapability: STAGING_CAPABILITY, commandRunner: mutableCommand.runner,
  })
  const failedCommand = createCommandRunner([{ stdout: '', stderr: 'private engine failure', exitCode: 1 }])
  const failed = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: failedCommand.runner,
  })

  assert.deepEqual(await mutable.available(), {
    available: false, backend: 'docker', code: 'container-image-invalid', capabilities: null,
  })
  assert.equal(mutableCommand.calls.length, 0)
  assert.deepEqual(await failed.available(), {
    available: false, backend: 'docker', code: 'container-engine-unavailable', capabilities: null,
  })
})

test('container backend normalizes a probe timeout without exposing engine diagnostics', async () => {
  const timeout = new Error('private engine timeout')
  timeout.code = 'ETIMEDOUT'
  const command = createCommandRunner([timeout])
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
  })

  assert.deepEqual(await backend.available(), {
    available: false, backend: 'docker', code: 'container-engine-unavailable', capabilities: null,
  })
})

test('container backend rejects oversized hostile probe output without returning it', async () => {
  const command = createCommandRunner([{
    stdout: 'x'.repeat(CONTAINER_BACKEND_LIMITS.probeOutputBytes + 1), stderr: '',
  }])
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
  })

  assert.deepEqual(await backend.available(), {
    available: false, backend: 'docker', code: 'container-probe-output-too-large', capabilities: null,
  })
})

test('container backend rejects unknown probe JSON fields without returning the hostile payload', async () => {
  const command = createCommandRunner([{
    stdout: `${JSON.stringify({
      Name: 'default', Current: true, DockerEndpoint: 'npipe:////./pipe/docker_engine', unexpected: 'hostile',
    })}\n`,
    stderr: '',
  }])
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
  })

  assert.deepEqual(await backend.available(), {
    available: false, backend: 'docker', code: 'container-probe-invalid', capabilities: null,
  })
})

test('container backend creates uniquely labeled hardened runner handles from immutable run specs', async () => {
  const command = createCommandRunner([
    localProbeFor('docker'),
    { stdout: `${CONTAINER_ID_A}\n`, stderr: '' },
    ({ calls }) => ({
      stdout: JSON.stringify({ 'dsh.sentinel.run': generatedRunnerLabel(calls[1]) }), stderr: '',
    }),
    { stdout: `${CONTAINER_ID_B}\n`, stderr: '' },
    ({ calls }) => ({
      stdout: JSON.stringify({ 'dsh.sentinel.run': generatedRunnerLabel(calls[3]) }), stderr: '',
    }),
  ])
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
  })

  assert.equal((await backend.available()).available, true)
  const first = await backend.prepare(immutableContainerRunSpec())
  const second = await backend.prepare(immutableContainerRunSpec('123e4567-e89b-12d3-a456-426614174001'))

  assert.equal(Object.isFrozen(first), true)
  assert.equal(Object.isFrozen(first.ownership), true)
  assert.equal(first.ownership.resourceId, CONTAINER_ID_A)
  assert.notEqual(first.ownership.label, second.ownership.label)
  for (const call of command.calls.filter(call => call.args.includes('run'))) {
    assert.equal(call.args.includes('--pull=never'), true)
    assert.equal(call.args.includes('--network=none'), true)
    assert.equal(call.args.includes('--pid=private'), true)
    assert.equal(call.args.includes('--ipc=private'), true)
    assert.equal(call.args.includes('--read-only'), true)
    assert.equal(call.args.includes('--cap-drop=ALL'), true)
    assert.equal(call.args.includes('--security-opt=no-new-privileges'), true)
    assert.equal(call.args.includes('--user=65532:65532'), true)
    assert.equal(call.args.some(value => value.includes('docker.sock')), false)
  }
})

test('container backend accepts bounded OCI labels while requiring its generated ownership label', async () => {
  const command = createCommandRunner([
    localProbeFor('docker'),
    { stdout: `${CONTAINER_ID_A}\n`, stderr: '' },
    ({ calls }) => ({
      stdout: JSON.stringify({
        'dsh.sentinel.run': generatedRunnerLabel(calls[1]),
        'org.opencontainers.image.title': 'dsh-runner',
        'org.opencontainers.image.version': '1.0.0',
      }), stderr: '',
    }),
  ])
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
  })

  await backend.available()
  await assert.doesNotReject(() => backend.prepare(immutableContainerRunSpec()))
})

test('container backend rejects oversized ownership label maps before registering a handle', async () => {
  const command = createCommandRunner([
    localProbeFor('docker'),
    { stdout: `${CONTAINER_ID_A}\n`, stderr: '' },
    ({ calls }) => ({
      stdout: JSON.stringify({
        'dsh.sentinel.run': generatedRunnerLabel(calls[1]),
        'org.opencontainers.image.annotations': 'x'.repeat(4096),
      }), stderr: '',
    }),
    { stdout: '', stderr: '' },
  ])
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
  })

  await backend.available()
  await assert.rejects(
    () => backend.prepare(immutableContainerRunSpec()),
    error => error?.code === 'container-ownership-unverified',
  )
  assert.deepEqual(command.calls[3].args, ['--host', LOCAL_DOCKER_ENDPOINT, 'rm', '--force', CONTAINER_ID_A])
})

test('container backend rejects ownership that hostile runner output cannot prove from the generated label', async () => {
  const command = createCommandRunner([
    localProbeFor('docker'),
    {
      stdout: `${CONTAINER_ID_A}\n`, stderr: '',
      label: 'dsh-attacker', ownership: { runId: 'attacker', resourceId: 'attacker' },
    },
    { stdout: JSON.stringify({ 'dsh.sentinel.run': 'dsh-attacker' }), stderr: '' },
  ])
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
  })

  await backend.available()
  await assert.rejects(
    () => backend.prepare(immutableContainerRunSpec()),
    error => error?.code === 'container-ownership-unverified',
  )
  assert.equal(command.calls.length, 4)
})

test('container backend refuses a create response without a captured resource ID before ownership lookup', async () => {
  const command = createCommandRunner([
    localProbeFor('docker'),
    { stdout: 'not-a-container-id\n', stderr: '' },
  ])
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
  })

  await backend.available()
  await assert.rejects(
    () => backend.prepare(immutableContainerRunSpec()),
    error => error?.code === 'container-prepare-output-invalid',
  )
  assert.equal(command.calls.length, 2)
})

test('container backend removes the exact newly created resource when ownership validation fails', async () => {
  const command = createCommandRunner([
    localProbeFor('docker'),
    { stdout: `${CONTAINER_ID_A}\n`, stderr: '' },
    { stdout: JSON.stringify({ 'dsh.sentinel.run': 'dsh-attacker' }), stderr: '' },
    { stdout: '', stderr: '' },
  ])
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
  })

  await backend.available()
  await assert.rejects(
    () => backend.prepare(immutableContainerRunSpec()),
    error => error?.code === 'container-ownership-unverified',
  )
  assert.deepEqual(command.calls[3].args, ['--host', LOCAL_DOCKER_ENDPOINT, 'rm', '--force', CONTAINER_ID_A])
  assert.equal(command.calls.some(call => call.args.includes('dsh-attacker')), false)
})

test('container backend retains failed rollback reservations at the active-resource ceiling', async () => {
  let createAttempts = 0
  let rollbackAttempts = 0
  const command = createCommandRunner([])
  command.runner = async (file, args, options) => {
    command.calls.push({ file, args: [...args], options: { ...options } })
    if (args.includes('context') || args.includes('connection')) return localProbeFor('docker')
    if (args.includes('run')) {
      createAttempts += 1
      return { stdout: `${String(createAttempts).padStart(64, '0')}\n`, stderr: '' }
    }
    if (args.includes('inspect')) return { stdout: '{}', stderr: '' }
    if (args.includes('rm')) {
      rollbackAttempts += 1
      return { stdout: '', stderr: '', exitCode: 1 }
    }
    return { stdout: '', stderr: '', exitCode: 1 }
  }
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
  })

  await backend.available()
  for (let attempt = 0; attempt < CONTAINER_BACKEND_LIMITS.maxActiveResources + 1; attempt += 1) {
    await assert.rejects(
      () => backend.prepare(immutableContainerRunSpec()),
      error => error?.code === 'container-ownership-unverified' || error?.code === 'container-label-generation-failed',
    )
  }
  assert.equal(createAttempts, CONTAINER_BACKEND_LIMITS.maxActiveResources)
  assert.equal(rollbackAttempts, CONTAINER_BACKEND_LIMITS.maxActiveResources)
})

test('container backend treats a deeply frozen run spec as structural input, not provenance proof', async () => {
  const command = createCommandRunner([localProbeFor('docker')])
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
  })

  await backend.available()
  const structurallyValidCopy = Object.freeze({ ...immutableContainerRunSpec() })
  await assert.rejects(() => backend.prepare(structurallyValidCopy), error => error?.code === 'container-prepare-failed')
  assert.equal(command.calls.length, 2)
})

test('container backend runs each allowlisted stage in a fresh hardened runner and collects owned evidence', async () => {
  const command = createCommandRunner([
    localProbeFor('docker'),
  ])
  const stageIds = [CONTAINER_ID_A, CONTAINER_ID_B, 'c'.repeat(64)]
  command.runner = async (file, args, options) => {
    command.calls.push({ file, args: [...args], options: { ...options } })
    if (args.includes('context')) return localProbeFor('docker')
    if (args.includes('run')) {
      const runCount = command.calls.filter(call => call.args.includes('run')).length
      const id = runCount === 1 ? CONTAINER_ID_A : stageIds[runCount - 2]
      return { stdout: `${id}\n`, stderr: '' }
    }
    if (args.includes('inspect')) {
      const runCall = [...command.calls].reverse().find(call => call.args.includes('run'))
      return { stdout: JSON.stringify({ 'dsh.sentinel.run': generatedRunnerLabel(runCall) }), stderr: '' }
    }
    if (args.includes('wait')) return { stdout: '0\n', stderr: '' }
    if (args.includes('logs')) {
      return { stdout: JSON.stringify({ networkAttempts: [] }), stderr: '' }
    }
    if (args.includes('rm')) return { stdout: '', stderr: '' }
    return { stdout: '', stderr: '', exitCode: 1 }
  }
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
  })
  await backend.available()
  const handle = await backend.prepare(immutableContainerRunSpec())

  for (const name of ['load', 'registration', 'invocation']) {
    await assert.doesNotReject(() => backend.runStage(handle, Object.freeze({ name })))
  }
  const evidence = await backend.collect(handle)
  assert.deepEqual(evidence.networkAttempts, [])
  const stageCalls = command.calls.filter(call => ['load', 'registration', 'invocation'].includes(call.args.at(-1)))
  assert.equal(stageCalls.length, 3)
  assert.equal(command.calls.filter(call => call.args.includes('exec')).length, 0)
  for (const [index, call] of stageCalls.entries()) {
    assert.equal(call.args.includes('--pull=never'), true)
    assert.equal(call.args.includes('--network=none'), true)
    assert.equal(call.args.includes('--pid=private'), true)
    assert.equal(call.args.includes('--ipc=private'), true)
    assert.equal(call.args.includes('--read-only'), true)
    assert.equal(call.args.includes('--cap-drop=ALL'), true)
    assert.equal(call.args.includes('--security-opt=no-new-privileges'), true)
    assert.equal(call.args.includes('--entrypoint=/usr/local/bin/dsh-sentinel-harness'), true)
    assert.equal(call.args.at(-1), ['load', 'registration', 'invocation'][index])
    assert.deepEqual(call.args.slice(0, 2), ['--host', LOCAL_DOCKER_ENDPOINT])
    assert.equal(Object.isFrozen(call.options.env), true)
    assert.equal(call.options.shell, false)
  }
})

test('container backend rejects forged handles and every non-schema stage without invoking a runner', async () => {
  const command = createCommandRunner([
    localProbeFor('docker'),
    { stdout: `${CONTAINER_ID_A}\n`, stderr: '' },
    ({ calls }) => ({
      stdout: JSON.stringify({ 'dsh.sentinel.run': generatedRunnerLabel(calls[1]) }), stderr: '',
    }),
  ])
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
  })
  await backend.available()
  const handle = await backend.prepare(immutableContainerRunSpec())
  const forged = Object.freeze({ ...handle, ownership: Object.freeze({ ...handle.ownership }) })

  await assert.rejects(() => backend.runStage(forged, Object.freeze({ name: 'load' })), error => error?.code === 'container-handle-invalid')
  await assert.rejects(() => backend.collect(forged), error => error?.code === 'container-handle-invalid')
  for (const stageSpec of [
    { name: 'load', argv: ['--privileged'] },
    { name: 'evil' },
    Object.freeze({ name: 'load', extra: 'forged' }),
    { name: 'load' },
  ]) {
    await assert.rejects(() => backend.runStage(handle, stageSpec), error => error?.code === 'container-stage-invalid')
  }
  assert.equal(command.calls.length, 3)
})

test('container backend bounds and normalizes stage timeout, crash, nonzero, malformed, and oversized output', async () => {
  const cases = [
    ['timeout', ({ args }) => args.includes('wait') ? Object.assign(new Error('engine secret C:\\host\\private'), { code: 'ETIMEDOUT' }) : null, 'container-stage-timeout'],
    ['nonzero', ({ args }) => args.includes('wait') ? { stdout: '137\n', stderr: 'private engine diagnostics' } : null, 'container-stage-nonzero'],
    ['malformed', ({ args }) => args.includes('logs') ? { stdout: '{not-json', stderr: '' } : null, 'container-stage-evidence-invalid'],
    ['oversized', ({ args }) => args.includes('logs') ? { stdout: 'x'.repeat(CONTAINER_PHASE_B_LIMITS.outputBytes + 1), stderr: '' } : null, 'container-stage-output-too-large'],
  ]

  for (const [name, responseFor, expectedCode] of cases) {
    const command = createCommandRunner([localProbeFor('docker')])
    command.runner = async (file, args, options) => {
      command.calls.push({ file, args: [...args], options: { ...options } })
      if (args.includes('context')) return localProbeFor('docker')
      if (args.includes('run')) return { stdout: `${CONTAINER_ID_A}\n`, stderr: '' }
      if (args.includes('inspect')) {
        const runCall = [...command.calls].reverse().find(call => call.args.includes('run'))
        return { stdout: JSON.stringify({ 'dsh.sentinel.run': generatedRunnerLabel(runCall) }), stderr: '' }
      }
      const selected = responseFor({ file, args, options, calls: command.calls })
      if (selected instanceof Error) throw selected
      if (selected !== null) return selected
      if (args.includes('wait')) return { stdout: '0\n', stderr: '' }
      if (args.includes('logs')) return { stdout: JSON.stringify({ networkAttempts: [] }), stderr: '' }
      if (args.includes('rm')) return { stdout: '', stderr: '' }
      return { stdout: '', stderr: '', exitCode: 1 }
    }
    const backend = createContainerBackend({
      engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
    })
    await backend.available()
    const handle = await backend.prepare(immutableContainerRunSpec())

    await assert.rejects(
      () => backend.runStage(handle, Object.freeze({ name: 'load' })),
      error => error?.code === expectedCode && error.message === expectedCode,
    )
    assert.equal(command.calls.some(call => call.args.includes('C:\\host\\private')), false)
    assert.deepEqual(command.calls.at(-1).args, ['--host', LOCAL_DOCKER_ENDPOINT, 'rm', '--force', CONTAINER_ID_A])
  }
})

test('container backend retains an exact failed stage cleanup for bounded retry and never completes collection early', async () => {
  let cleanupAttempts = 0
  const command = createCommandRunner([localProbeFor('docker')])
  command.runner = async (file, args, options) => {
    command.calls.push({ file, args: [...args], options: { ...options } })
    if (args.includes('context')) return localProbeFor('docker')
    if (args.includes('run')) return { stdout: `${CONTAINER_ID_A}\n`, stderr: '' }
    if (args.includes('inspect')) {
      const runCall = [...command.calls].reverse().find(call => call.args.includes('run'))
      return { stdout: JSON.stringify({ 'dsh.sentinel.run': generatedRunnerLabel(runCall) }), stderr: '' }
    }
    if (args.includes('wait')) return { stdout: '0\n', stderr: '' }
    if (args.includes('logs')) return { stdout: JSON.stringify({ networkAttempts: [] }), stderr: '' }
    if (args.includes('rm')) {
      cleanupAttempts += 1
      return cleanupAttempts === 1 ? { stdout: '', stderr: '', exitCode: 1 } : { stdout: '', stderr: '' }
    }
    return { stdout: '', stderr: '', exitCode: 1 }
  }
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
  })
  await backend.available()
  const handle = await backend.prepare(immutableContainerRunSpec())

  await assert.rejects(
    () => backend.runStage(handle, Object.freeze({ name: 'load' })),
    error => error?.code === 'container-stage-cleanup-incomplete',
  )
  await assert.rejects(
    () => backend.collect(handle),
    error => error?.code === 'container-collection-incomplete',
  )
  assert.deepEqual(await backend.cleanup(handle), { complete: true })
  assert.deepEqual(command.calls.at(-1).args, ['--host', LOCAL_DOCKER_ENDPOINT, 'rm', '--force', CONTAINER_ID_A])
  assert.deepEqual(await backend.cleanup(handle), { complete: true })
  assert.equal(command.calls.filter(call => call.args.includes('rm')).length, 3)
})

test('container backend carries the verified Docker and Podman binding into every stage command', async () => {
  for (const engine of ['docker', 'podman']) {
    const endpoint = engine === 'docker' ? LOCAL_DOCKER_ENDPOINT : LOCAL_PODMAN_ENDPOINT
    const environment = { PATH: 'C:\\trusted-engine-bin', DSH_STAGE_TEST: 'kept' }
    const command = createCommandRunner([])
    command.runner = async (file, args, options) => {
      command.calls.push({ file, args: [...args], options: { ...options } })
      if (args.includes('context') || args.includes('connection')) return localProbeFor(engine)
      if (args.includes('run')) {
        const id = command.calls.filter(call => call.args.includes('run')).length === 1 ? CONTAINER_ID_A : CONTAINER_ID_B
        return { stdout: `${id}\n`, stderr: '' }
      }
      if (args.includes('inspect')) {
        const runCall = [...command.calls].reverse().find(call => call.args.includes('run'))
        return { stdout: JSON.stringify({ 'dsh.sentinel.run': generatedRunnerLabel(runCall) }), stderr: '' }
      }
      if (args.includes('wait')) return { stdout: '0\n', stderr: '' }
      if (args.includes('logs')) return { stdout: JSON.stringify({ networkAttempts: [] }), stderr: '' }
      if (args.includes('rm')) return { stdout: '', stderr: '' }
      return { stdout: '', stderr: '', exitCode: 1 }
    }
    const backend = createContainerBackend({
      engine, image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner, environment,
    })
    await backend.available()
    const handle = await backend.prepare(immutableContainerRunSpec())
    await backend.runStage(handle, Object.freeze({ name: 'load' }))

    const stageCalls = command.calls.filter(call => call.args.includes(CONTAINER_ID_B))
    assert.ok(stageCalls.length >= 4)
    for (const call of stageCalls) {
      assert.equal(call.file, engine)
      assert.deepEqual(call.args.slice(0, 2), engine === 'docker' ? ['--host', endpoint] : ['--url', endpoint])
      assert.equal(call.options.env.PATH, environment.PATH)
      assert.equal(call.options.env.DSH_STAGE_TEST, environment.DSH_STAGE_TEST)
      assert.equal(call.options.shell, false)
    }
    await backend.cleanup(handle)
  }
})

test('container backend converts a cancelled late stage into a fixed failure and cleans its captured ID', async () => {
  const command = createCommandRunner([])
  command.runner = async (file, args, options) => {
    command.calls.push({ file, args: [...args], options: { ...options } })
    if (args.includes('context')) return localProbeFor('docker')
    if (args.includes('run')) {
      const id = command.calls.filter(call => call.args.includes('run')).length === 1 ? CONTAINER_ID_A : CONTAINER_ID_B
      return { stdout: `${id}\n`, stderr: '' }
    }
    if (args.includes('inspect')) {
      const runCall = [...command.calls].reverse().find(call => call.args.includes('run'))
      return { stdout: JSON.stringify({ 'dsh.sentinel.run': generatedRunnerLabel(runCall) }), stderr: '' }
    }
    if (args.includes('wait')) {
      await new Promise(resolve => setTimeout(resolve, 20))
      return { stdout: '0\n', stderr: '' }
    }
    if (args.includes('rm')) return { stdout: '', stderr: '' }
    return { stdout: '', stderr: '', exitCode: 1 }
  }
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
  })
  await backend.available()
  const handle = await backend.prepare(immutableContainerRunSpec())
  const controller = new AbortController()
  const stage = backend.runStage(handle, Object.freeze({ name: 'load' }), controller.signal)
  await new Promise(resolve => setTimeout(resolve, 1))
  controller.abort()

  await assert.rejects(stage, error => error?.code === 'container-stage-cancelled')
  assert.deepEqual(command.calls.at(-1).args, ['--host', LOCAL_DOCKER_ENDPOINT, 'rm', '--force', CONTAINER_ID_B])
})

test('container backend refuses a non-factory staging object before it can reach a create command', async () => {
  const command = createCommandRunner([localProbeFor('docker')])
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE,
    stagingCapability: Object.freeze({ root: 'C:/host', snapshot: 'C:/host/snapshot-untrusted' }),
    commandRunner: command.runner,
  })

  await backend.available()
  await assert.rejects(
    () => backend.prepare(immutableContainerRunSpec()),
    error => error?.code === 'container-prepare-refused',
  )
  assert.equal(command.calls.length, 1)
})

test('container backend retains its caller-tightened cleanup execution bounds', async () => {
  const limits = Object.freeze({ timeoutMs: 17, memoryBytes: 1024, pidsLimit: 2, outputBytes: 128 })
  const command = createCommandRunner([
    localProbeFor('docker'),
    { stdout: `${CONTAINER_ID_A}\n`, stderr: '' },
    ({ calls }) => ({
      stdout: JSON.stringify({ 'dsh.sentinel.run': generatedRunnerLabel(calls[1]) }), stderr: '',
    }),
    { stdout: '', stderr: '' },
  ])
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY,
    limits, commandRunner: command.runner,
  })

  await backend.available()
  const handle = await backend.prepare(immutableContainerRunSpec())

  assert.deepEqual(await backend.cleanup(handle), { complete: true })
  assert.equal(command.calls[3].options.timeout, limits.timeoutMs)
  assert.equal(command.calls[3].options.maxBuffer, limits.outputBytes)
})

test('container backend cleanup only removes a resource captured by this backend prepare call', async () => {
  const command = createCommandRunner([
    localProbeFor('docker'),
    { stdout: `${CONTAINER_ID_A}\n`, stderr: '' },
    ({ calls }) => ({
      stdout: JSON.stringify({ 'dsh.sentinel.run': generatedRunnerLabel(calls[1]) }), stderr: '',
    }),
    { stdout: '', stderr: '' },
  ])
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
  })

  await backend.available()
  const handle = await backend.prepare(immutableContainerRunSpec())
  const forged = Object.freeze({ ...handle, ownership: Object.freeze({ ...handle.ownership }) })

  assert.deepEqual(await backend.cleanup(forged), { complete: false })
  assert.equal(command.calls.length, 3)
  assert.deepEqual(await backend.cleanup(handle), { complete: true })
  assert.equal(command.calls.length, 4)
  assert.deepEqual(command.calls[3].args, ['--host', LOCAL_DOCKER_ENDPOINT, 'rm', '--force', CONTAINER_ID_A])
})

test('container backend reports a failed owned cleanup with a fixed incomplete result', async () => {
  const command = createCommandRunner([
    localProbeFor('docker'),
    { stdout: `${CONTAINER_ID_A}\n`, stderr: '' },
    ({ calls }) => ({
      stdout: JSON.stringify({ 'dsh.sentinel.run': generatedRunnerLabel(calls[1]) }), stderr: '',
    }),
    { stdout: '', stderr: '', exitCode: 1 },
  ])
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
  })

  await backend.available()
  const handle = await backend.prepare(immutableContainerRunSpec())

  assert.deepEqual(await backend.cleanup(handle), { complete: false })
  assert.deepEqual(command.calls[3].args, ['--host', LOCAL_DOCKER_ENDPOINT, 'rm', '--force', CONTAINER_ID_A])
})

test('container backend suppresses duplicate cleanup after its owned resource is removed', async () => {
  const command = createCommandRunner([
    localProbeFor('docker'),
    { stdout: `${CONTAINER_ID_A}\n`, stderr: '' },
    ({ calls }) => ({
      stdout: JSON.stringify({ 'dsh.sentinel.run': generatedRunnerLabel(calls[1]) }), stderr: '',
    }),
    { stdout: '', stderr: '' },
  ])
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
  })

  await backend.available()
  const handle = await backend.prepare(immutableContainerRunSpec())

  assert.deepEqual(await backend.cleanup(handle), { complete: true })
  assert.deepEqual(await backend.cleanup(handle), { complete: true })
  assert.equal(command.calls.length, 4)
})

test('container backend makes concurrent cleanup single-flight and shares its fixed result', async () => {
  let releaseCleanup
  const cleanupGate = new Promise(resolve => { releaseCleanup = resolve })
  const command = createCommandRunner([
    localProbeFor('docker'),
    { stdout: `${CONTAINER_ID_A}\n`, stderr: '' },
    ({ calls }) => ({
      stdout: JSON.stringify({ 'dsh.sentinel.run': generatedRunnerLabel(calls[1]) }), stderr: '',
    }),
  ])
  command.runner = async (file, args, options) => {
    command.calls.push({ file, args: [...args], options: { ...options } })
    if (command.calls.length === 1) return localProbeFor('docker')
    if (args.includes('run')) return { stdout: `${CONTAINER_ID_A}\n`, stderr: '' }
    if (args.includes('inspect')) {
      return { stdout: JSON.stringify({ 'dsh.sentinel.run': generatedRunnerLabel(command.calls[1]) }), stderr: '' }
    }
    if (args.includes('rm')) {
      await cleanupGate
      return { stdout: '', stderr: '' }
    }
    return { stdout: '', stderr: '', exitCode: 1 }
  }
  const backend = createContainerBackend({
    engine: 'docker', image: IMAGE, stagingCapability: STAGING_CAPABILITY, commandRunner: command.runner,
  })
  await backend.available()
  const handle = await backend.prepare(immutableContainerRunSpec())

  const first = backend.cleanup(handle)
  const second = backend.cleanup(handle)
  await Promise.resolve()
  assert.equal(command.calls.filter(call => call.args.includes('rm')).length, 1)
  releaseCleanup()
  const results = await Promise.all([first, second])
  assert.deepEqual(results, [{ complete: true }, { complete: true }])
  assert.equal(command.calls.filter(call => call.args.includes('rm')).length, 1)
})
