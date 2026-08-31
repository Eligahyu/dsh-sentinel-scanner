import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { DYNAMIC_HARD_LIMITS, normalizeDynamicOptions } from '../engine/dynamic/policy.js'
import { createCanarySet } from '../engine/dynamic/canaries.js'
import { evidenceDigest, normalizeDynamicEvidence } from '../engine/dynamic/evidence.js'
import { resolveDynamicBackend } from '../engine/dynamic/backend-resolver.js'
import {
  DYNAMIC_STAGES,
  evaluateDynamicPreflight,
  runDynamicAnalysis,
} from '../engine/dynamic/orchestrator.js'
import { FakeDynamicBackend } from './helpers/fake-dynamic-backend.js'
import { loadConfig } from '../engine/config.js'
import { main } from '../bin/sentinel.mjs'

const capture = () => {
  const buf = { out: '', err: '' }
  const stdout = { isTTY: false, write(value) { buf.out += value } }
  const stderr = { isTTY: false, write(value) { buf.err += value } }
  return { stdout, stderr, buf }
}

test('dynamic options normalize defaults and bounded accepted values', () => {
  assert.deepEqual(normalizeDynamicOptions({}), {
    requested: false,
    backendName: 'auto',
    profile: 'observe',
    timeoutMs: 15000,
  })
  assert.deepEqual(normalizeDynamicOptions({
    dynamic: true,
    dynamicBackend: 'docker',
    dynamicProfile: 'observe',
    dynamicTimeoutMs: '1200',
  }), {
    requested: true,
    backendName: 'docker',
    profile: 'observe',
    timeoutMs: 1200,
  })
  assert.equal(normalizeDynamicOptions({ dynamicBackend: 'podman' }).backendName, 'podman')
  assert.equal(normalizeDynamicOptions({ dynamic: true, dynamicTimeoutMs: 60000 }).timeoutMs, 30000)
  assert.equal(normalizeDynamicOptions({ dynamic: true, dynamicTimeoutMs: 400 }).timeoutMs, 1000)
})

test('dynamic options reject unsupported values and non-finite timeouts', () => {
  assert.throws(() => normalizeDynamicOptions({ dynamicBackend: 'remote' }), /dynamic backend/i)
  assert.throws(() => normalizeDynamicOptions({ dynamicProfile: 'internet' }), /dynamic profile/i)
  assert.throws(() => normalizeDynamicOptions({ dynamicTimeoutMs: 'not-a-number' }), /dynamic timeout/i)
  assert.throws(() => normalizeDynamicOptions({ dynamicTimeoutMs: Infinity }), /dynamic timeout/i)
  for (const value of ['', '   ', false, true, [], [1500]]) {
    assert.throws(
      () => normalizeDynamicOptions({ dynamicTimeoutMs: value }),
      /dynamic timeout/i,
      `rejects non-numeric timeout value ${JSON.stringify(value)}`,
    )
  }
})

test('dynamic configuration exposes only bounded primitive defaults', () => {
  const root = mkdtempSync(join(tmpdir(), 'dynamic-config-'))
  try {
    writeFileSync(join(root, 'sentinel.config.json'), JSON.stringify({
      dynamic: true,
      dynamicBackend: 'podman',
      dynamicProfile: 'observe',
      dynamicTimeoutMs: 2500,
      dynamicBackendAdapter: { execute: 'forbidden' },
      commandPath: 'docker',
      image: 'untrusted:image',
      endpoint: 'https://example.invalid',
      privileged: true,
    }))
    const { config } = loadConfig({ cwd: root })
    assert.deepEqual({
      dynamic: config.dynamic,
      dynamicBackend: config.dynamicBackend,
      dynamicProfile: config.dynamicProfile,
      dynamicTimeoutMs: config.dynamicTimeoutMs,
    }, {
      dynamic: true,
      dynamicBackend: 'podman',
      dynamicProfile: 'observe',
      dynamicTimeoutMs: 2500,
    })
    assert.equal(Object.hasOwn(config, 'dynamicBackendAdapter'), false)
    assert.equal(Object.hasOwn(config, 'commandPath'), false)
    assert.equal(Object.hasOwn(config, 'image'), false)
    assert.equal(Object.hasOwn(config, 'endpoint'), false)
    assert.equal(Object.hasOwn(config, 'privileged'), false)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('dynamic CLI accepts normalized primitive flags', async () => {
  const root = mkdtempSync(join(tmpdir(), 'dynamic-cli-'))
  try {
    writeFileSync(join(root, 'safe.js'), 'export const safe = true\n')
    const io = capture()
    const code = await main([
      root,
      '--dynamic',
      '--dynamic-backend', 'docker',
      '--dynamic-profile', 'observe',
      '--dynamic-timeout', '60000',
      '--json',
    ], io)
    assert.equal(code, 0)
    assert.doesNotThrow(() => JSON.parse(io.buf.out))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('dynamic CLI sends invalid or missing option values through usage errors', async () => {
  for (const args of [
    ['--dynamic-backend', 'remote'],
    ['--dynamic-profile', 'internet'],
    ['--dynamic-backend'],
    ['--dynamic-profile'],
    ['--dynamic-timeout'],
    ['--dynamic-timeout', 'Infinity'],
  ]) {
    const io = capture()
    const code = await main(['.', ...args], io)
    assert.equal(code, 2, `expected usage error for ${args.join(' ')}`)
    assert.match(io.buf.err, /dynamic[- ](backend|profile|timeout)/i)
  }
})

test('dynamic canary descriptors are stable metadata without raw values', () => {
  const canaries = createCanarySet({
    runId: 'run-test',
    entropy: size => Buffer.alloc(size, 0x41),
  })
  const kinds = [
    'api-key', 'bearer-token', 'environment-secret', 'ssh-file',
    'workspace-document', 'conversation', 'memory', 'tool-argument',
  ]

  assert.deepEqual(canaries.descriptors.map(item => item.kind), kinds)
  assert.deepEqual(canaries.descriptors.map(item => item.id), kinds)
  assert.equal(Object.isFrozen(canaries.values), true)
  assert.equal(Object.isFrozen(canaries.descriptors), true)
  for (const descriptor of canaries.descriptors) {
    assert.match(descriptor.digest, /^[a-f0-9]{64}$/)
    assert.equal(Object.hasOwn(descriptor, 'value'), false)
    assert.equal(JSON.stringify(descriptor).includes(canaries.values[descriptor.kind === 'api-key'
      ? 'apiKey'
      : descriptor.kind.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())]), false)
  }
  assert.equal(JSON.stringify(canaries.descriptors).includes(canaries.values.apiKey), false)
})

test('dynamic evidence recursively redacts canaries and host paths while dropping unknown fields', () => {
  const canaries = createCanarySet({
    runId: 'run-test',
    entropy: size => Buffer.alloc(size, 0x41),
  })
  const normalized = normalizeDynamicEvidence({
    stdout: `prefix ${canaries.values.apiKey} suffix`,
    networkAttempts: [{
      destination: 'sink.invalid',
      body: { nested: canaries.values.apiKey },
      unknownField: 'must-not-survive',
    }],
    fileEvents: [
      { path: 'C:\\Users\\alice\\secret.txt', operation: 'read' },
      { path: '/home/alice/secret.txt', operation: 'write' },
    ],
    unknownCollection: [{ body: canaries.values.apiKey }],
  }, { canaries, limits: DYNAMIC_HARD_LIMITS })

  assert.equal(JSON.stringify(normalized).includes(canaries.values.apiKey), false)
  assert.equal(normalized.networkAttempts[0].canaryIds.includes('api-key'), true)
  assert.match(normalized.networkAttempts[0].body.nested, /\[CANARY:api-key\]/)
  assert.match(normalized.stdout, /\[CANARY:api-key\]/)
  assert.equal(normalized.fileEvents[0].path, '[HOST_PATH]')
  assert.equal(normalized.fileEvents[1].path, '[HOST_PATH]')
  assert.equal(Object.hasOwn(normalized.networkAttempts[0], 'unknownField'), false)
  assert.equal(Object.hasOwn(normalized, 'unknownCollection'), false)
})

test('dynamic evidence accepts report collections and records bounded truncation', () => {
  const limits = {
    ...DYNAMIC_HARD_LIMITS,
    maxEvents: 4,
    maxListItems: 1,
    maxTextBytes: 8,
    maxEvidenceDepth: 2,
  }
  const normalized = normalizeDynamicEvidence({
    stdout: '0123456789abcdef',
    stages: [{ name: 'one' }, { name: 'two' }],
    networkAttempts: [{ destination: 'one', body: { first: 'a', second: 'b' } }, { destination: 'two' }],
    dnsQueries: [{ hostname: 'one' }, { hostname: 'two' }],
    processes: [{ command: 'one' }, { command: 'two' }],
    fileEvents: [{ path: '/tmp/one' }, { path: '/tmp/two' }],
    canaryEvents: [{ canaryId: 'api-key' }, { canaryId: 'bearer-token' }],
    policyViolations: [{ reason: 'one' }, { reason: 'two' }],
    limitations: [{ reason: 'existing' }, { reason: 'extra' }],
    failures: [{ reason: 'one' }, { reason: 'two' }],
  }, { limits })

  const eventCount = [
    'stages', 'networkAttempts', 'dnsQueries', 'processes', 'fileEvents',
    'canaryEvents', 'policyViolations', 'limitations', 'failures',
  ].reduce((total, field) => total + normalized[field].length, 0)
  assert.ok(eventCount <= limits.maxEvents)
  for (const field of [
    'stages', 'networkAttempts', 'dnsQueries', 'processes', 'fileEvents',
    'canaryEvents', 'policyViolations', 'limitations', 'failures',
  ]) {
    assert.ok(normalized[field].length <= limits.maxListItems, `${field} exceeded its item cap`)
  }
  assert.ok(Object.keys(normalized.networkAttempts[0].body).length <= limits.maxListItems)
  assert.ok(normalized.limitations.some(item => item.reason === 'evidence-truncated'))
  assert.ok(Buffer.byteLength(normalized.stdout, 'utf8') <= limits.maxTextBytes)
})

test('dynamic evidence digest is stable when object key order differs', () => {
  const first = normalizeDynamicEvidence({
    networkAttempts: [{ destination: 'sink.invalid', body: { z: 1, a: 2 } }],
  })
  const second = normalizeDynamicEvidence({
    networkAttempts: [{ body: { a: 2, z: 1 }, destination: 'sink.invalid' }],
  })

  assert.equal(evidenceDigest(first), evidenceDigest(second))
  assert.match(evidenceDigest(first), /^[a-f0-9]{64}$/)
  assert.equal(Object.hasOwn(first, 'stdout'), false)
  assert.equal(Object.hasOwn(first, 'stderr'), false)
})

test('dynamic evidence keeps truncation notices inside the total event cap', () => {
  const limits = { ...DYNAMIC_HARD_LIMITS, maxEvents: 2, maxListItems: 5 }
  const repeated = Array.from({ length: 6 }, (_, index) => ({ name: `event-${index}` }))
  const normalized = normalizeDynamicEvidence({
    stages: repeated,
    networkAttempts: repeated,
    dnsQueries: repeated,
    processes: repeated,
    fileEvents: repeated,
    canaryEvents: repeated,
    policyViolations: repeated,
    limitations: repeated,
    failures: repeated,
  }, { limits })

  const eventCount = [
    'stages', 'networkAttempts', 'dnsQueries', 'processes', 'fileEvents',
    'canaryEvents', 'policyViolations', 'limitations', 'failures',
  ].reduce((total, field) => total + normalized[field].length, 0)
  assert.ok(eventCount <= limits.maxEvents)
  assert.ok(normalized.limitations.length <= limits.maxEvents)
})

test('dynamic evidence rejects partial, duplicate, and arbitrary canary metadata safely', () => {
  const canaries = createCanarySet({
    runId: 'run-review',
    entropy: size => Buffer.alloc(size, 0x42),
  })
  const malformed = [
    { ...canaries, descriptors: canaries.descriptors.slice(0, -1) },
    {
      ...canaries,
      descriptors: canaries.descriptors.map((descriptor, index) => (
        index === 1 ? { ...descriptor, id: canaries.descriptors[0].id } : descriptor
      )),
    },
    {
      ...canaries,
      descriptors: canaries.descriptors.map((descriptor, index) => (
        index === 0 ? { ...descriptor, id: canaries.values.apiKey } : descriptor
      )),
    },
  ]
  const descriptorsWithExtraMetadata = [...canaries.descriptors]
  Object.defineProperty(descriptorsWithExtraMetadata, 'untrusted', {
    value: canaries.values.apiKey,
    enumerable: true,
  })
  malformed.push({ ...canaries, descriptors: descriptorsWithExtraMetadata })

  for (const candidate of malformed) {
    const normalized = normalizeDynamicEvidence({
      networkAttempts: [{ body: canaries.values.apiKey }],
    }, { canaries: candidate })
    const serialized = JSON.stringify(normalized)
    assert.equal(serialized.includes(canaries.values.apiKey), false)
    assert.equal(serialized.includes(`[CANARY:${canaries.values.apiKey}]`), false)
    assert.deepEqual(normalized.failures, [{ reason: 'evidence-rejected', code: 'invalid-canary-set' }])
  }
})

test('dynamic evidence never leaks raw canary keys through truncation notices', () => {
  const canaries = createCanarySet({
    runId: 'run-review',
    entropy: size => Buffer.alloc(size, 0x43),
  })
  const body = {}
  Object.defineProperty(body, canaries.values.apiKey, { value: 'hidden', enumerable: true })
  const normalized = normalizeDynamicEvidence({
    networkAttempts: [{ body }],
  }, { canaries, limits: { ...DYNAMIC_HARD_LIMITS, maxTextBytes: 1 } })

  assert.equal(JSON.stringify(normalized).includes(canaries.values.apiKey), false)
  for (const limitation of normalized.limitations) {
    assert.equal(typeof limitation.field === 'string' && limitation.field.includes(canaries.values.apiKey), false)
  }
})

test('dynamic evidence drops unknown nested fields instead of preserving arbitrary payload keys', () => {
  const canaries = createCanarySet({
    runId: 'run-review',
    entropy: size => Buffer.alloc(size, 0x44),
  })
  const normalized = normalizeDynamicEvidence({
    networkAttempts: [{
      body: {
        content: canaries.values.apiKey,
        unknownNested: { secret: canaries.values.bearerToken },
      },
    }],
  }, { canaries })

  assert.equal(normalized.networkAttempts[0].body.content, '[CANARY:api-key]')
  assert.equal(Object.hasOwn(normalized.networkAttempts[0].body, 'unknownNested'), false)
  assert.equal(JSON.stringify(normalized).includes(canaries.values.bearerToken), false)
})

test('dynamic evidence does not execute discarded getters', () => {
  const canaries = createCanarySet({
    runId: 'run-review',
    entropy: size => Buffer.alloc(size, 0x45),
  })
  let getterRan = false
  const event = { destination: 'sink.invalid' }
  Object.defineProperty(event, 'unknownSecret', {
    enumerable: true,
    get() {
      getterRan = true
      throw new Error(canaries.values.apiKey)
    },
  })

  const normalized = normalizeDynamicEvidence({ networkAttempts: [event] }, { canaries })
  assert.equal(getterRan, false)
  assert.equal(JSON.stringify(normalized).includes(canaries.values.apiKey), false)
  assert.equal(Object.hasOwn(normalized.networkAttempts[0], 'unknownSecret'), false)
})

test('dynamic evidence converts throwing accessors and proxies to fixed safe failures', () => {
  const canaries = createCanarySet({
    runId: 'run-review',
    entropy: size => Buffer.alloc(size, 0x46),
  })
  const event = {}
  Object.defineProperty(event, 'destination', {
    enumerable: true,
    get() {
      throw new Error(canaries.values.apiKey)
    },
  })
  const accessorResult = normalizeDynamicEvidence({ networkAttempts: [event] }, { canaries })
  assert.deepEqual(accessorResult.failures, [{ reason: 'evidence-rejected', code: 'unsafe-input' }])
  assert.equal(JSON.stringify(accessorResult).includes(canaries.values.apiKey), false)

  const proxyInput = new Proxy({}, {
    getOwnPropertyDescriptor() {
      throw new Error(canaries.values.bearerToken)
    },
  })
  const proxyResult = normalizeDynamicEvidence(proxyInput, { canaries })
  assert.deepEqual(proxyResult.failures, [{ reason: 'evidence-rejected', code: 'unsafe-input' }])
  assert.equal(JSON.stringify(proxyResult).includes(canaries.values.bearerToken), false)
})

test('dynamic evidence enforces shared aggregate text and nested item budgets', () => {
  const limits = { ...DYNAMIC_HARD_LIMITS, maxTextBytes: 10, maxListItems: 2 }
  const normalized = normalizeDynamicEvidence({
    stdout: '1234567890',
    stderr: 'abcdefghij',
    networkAttempts: [{ body: { first: 'a', second: 'b' }, headers: { first: 'c', second: 'd' } }],
  }, { limits })

  const textBytes = ['stdout', 'stderr']
    .filter(field => typeof normalized[field] === 'string')
    .reduce((total, field) => total + Buffer.byteLength(normalized[field], 'utf8'), 0)
  assert.ok(textBytes <= limits.maxTextBytes)
  assert.ok(
    Object.keys(normalized.networkAttempts[0].body).length
      + Object.keys(normalized.networkAttempts[0].headers).length <= limits.maxListItems,
  )
})

test('dynamic evidence derives canary attribution instead of trusting supplied ids', () => {
  const canaries = createCanarySet({
    runId: 'run-review',
    entropy: size => Buffer.alloc(size, 0x47),
  })
  const normalized = normalizeDynamicEvidence({
    networkAttempts: [{
      body: 'plain body',
      canaryId: 'api-key',
      canaryIds: ['bearer-token', 'forged-id'],
    }],
  }, { canaries })

  assert.equal(Object.hasOwn(normalized.networkAttempts[0], 'canaryId'), false)
  assert.equal(Object.hasOwn(normalized.networkAttempts[0], 'canaryIds'), false)
})

test('dynamic evidence digest is invariant to supplied attribution order', () => {
  const canaries = createCanarySet({
    runId: 'run-review',
    entropy: size => Buffer.alloc(size, 0x48),
  })
  const first = normalizeDynamicEvidence({
    networkAttempts: [{ body: canaries.values.apiKey, canaryIds: ['bearer-token', 'api-key'] }],
  }, { canaries })
  const second = normalizeDynamicEvidence({
    networkAttempts: [{ body: canaries.values.apiKey, canaryIds: ['api-key', 'bearer-token'] }],
  }, { canaries })

  assert.equal(evidenceDigest(first), evidenceDigest(second))
})

test('dynamic evidence redacts UNC and spaced absolute paths', () => {
  const unc = String.raw`\\server\share\folder with spaces\secret.txt`
  const posix = '/home/alice/folder with spaces/secret.txt'
  const normalized = normalizeDynamicEvidence({ stdout: `${unc} ${posix}` })

  assert.equal(normalized.stdout.includes('server'), false)
  assert.equal(normalized.stdout.includes('/home/'), false)
  assert.equal(normalized.stdout.match(/\[HOST_PATH\]/g)?.length, 2)
})

test('dynamic evidence digest rejects cyclic direct input deterministically', () => {
  const cyclic = { stages: [] }
  cyclic.self = cyclic
  assert.throws(() => evidenceDigest(cyclic), /^Error: invalid normalized evidence$/)

  const sparse = { stages: [] }
  sparse.stages.length = 1
  assert.throws(() => evidenceDigest(sparse), /^Error: invalid normalized evidence$/)

  const extraArrayProperty = normalizeDynamicEvidence({ stages: [{ name: 'stage' }] })
  extraArrayProperty.stages.extra = 'must-not-be-ignored'
  assert.throws(() => evidenceDigest(extraArrayProperty), /^Error: invalid normalized evidence$/)
})

test('dynamic evidence reports exact event drops after reserving the limitation', () => {
  const normalized = normalizeDynamicEvidence({
    networkAttempts: [
      { destination: 'one' },
      { destination: 'two' },
      { destination: 'three' },
    ],
  }, { limits: { ...DYNAMIC_HARD_LIMITS, maxEvents: 2 } })

  const eventCount = normalized.networkAttempts.length
  const truncation = normalized.limitations.find(item => item.reason === 'evidence-truncated' && item.kind === 'events')
  assert.equal(truncation.dropped, 3 - eventCount)
})

test('dynamic evidence bounds text scanning and buffering before expensive sanitization', () => {
  const canaries = createCanarySet({
    runId: 'run-round-two',
    entropy: size => Buffer.alloc(size, 0x49),
  })
  const limits = { ...DYNAMIC_HARD_LIMITS, maxTextBytes: 64 }
  const huge = `${canaries.values.apiKey} ${'x'.repeat(8 * 1024 * 1024)}`
  const originalIncludes = String.prototype.includes
  const originalBufferFrom = Buffer.from
  let largestScannedString = 0
  let oversizedBufferInput = false
  String.prototype.includes = function (...args) {
    largestScannedString = Math.max(largestScannedString, this.length)
    return originalIncludes.apply(this, args)
  }
  Buffer.from = function (value, ...args) {
    if (typeof value === 'string' && value.length > 4096) oversizedBufferInput = true
    return originalBufferFrom.call(this, value, ...args)
  }
  try {
    const normalized = normalizeDynamicEvidence({ stdout: huge }, { canaries, limits })
    assert.match(normalized.stdout, /\[CANARY:api-key\]/)
    assert.ok(Buffer.byteLength(normalized.stdout, 'utf8') <= limits.maxTextBytes)
  } finally {
    String.prototype.includes = originalIncludes
    Buffer.from = originalBufferFrom
  }
  assert.ok(largestScannedString <= 4096)
  assert.equal(oversizedBufferInput, false)
})

test('dynamic evidence redacts paths before newline and preserves trailing narrative', () => {
  const cases = [
    [`C:\\Users\\alice\\folder with spaces\\secret.txt\n failed to read`, '[HOST_PATH]\n failed to read'],
    [`\\\\server\\share\\folder with spaces\\secret.txt\n failed to read`, '[HOST_PATH]\n failed to read'],
    ['/home/alice/folder with spaces/secret.txt\n failed to read', '[HOST_PATH]\n failed to read'],
    [`C:\\Users\\alice\\folder with spaces\\secret.txt failed to read`, '[HOST_PATH] failed to read'],
    [`\\\\server\\share\\folder with spaces\\secret.txt failed to read`, '[HOST_PATH] failed to read'],
    ['/home/alice/folder with spaces/secret.txt failed to read', '[HOST_PATH] failed to read'],
  ]
  for (const [input, expected] of cases) {
    const normalized = normalizeDynamicEvidence({ stdout: input })
    assert.equal(normalized.stdout, expected, input)
  }
})

test('dynamic evidence digest rejects non-enumerable and non-canonical normalized fields', () => {
  const nonEnumerable = normalizeDynamicEvidence({ networkAttempts: [{ destination: 'sink.invalid' }] })
  Object.defineProperty(nonEnumerable.networkAttempts[0], 'destination', {
    value: 'sink.invalid', enumerable: false, writable: true, configurable: true,
  })
  assert.throws(() => evidenceDigest(nonEnumerable), /^Error: invalid normalized evidence$/)

  const canaries = createCanarySet({
    runId: 'run-round-two-digest',
    entropy: size => Buffer.alloc(size, 0x4a),
  })
  const unsorted = normalizeDynamicEvidence({
    networkAttempts: [{ body: `${canaries.values.apiKey} ${canaries.values.bearerToken}` }],
  }, { canaries })
  const ids = unsorted.networkAttempts[0].canaryIds
  ids.reverse()
  assert.throws(() => evidenceDigest(unsorted), /^Error: invalid normalized evidence$/)
})

test('dynamic evidence keeps text-array containers digestable at zero evidence depth', () => {
  const normalized = normalizeDynamicEvidence({
    dnsQueries: [{ answers: ['safe.example'] }],
  }, { limits: { ...DYNAMIC_HARD_LIMITS, maxEvidenceDepth: 0 } })

  assert.ok(Array.isArray(normalized.dnsQueries[0].answers))
  assert.doesNotThrow(() => evidenceDigest(normalized))
})

test('dynamic evidence structurally terminates drive UNC and POSIX path redaction', () => {
  const cases = [
    [`C:\\Users\\alice\\folder with spaces\\secret.txt\n could not be read`, '[HOST_PATH]\n could not be read'],
    [`\\\\server\\share\\folder with spaces\\secret.txt\n could not be read`, '[HOST_PATH]\n could not be read'],
    ['/home/alice/folder with spaces/secret.txt\n could not be read', '[HOST_PATH]\n could not be read'],
    [`C:\\Users\\alice\\folder with spaces\\secret.txt could not be read`, '[HOST_PATH] could not be read'],
    [`\\\\server\\share\\folder with spaces\\secret.txt could not be read`, '[HOST_PATH] could not be read'],
    ['/home/alice/folder with spaces/secret.txt could not be read', '[HOST_PATH] could not be read'],
    [`"C:\\Users\\alice\\folder with spaces\\secret.txt" could not be read`, '"[HOST_PATH]" could not be read'],
    [`"\\\\server\\share\\folder with spaces\\secret.txt" could not be read`, '"[HOST_PATH]" could not be read'],
    ['"/home/alice/folder with spaces/secret.txt" could not be read', '"[HOST_PATH]" could not be read'],
    [`C:\\Users\\alice\\folder with spaces\\secret.txt`, '[HOST_PATH]'],
    [`\\\\server\\share\\folder with spaces\\secret.txt`, '[HOST_PATH]'],
    ['/home/alice/folder with spaces/secret.txt', '[HOST_PATH]'],
  ]
  for (const [input, expected] of cases) {
    assert.equal(normalizeDynamicEvidence({ stdout: input }).stdout, expected, input)
  }
})

test('dynamic evidence redacts quoted host paths with escaped delimiters safely', () => {
  const cases = [
    [String.raw`"/home/alice/a\"b/secret.txt" arbitrary narrative`, '"[HOST_PATH]" arbitrary narrative'],
    [String.raw`'C:\Users\alice\a\'b\secret.txt' arbitrary narrative`, "'[HOST_PATH]' arbitrary narrative"],
    [String.raw`"\\server\share\a\"b\secret.txt" arbitrary narrative`, '"[HOST_PATH]" arbitrary narrative'],
    [String.raw`'/home/alice/a\'b/secret.txt' arbitrary narrative`, "'[HOST_PATH]' arbitrary narrative"],
    [String.raw`"C:\Users\alice\escaped\\" arbitrary narrative`, '"[HOST_PATH]" arbitrary narrative'],
    [String.raw`'\\server\share\escaped\\' arbitrary narrative`, "'[HOST_PATH]' arbitrary narrative"],
    ['"/home/alice/secret.txt\nnext narrative', '"[HOST_PATH]\nnext narrative'],
    [String.raw`"/home/alice/a\"b/secret.txt arbitrary narrative`, '"[HOST_PATH]'],
  ]
  for (const [input, expected] of cases) {
    assert.equal(normalizeDynamicEvidence({ stdout: input }).stdout, expected, input)
  }
})

test('dynamic evidence digest accepts any sorted non-empty canary subset', () => {
  const onlySubset = normalizeDynamicEvidence({ networkAttempts: [{ destination: 'sink.invalid' }] })
  onlySubset.networkAttempts[0].canaryIds = ['bearer-token']
  assert.match(evidenceDigest(onlySubset), /^[a-f0-9]{64}$/)

  for (const ids of [
    ['bearer-token', 'api-key'],
    ['bearer-token', 'bearer-token'],
    ['unknown-id'],
  ]) {
    const invalid = normalizeDynamicEvidence({ networkAttempts: [{ destination: 'sink.invalid' }] })
    invalid.networkAttempts[0].canaryIds = ids
    assert.throws(() => evidenceDigest(invalid), /^Error: invalid normalized evidence$/)
  }
})

const dynamicOptions = (overrides = {}) => ({
  dynamic: true,
  dynamicBackend: 'auto',
  dynamicProfile: 'observe',
  dynamicTimeoutMs: 1000,
  ...overrides,
})

const eligiblePreflight = () => ({
  scanComplete: true,
  entrypoints: ['index.js'],
})

test('dynamic orchestrator leaves an unrequested run untouched', async () => {
  const backend = new FakeDynamicBackend()
  const result = await runDynamicAnalysis({
    target: 'fixture',
    options: dynamicOptions({ dynamic: false }),
    backend,
    preflight: eligiblePreflight(),
  })

  assert.equal(result.status, 'not-requested')
  assert.equal(result.requested, false)
  assert.equal(backend.calls.length, 0)
})

test('dynamic orchestrator refuses static preflight before checking backend availability', async () => {
  const backend = new FakeDynamicBackend()
  const result = await runDynamicAnalysis({
    target: 'fixture',
    options: dynamicOptions(),
    backend,
    preflight: { scanComplete: false, entrypoints: ['index.js'] },
  })

  assert.equal(result.status, 'refused')
  assert.deepEqual(result.failures, [{ reason: 'preflight-refused', code: 'static-scan-incomplete' }])
  assert.equal(backend.calls.length, 0)
})

test('dynamic orchestrator reports unavailable after eligible preflight without a Phase A backend', async () => {
  const result = await runDynamicAnalysis({
    target: 'fixture',
    options: dynamicOptions(),
    preflight: eligiblePreflight(),
  })

  assert.equal(result.status, 'unavailable')
  assert.deepEqual(result.failures, [{ reason: 'backend-unavailable', code: 'backend-not-implemented-phase-a' }])
})

test('dynamic orchestrator evaluates explicit preflight denials with fixed reason codes', () => {
  assert.deepEqual(
    evaluateDynamicPreflight({ scanComplete: true, entrypoints: [], blockers: [] }),
    { allowed: false, code: 'entrypoint-unresolved' },
  )
  assert.deepEqual(
    evaluateDynamicPreflight({ scanComplete: true, entrypoints: ['index.js'], blockers: [{ highRisk: true }] }),
    { allowed: false, code: 'high-risk-blocker' },
  )
})

test('dynamic orchestrator completes with normalized evidence and immutable run data', async () => {
  const backend = new FakeDynamicBackend({
    evidence: { networkAttempts: [{ destination: 'sink.invalid' }] },
  })
  const result = await runDynamicAnalysis({
    target: 'fixture',
    options: dynamicOptions(),
    backend,
    preflight: eligiblePreflight(),
  })

  assert.equal(result.status, 'complete')
  assert.equal(result.complete, true)
  assert.equal(result.backend, 'injected')
  assert.deepEqual(result.stages.map(item => item.stage), DYNAMIC_STAGES)
  assert.equal(result.networkAttempts[0].destination, 'sink.invalid')
  assert.match(result.evidenceDigest, /^[a-f0-9]{64}$/)
  assert.equal(backend.prepareCalls.length, 1)
  assert.equal(Object.isFrozen(backend.prepareCalls[0]), true)
  assert.equal(Object.isFrozen(backend.prepareCalls[0].canaries), true)
  assert.equal(backend.prepareCalls[0].canaries.values.apiKey.includes(backend.prepareCalls[0].runId), true)
  assert.equal(backend.cleanupCalls.length, 1)
})

test('dynamic orchestrator retains normalized stage evidence returned by the backend', async () => {
  const backend = new FakeDynamicBackend({
    stageEvidence: { load: { stages: [{ stage: 'load', durationMs: 7, status: 'observed' }] } },
  })
  const result = await runDynamicAnalysis({
    target: 'fixture', options: dynamicOptions(), backend, preflight: eligiblePreflight(),
  })

  assert.deepEqual(
    result.stages.find(item => item.durationMs === 7),
    { stage: 'load', durationMs: 7, status: 'observed' },
  )
})

for (const [name, fixture, expectedCode] of [
  ['stage failure', { stageErrors: { registration: new Error('backend secret') } }, 'stage-failed'],
  ['collection failure', { collectError: new Error('backend secret') }, 'collection-failed'],
  ['timeout', { delays: { runStage: 1100 } }, 'timeout'],
]) {
  test(`dynamic orchestrator marks ${name} incomplete and cleans an acquired handle once`, async () => {
    const backend = new FakeDynamicBackend(fixture)
    const result = await runDynamicAnalysis({
      target: 'fixture',
      options: dynamicOptions(),
      backend,
      preflight: eligiblePreflight(),
    })

    assert.equal(result.status, 'incomplete')
    assert.deepEqual(result.failures, [{ reason: 'execution-incomplete', code: expectedCode }])
    assert.equal(backend.prepareCalls.length, 1)
    assert.equal(backend.cleanupCalls.length, 1)
    assert.equal(JSON.stringify(result).includes('backend secret'), false)
  })
}

test('dynamic orchestrator cleans an acquired handle once after cancellation', async () => {
  const controller = new AbortController()
  const backend = new FakeDynamicBackend({ delays: { runStage: 100 } })
  const run = runDynamicAnalysis({
    target: 'fixture',
    options: dynamicOptions(),
    backend,
    preflight: eligiblePreflight(),
    signal: controller.signal,
  })
  setTimeout(() => controller.abort(), 10)
  const result = await run

  assert.equal(result.status, 'incomplete')
  assert.deepEqual(result.failures, [{ reason: 'execution-incomplete', code: 'cancelled' }])
  assert.equal(backend.cleanupCalls.length, 1)
})

test('dynamic orchestrator makes cleanup uncertainty incomplete without backend output', async () => {
  const backend = new FakeDynamicBackend({ cleanupComplete: false })
  const result = await runDynamicAnalysis({
    target: 'fixture',
    options: dynamicOptions(),
    backend,
    preflight: eligiblePreflight(),
  })

  assert.equal(result.status, 'incomplete')
  assert.deepEqual(result.failures, [{ reason: 'cleanup-uncertain', code: 'cleanup-incomplete' }])
  assert.equal(backend.cleanupCalls.length, 1)
})

test('dynamic orchestrator never prepares unavailable or refused runs', async () => {
  const unavailable = new FakeDynamicBackend({ available: false })
  const unavailableResult = await runDynamicAnalysis({
    target: 'fixture', options: dynamicOptions(), backend: unavailable, preflight: eligiblePreflight(),
  })
  const refused = new FakeDynamicBackend()
  const refusedResult = await runDynamicAnalysis({
    target: 'fixture', options: dynamicOptions(), backend: refused,
    preflight: { scanComplete: true, entrypoints: [], blockers: [] },
  })

  assert.equal(unavailableResult.status, 'unavailable')
  assert.equal(refusedResult.status, 'refused')
  assert.equal(unavailable.prepareCalls.length, 0)
  assert.equal(refused.prepareCalls.length, 0)
})

test('dynamic orchestrator replaces backend diagnostics with fixed bounded codes', async () => {
  const unavailableBackend = new FakeDynamicBackend({ available: false, availableCode: 'host path C:\\secret' })
  const unavailable = await runDynamicAnalysis({
    target: 'fixture', options: dynamicOptions(), backend: unavailableBackend, preflight: eligiblePreflight(),
  })
  const noisyEvidenceBackend = new FakeDynamicBackend({
    evidence: { failures: [{ reason: 'backend stack trace: private detail', code: 'untrusted-code' }] },
  })
  const completed = await runDynamicAnalysis({
    target: 'fixture', options: dynamicOptions(), backend: noisyEvidenceBackend, preflight: eligiblePreflight(),
  })

  assert.deepEqual(unavailable.failures, [{ reason: 'backend-unavailable', code: 'backend-unavailable' }])
  assert.equal(JSON.stringify(unavailable).includes('host path'), false)
  assert.deepEqual(completed.failures, [])
  assert.equal(JSON.stringify(completed).includes('backend stack trace'), false)
})

test('dynamic orchestrator resolver exposes only injected backends in Phase A', async () => {
  const injectedBackend = new FakeDynamicBackend()
  const injected = await resolveDynamicBackend({ backendName: 'docker', injectedBackend })
  const unavailable = await resolveDynamicBackend({ backendName: 'docker' })

  assert.equal(injected.backend, injectedBackend)
  assert.equal(unavailable.available, false)
  assert.equal(unavailable.code, 'backend-not-implemented-phase-a')
  assert.equal(Object.isFrozen(unavailable), true)
})

const pause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds))

test('dynamic orchestrator bounds availability and skips it for an already-aborted run', async () => {
  const hung = new FakeDynamicBackend({ delays: { available: 1100 }, ignoreAbort: { available: true } })
  const unavailable = await runDynamicAnalysis({
    target: 'fixture', options: dynamicOptions(), backend: hung, preflight: eligiblePreflight(),
  })
  const controller = new AbortController()
  controller.abort()
  const aborted = new FakeDynamicBackend()
  const cancelled = await runDynamicAnalysis({
    target: 'fixture', options: dynamicOptions(), backend: aborted,
    preflight: eligiblePreflight(), signal: controller.signal,
  })

  assert.deepEqual(unavailable.failures, [{ reason: 'backend-unavailable', code: 'backend-timeout' }])
  assert.equal(hung.prepareCalls.length, 0)
  assert.equal(cancelled.status, 'incomplete')
  assert.deepEqual(cancelled.failures, [{ reason: 'execution-incomplete', code: 'cancelled' }])
  assert.equal(aborted.calls.length, 0)
})

test('dynamic orchestrator cleans a late prepare handle once without an unhandled rejection', async () => {
  const backend = new FakeDynamicBackend({ delays: { prepare: 1100 }, ignoreAbort: { prepare: true } })
  const unhandled = []
  const observeUnhandled = reason => unhandled.push(reason)
  process.on('unhandledRejection', observeUnhandled)
  try {
    const result = await runDynamicAnalysis({
      target: 'fixture', options: dynamicOptions(), backend, preflight: eligiblePreflight(),
    })
    await pause(150)

    assert.equal(result.status, 'incomplete')
    assert.deepEqual(result.failures, [
      { reason: 'execution-incomplete', code: 'timeout' },
      { reason: 'cleanup-uncertain', code: 'operation-not-quiesced' },
    ])
    assert.equal(backend.cleanupCalls.length, 1)
    assert.equal(unhandled.length, 0)
  } finally {
    process.removeListener('unhandledRejection', observeUnhandled)
  }
})

test('dynamic orchestrator waits for a timed-out stage to quiesce before cleanup', async () => {
  const backend = new FakeDynamicBackend({ delays: { runStage: 1100 }, ignoreAbort: { runStage: true } })
  const result = await runDynamicAnalysis({
    target: 'fixture', options: dynamicOptions(), backend, preflight: eligiblePreflight(),
  })
  await pause(150)

  assert.deepEqual(result.failures, [
    { reason: 'execution-incomplete', code: 'timeout' },
    { reason: 'cleanup-uncertain', code: 'operation-not-quiesced' },
  ])
  assert.ok(backend.events.indexOf('runStage:settled') < backend.events.indexOf('cleanup:start'))
})

test('dynamic orchestrator marks timed-out collection incomplete without concurrent cleanup', async () => {
  const backend = new FakeDynamicBackend({ delays: { collect: 1100 }, ignoreAbort: { collect: true } })
  const result = await runDynamicAnalysis({
    target: 'fixture', options: dynamicOptions(), backend, preflight: eligiblePreflight(),
  })
  await pause(150)

  assert.equal(result.status, 'incomplete')
  assert.equal(result.failures[0].code, 'timeout')
  assert.equal(result.failures[1].code, 'operation-not-quiesced')
  assert.ok(backend.events.indexOf('collect:settled') < backend.events.indexOf('cleanup:start'))
})

test('dynamic orchestrator treats every non-exact cleanup result as uncertain', async () => {
  const inherited = Object.create({ complete: true })
  const accessor = {}
  Object.defineProperty(accessor, 'complete', { enumerable: true, get() { return true } })
  for (const cleanupResult of [inherited, accessor, { complete: true, extra: true }]) {
    const backend = new FakeDynamicBackend({ cleanupResult })
    const result = await runDynamicAnalysis({
      target: 'fixture', options: dynamicOptions(), backend, preflight: eligiblePreflight(),
    })
    assert.equal(result.status, 'incomplete')
    assert.deepEqual(result.failures, [{ reason: 'cleanup-uncertain', code: 'cleanup-invalid' }])
  }
  for (const fixture of [
    { cleanupError: new Error('secret cleanup failure') },
    { delays: { cleanup: 1100 }, ignoreAbort: { cleanup: true } },
  ]) {
    const backend = new FakeDynamicBackend(fixture)
    const result = await runDynamicAnalysis({
      target: 'fixture', options: dynamicOptions(), backend, preflight: eligiblePreflight(),
    })
    assert.equal(result.status, 'incomplete')
    assert.equal(result.failures[0].reason, 'cleanup-uncertain')
  }
})

test('dynamic orchestrator validates its backend interface before canary creation', async () => {
  const missingMethod = { available() {}, prepare() {}, runStage() {}, collect() {} }
  const hostile = new Proxy({}, { getPrototypeOf() { throw new Error('backend secret') } })
  const accessor = new FakeDynamicBackend()
  Object.defineProperty(accessor, 'prepare', { get() { throw new Error('backend secret') } })
  for (const backend of [missingMethod, hostile, accessor]) {
    const result = await runDynamicAnalysis({
      target: 'fixture', options: dynamicOptions(), backend, preflight: eligiblePreflight(),
    })
    assert.equal(result.status, 'unavailable')
    assert.deepEqual(result.failures, [{ reason: 'backend-unavailable', code: 'backend-interface-invalid' }])
  }
})

test('dynamic orchestrator rejects unsafe run input and deeply freezes a cloned run spec', async () => {
  const target = { nested: { value: 'safe' } }
  const entrypoint = { resolved: true, nested: { value: 'entry' } }
  const backend = new FakeDynamicBackend()
  const complete = await runDynamicAnalysis({
    target, options: dynamicOptions(), backend,
    preflight: { scanComplete: true, entrypoints: [entrypoint] },
  })
  const runSpec = backend.prepareCalls[0]
  const invalid = await runDynamicAnalysis({
    target: { unsupported() {} }, options: dynamicOptions(), backend: new FakeDynamicBackend(),
    preflight: eligiblePreflight(),
  })
  const extraEntrypoints = ['index.js']
  extraEntrypoints.extra = 'not-json'
  const invalidEntrypoints = await runDynamicAnalysis({
    target: 'fixture', options: dynamicOptions(), backend: new FakeDynamicBackend(),
    preflight: { scanComplete: true, entrypoints: extraEntrypoints },
  })

  assert.equal(complete.status, 'complete')
  assert.notEqual(runSpec.target, target)
  assert.equal(Object.isFrozen(runSpec.target.nested), true)
  assert.equal(Object.isFrozen(runSpec.entrypoints[0].nested), true)
  assert.equal(invalid.status, 'incomplete')
  assert.deepEqual(invalid.failures, [{ reason: 'execution-incomplete', code: 'run-spec-invalid' }])
  assert.equal(invalidEntrypoints.status, 'incomplete')
  assert.deepEqual(invalidEntrypoints.failures, [{ reason: 'execution-incomplete', code: 'run-spec-invalid' }])
})

test('dynamic orchestrator treats hostile evidence and normalization rejection as incomplete', async () => {
  const hostileArray = new Proxy([], { getOwnPropertyDescriptor() { throw new Error('backend secret') } })
  const hostile = new FakeDynamicBackend({ evidence: { networkAttempts: hostileArray } })
  const rejected = new FakeDynamicBackend({
    evidence: { networkAttempts: [{ get destination() { throw new Error('backend secret') } }] },
  })
  const huge = new FakeDynamicBackend({
    evidence: { networkAttempts: Array.from({ length: 10000 }, () => ({ destination: 'sink.invalid' })) },
  })
  for (const backend of [hostile, rejected, huge]) {
    const result = await runDynamicAnalysis({
      target: 'fixture', options: dynamicOptions(), backend, preflight: eligiblePreflight(),
    })
    assert.equal(result.status, 'incomplete')
    assert.equal(result.failures.some(item => item.code === 'evidence-invalid'), true)
    assert.equal(JSON.stringify(result).includes('backend secret'), false)
  }
})

test('dynamic orchestrator reports only configured backend identity and preserves root plus cleanup failures', async () => {
  const backend = new FakeDynamicBackend({
    stageErrors: { load: new Error('backend secret') },
    cleanupComplete: false,
  })
  const result = await runDynamicAnalysis({
    target: 'fixture', options: dynamicOptions({ dynamicBackend: 'docker' }), backend, preflight: eligiblePreflight(),
  })

  assert.equal(result.backend, 'injected')
  assert.deepEqual(result.failures, [
    { reason: 'execution-incomplete', code: 'stage-failed' },
    { reason: 'cleanup-uncertain', code: 'cleanup-incomplete' },
  ])
})

for (const [name, fixture, settledEvent] of [
  ['stage', { delays: { runStage: 1100 }, ignoreAbort: { runStage: true }, stageErrors: { load: new Error('late stage rejection') } }, 'runStage:settled'],
  ['collection', { delays: { collect: 1100 }, ignoreAbort: { collect: true }, collectError: new Error('late collection rejection') }, 'collect:settled'],
]) {
  test(`dynamic orchestrator cleans once after a late ${name} rejection without an unhandled rejection`, async () => {
    const backend = new FakeDynamicBackend(fixture)
    const unhandled = []
    const observeUnhandled = reason => unhandled.push(reason)
    process.on('unhandledRejection', observeUnhandled)
    try {
      const result = await runDynamicAnalysis({
        target: 'fixture', options: dynamicOptions(), backend, preflight: eligiblePreflight(),
      })
      await pause(150)

      assert.equal(result.status, 'incomplete')
      assert.equal(result.failures[0].code, 'timeout')
      assert.equal(result.failures[1].code, 'operation-not-quiesced')
      assert.equal(backend.cleanupCalls.length, 1)
      assert.ok(backend.events.indexOf(settledEvent) < backend.events.indexOf('cleanup:start'))
      assert.equal(unhandled.length, 0)
    } finally {
      process.removeListener('unhandledRejection', observeUnhandled)
    }
  })
}

test('dynamic orchestrator clones own prototype-named target and entrypoint data without prototype mutation', async () => {
  const target = {}
  const entrypoint = { resolved: true }
  const targetProtoPayload = { inheritedTarget: 'attacker-data' }
  const entrypointProtoPayload = { inheritedEntrypoint: 'attacker-data' }
  for (const [value, protoPayload] of [[target, targetProtoPayload], [entrypoint, entrypointProtoPayload]]) {
    Object.defineProperty(value, '__proto__', { value: protoPayload, enumerable: true, writable: true, configurable: true })
    Object.defineProperty(value, 'constructor', { value: { kind: 'constructor-data' }, enumerable: true, writable: true, configurable: true })
    Object.defineProperty(value, 'prototype', { value: { kind: 'prototype-data' }, enumerable: true, writable: true, configurable: true })
  }
  const backend = new FakeDynamicBackend()
  const result = await runDynamicAnalysis({
    target, options: dynamicOptions(), backend,
    preflight: { scanComplete: true, entrypoints: [entrypoint] },
  })
  const runSpec = backend.prepareCalls[0]

  assert.equal(result.status, 'complete')
  assert.equal(Object.getPrototypeOf(runSpec.target), Object.prototype)
  assert.equal(Object.getPrototypeOf(runSpec.entrypoints[0]), Object.prototype)
  for (const [clone, protoPayload] of [[runSpec.target, targetProtoPayload], [runSpec.entrypoints[0], entrypointProtoPayload]]) {
    assert.equal(Object.hasOwn(clone, '__proto__'), true)
    assert.deepEqual(clone.__proto__, protoPayload)
    assert.deepEqual(clone.constructor, { kind: 'constructor-data' })
    assert.deepEqual(clone.prototype, { kind: 'prototype-data' })
    assert.equal(Object.isFrozen(clone.__proto__), true)
    assert.equal(clone.inheritedTarget, undefined)
    assert.equal(clone.inheritedEntrypoint, undefined)
  }
  assert.equal(Object.getPrototypeOf(target), Object.prototype)
  assert.equal(Object.getPrototypeOf(entrypoint), Object.prototype)
  assert.equal(target.inheritedTarget, undefined)
  assert.equal(entrypoint.inheritedEntrypoint, undefined)
})
