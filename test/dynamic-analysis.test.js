import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { DYNAMIC_HARD_LIMITS, normalizeDynamicOptions } from '../engine/dynamic/policy.js'
import { createCanarySet } from '../engine/dynamic/canaries.js'
import { evidenceDigest, normalizeDynamicEvidence } from '../engine/dynamic/evidence.js'
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
