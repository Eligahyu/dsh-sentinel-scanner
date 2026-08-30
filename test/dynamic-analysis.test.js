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
