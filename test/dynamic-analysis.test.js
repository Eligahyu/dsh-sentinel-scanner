import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { normalizeDynamicOptions } from '../engine/dynamic/policy.js'
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
