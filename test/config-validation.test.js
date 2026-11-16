import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { main } from '../bin/sentinel.mjs'
import { loadConfig } from '../engine/config.js'

function capture() {
  const buf = { out: '', err: '' }
  return {
    buf,
    stdout: { write(s) { buf.out += s }, isTTY: false },
    stderr: { write(s) { buf.err += s }, isTTY: false },
  }
}

function writeConfig(dir, value) {
  writeFileSync(join(dir, 'sentinel.config.json'), JSON.stringify(value))
  writeFileSync(join(dir, 'ok.js'), 'const ok = 1\n')
  return dir
}

test('invalid sentinel.config.json fields fail closed', () => {
  const cases = [
    [{ mode: 'everywhere' }, /mode 必须是/],
    [{ failOn: 'nope' }, /failOn 必须是/],
    [{ maxFiles: '10' }, /maxFiles 必须是正整数/],
    [{ maxFiles: 0 }, /maxFiles 必须是正整数/],
    [{ maxBytesPerFile: 1.5 }, /maxBytesPerFile 必须是正整数/],
    [{ hardMaxBytesPerFile: 10, maxBytesPerFile: 100 }, /hardMaxBytesPerFile 不能小于/],
    [{ ignore: 'engine/**' }, /ignore 必须是非空字符串数组/],
    [{ ignore: [''] }, /ignore 必须是非空字符串数组/],
    [{ trustedScopes: ['@ok', 1] }, /trustedScopes 必须是非空字符串数组/],
    [{ redactPaths: 'true' }, /redactPaths 必须是布尔值/],
    [{ dynamicBackend: 'remote' }, /dynamicBackend 必须是/],
    [{ dynamicTimeoutMs: '15000' }, /dynamicTimeoutMs 必须是有限数字/],
    [[], /根必须是 JSON 对象/],
  ]
  for (const [value, pattern] of cases) {
    const dir = mkdtempSync(join(tmpdir(), 'cfg-bad-'))
    try {
      writeFileSync(join(dir, 'sentinel.config.json'), JSON.stringify(value))
      assert.throws(() => loadConfig({ cwd: dir }), pattern)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }
})

test('unknown config fields are dropped and warned, not executed', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cfg-unknown-'))
  try {
    writeConfig(dir, { failOn: 'low', commandPath: 'docker', image: 'untrusted:image' })
    const loaded = loadConfig({ cwd: dir })
    assert.equal(loaded.config.failOn, 'low')
    assert.equal(Object.hasOwn(loaded.config, 'commandPath'), false)
    assert.equal(Object.hasOwn(loaded.config, 'image'), false)
    assert.match(loaded.warnings.join('\n'), /commandPath/)
    assert.match(loaded.warnings.join('\n'), /image/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('CLI exits 2 on an invalid config and honors config redactPaths', async () => {
  const bad = mkdtempSync(join(tmpdir(), 'cfg-cli-bad-'))
  const redacted = mkdtempSync(join(tmpdir(), 'cfg-cli-redact-'))
  try {
    writeConfig(bad, { maxFiles: -5 })
    const badIo = capture()
    const badCode = await main([bad, '--json'], badIo)
    assert.equal(badCode, 2)
    assert.match(badIo.buf.err, /sentinel.config.json 无效/)
    assert.equal(badIo.buf.out, '')

    writeConfig(redacted, { redactPaths: true, commandPath: 'ignored' })
    const io = capture()
    const code = await main([redacted, '--json'], io)
    assert.equal(code, 0)
    assert.match(io.buf.err, /忽略未知字段 commandPath/)
    const report = JSON.parse(io.buf.out)
    assert.match(report.target.path, /^<workspace>\//)
    for (const finding of report.findings) {
      assert.equal(String(finding.file).includes(redacted), false)
    }
  } finally {
    rmSync(bad, { recursive: true, force: true })
    rmSync(redacted, { recursive: true, force: true })
  }
})
