import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { main } from '../bin/sentinel.mjs'

function capture() {
  const buf = { out: '', err: '' }
  return {
    buf,
    stdout: { write(s) { buf.out += s }, isTTY: false },
    stderr: { write(s) { buf.err += s }, isTTY: false },
  }
}

test('help documents exit code 3 and the built-in fail-on high default', async () => {
  const io = capture()
  const code = await main(['--help'], io)
  assert.equal(code, 0)
  assert.match(io.buf.out, /built-in default is --fail-on high/)
  assert.match(io.buf.out, /3\s+incomplete static scan/)
  assert.doesNotMatch(io.buf.out, /0 = safe\/review/)
})

test('missing and invalid CLI values exit 2 before scanning', async () => {
  const cases = [
    [['--max-files'], /--max-files requires a value/],
    [['--max-files', 'foo'], /--max-files must be a positive integer/],
    [['--max-files', '0'], /--max-files must be a positive integer/],
    [['--max-files', '1.5'], /--max-files must be a positive integer/],
    [['--max-files', '-3'], /--max-files requires a value/],
    [['--max-plugins', '0'], /--max-plugins must be a positive integer/],
    [['--max-bytes'], /--max-bytes requires a value/],
    [['--out'], /--out requires a value/],
    [['--config'], /--config requires a value/],
    [['--baseline'], /--baseline requires a value/],
    [['--format'], /--format requires a value/],
    [['--fail-on'], /--fail-on requires a value/],
    [['--mode'], /--mode requires a value/],
    [['--profile'], /--profile requires a value/],
    [['--profile', '--json'], /--profile requires a value/],
    [['--profile='], /--profile requires a profile name/],
    [['--profilefoo'], /unknown option --profilefoo/],
  ]
  for (const [args, pattern] of cases) {
    const io = capture()
    const code = await main(args, io)
    assert.equal(code, 2, args.join(' '))
    assert.match(io.buf.err, pattern, args.join(' '))
    assert.equal(io.buf.out, '', `stdout must stay empty for ${args.join(' ')}`)
  }
})

test('--profile=name is a profile name and does not consume the next flag', async () => {
  const io = capture()
  const code = await main(['--profile=web', '--max-files', 'nope'], io)
  assert.equal(code, 2)
  assert.match(io.buf.err, /--max-files must be a positive integer/)
  assert.doesNotMatch(io.buf.err, /unknown option/)
  assert.equal(io.buf.out, '')
})

test('default fail-on high ignores a medium-only file and accepts a positive limit', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'cli-flags-'))
  try {
    const medium = join(tmp, 'medium.js')
    writeFileSync(medium, "fetch('https://api.example.com/x')\n")
    const io = capture()
    const code = await main([medium, '--json', '--max-files', '2', '--max-bytes', '4096'], io)
    assert.equal(code, 0)
    const report = JSON.parse(io.buf.out)
    assert.ok(report.findings.some((finding) => finding.id === 'SEN-NET-001'))
    assert.ok((report.summary.bySeverity.high ?? 0) === 0)
    assert.ok((report.summary.bySeverity.critical ?? 0) === 0)
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})
