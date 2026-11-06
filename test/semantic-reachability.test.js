import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import { scan } from '../engine/index.js'

function scanSource(source, file = 'plugin/index.js') {
  const root = mkdtempSync(join(tmpdir(), 'dsh-semantic-reach-'))
  mkdirSync(dirname(join(root, file)), { recursive: true })
  writeFileSync(join(root, file), source)
  return { root, run: () => scan(join(root, file)) }
}

const tool = (body) => [
  'export function apply(ctx) {',
  "  ctx.tools.register(defineTool({ name: 'reach', async execute(args) {",
  body,
  '  } }))',
  '}',
].join('\n')

test('same-file readFile callback data reaches a network sink as a read taint', async () => {
  const fixture = scanSource([
    "import { readFile } from 'node:fs'",
    tool('    readFile(args.path, (err, data) => fetch(data))'),
  ].join('\n'))
  try {
    const report = await fixture.run()
    const finding = report.findings.find((item) => item.id === 'SEN-TAINT-002')
    assert.ok(finding)
    assert.match(finding.source.name, /readFile/)
    assert.equal(finding.sink.type, 'network')
  } finally {
    rmSync(fixture.root, { recursive: true, force: true })
  }
})

test('same-file array iteration callbacks inherit element taint', async () => {
  const fixture = scanSource([
    "import { exec } from 'node:child_process'",
    tool('    const commands = [args.command]\n    commands.forEach((command) => exec(command))'),
  ].join('\n'))
  try {
    const report = await fixture.run()
    const finding = report.findings.find((item) => item.id === 'SEN-AGENT-001')
    assert.ok(finding)
    assert.ok(finding.flow.some((step) => String(step).includes('args.command')))
  } finally {
    rmSync(fixture.root, { recursive: true, force: true })
  }
})

test('same-file object and class methods are followed when the receiver is statically known', async () => {
  const objectFixture = scanSource([
    "import { exec } from 'node:child_process'",
    'const runner = { run(command) { exec(command) }, runFixed(command) { exec("fixed") } }',
    tool('    runner.run(args.command)'),
  ].join('\n'))
  try {
    const report = await objectFixture.run()
    assert.ok(report.findings.some((item) => item.id === 'SEN-AGENT-001'))
  } finally {
    rmSync(objectFixture.root, { recursive: true, force: true })
  }

  const classFixture = scanSource([
    "import { exec } from 'node:child_process'",
    'class Runner { run(command) { exec(command) } runFixed(command) { exec("fixed") } }',
    tool('    const runner = new Runner()\n    runner.run(args.command)'),
  ].join('\n'))
  try {
    const report = await classFixture.run()
    assert.ok(report.findings.some((item) => item.id === 'SEN-AGENT-001'))
  } finally {
    rmSync(classFixture.root, { recursive: true, force: true })
  }
})

test('same-file method and callback negatives do not invent taint', async () => {
  const objectSafe = scanSource([
    "import { exec } from 'node:child_process'",
    'const runner = { runFixed(command) { exec("fixed") } }',
    tool('    runner.runFixed(args.command)'),
  ].join('\n'))
  try {
    const report = await objectSafe.run()
    assert.equal(report.findings.some((item) => item.id === 'SEN-AGENT-001'), false)
  } finally {
    rmSync(objectSafe.root, { recursive: true, force: true })
  }

  const callbackSafe = scanSource([
    "import { readFile } from 'node:fs'",
    tool("    readFile(args.path, (err, data) => fetch('https://example.com/health'))"),
  ].join('\n'))
  try {
    const report = await callbackSafe.run()
    assert.equal(report.findings.some((item) => item.id === 'SEN-TAINT-002'), false)
  } finally {
    rmSync(callbackSafe.root, { recursive: true, force: true })
  }
})
