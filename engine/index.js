/**
 * dsh-sentinel public API — shared by the DSH tool plugin and the CLI.
 *
 * 扫描模式:
 *   source  — GitHub 源码仓库视角:跳过 dist/build/out(默认)
 *   package — npm tarball / 已安装插件视角:必须扫描 dist/build/lib/out(实际执行产物)
 *   profile — 已安装 profile 视角:同 package
 *
 * 完整度契约:findings 上限只限报告保存条数;filesAnalyzed / scanComplete 如实上报;
 * 评分基于全部有效命中(allStats),critical/high 不会因出现晚而丢失。
 */

import { statSync, readdirSync, readFileSync, existsSync, realpathSync } from 'node:fs'
import { join, resolve, dirname, relative, basename, isAbsolute } from 'node:path'
import { homedir } from 'node:os'
import {
  scanTree, applyRule, isMinifiedContent, FindingCollector, mergeStats, emptyAllStats, DEFAULT_LIMITS,
  readMaybe, parsePatchRows, resolvePatchEntry,
} from './scanner.js'
import { inspectBundle } from './manifest.js'
import { buildReport, verdictFor } from './report.js'
import { RULES, CODE_EXT } from './rules.js'
import { semanticScan } from './semantic/index.js'
import { resolveInside } from './path-safety.js'
import { buildModuleGraph } from './semantic/module-graph.js'
import { analyzeCrossFileTaint } from './semantic/cross-file-taint.js'
import { buildDependencyGraph } from './supplychain/dependency-graph.js'
import { buildCapabilityGraph, evaluateCapabilityPolicy } from './semantic/capability-graph.js'
import { runDynamicAnalysis } from './dynamic/orchestrator.js'
import { emptyDynamicLayer, normalizeDynamicLayer } from './dynamic/contracts.js'
import { normalizeDynamicOptions } from './dynamic/policy.js'

export { VERSION } from './version.js'
export { RULES } from './rules.js'
export { parsePatchRows, resolvePatchEntry } from './scanner.js'
export { inspectBundle } from './manifest.js'
export { buildReport, verdictFor } from './report.js'
export { semanticScan } from './semantic/index.js'
export { buildCapabilityGraph, evaluateCapabilityPolicy } from './semantic/capability-graph.js'
export { auditPackageBeforeInstall, auditNpmSpec, auditVerdictFor } from './package/audit.js'
export { loadConfig, mergeOverrides, DEFAULT_CONFIG } from './config.js'

/** Resolve the DeepSeek Harness home: $DSH_HOME, else ~/.dsh (matches dsh). */
export function resolveDshHome(env = process.env) {
  const fromEnv = env.DSH_HOME
  const home = fromEnv !== undefined && fromEnv.trim().length > 0 ? fromEnv : join(homedir(), '.dsh')
  return resolve(home)
}

/** Nearest ancestor (≤3 levels) carrying package.json, else the target itself. */
function findBundleRoot(target) {
  let dir = target
  for (let i = 0; i < 3; i += 1) {
    if (existsSync(join(dir, 'package.json'))) return dir
    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return target
}

/**
 * 计算"运行期可达"文件集合(相对 bundleRoot):
 * package.json 的 main / exports / bin / dsh.bundle.patch 解析出的入口文件。
 * 用于 test 文件降权:被这些入口可达的 test 文件不得降权(§13)。
 * 所有 manifest 派生路径(patch/main/exports/bin)一律先做 containment:
 * 逃逸/穿越 symlink/不存在(patch mustExist)时跳过,绝不读取 root 外文件。
 */
export function computeRuntimeEntries(bundleRoot) {
  const out = new Set()
  const pkg = readJsonSafe(join(bundleRoot, 'package.json'))
  if (!pkg) return out
  const add = (rel) => {
    if (typeof rel !== 'string' || rel.length === 0) return
    try {
      const abs = resolveInside(bundleRoot, rel)
      out.add(relative(bundleRoot, abs).replace(/\\/g, '/'))
    } catch {
      // manifest 负责 finding(SEN-MAN-009);入口不加入
    }
  }
  if (typeof pkg.main === 'string') add(pkg.main)
  if (pkg.exports && typeof pkg.exports === 'object' && !Array.isArray(pkg.exports)) {
    for (const v of Object.values(pkg.exports)) {
      const target = typeof v === 'string' ? v : v?.default
      if (typeof target === 'string' && target.startsWith('.')) add(target)
    }
  }
  if (pkg.bin) {
    const bins = typeof pkg.bin === 'string' ? { [pkg.name ?? 'bin']: pkg.bin } : pkg.bin
    for (const v of Object.values(bins ?? {})) if (typeof v === 'string') add(v)
  }
  if (pkg.dsh?.bundle?.patch && typeof pkg.dsh.bundle.patch === 'string') {
    let patchPath
    try {
      patchPath = resolveInside(bundleRoot, pkg.dsh.bundle.patch, { mustExist: true })
    } catch {
      return out // patch 逃逸/缺失:manifest 负责 finding,绝不读取 root 外文件
    }
    const rows = parsePatchRows(readMaybe(patchPath) ?? '')
    for (const row of rows) {
      if (!row.name || row.name.startsWith('cordis:') || row.name.startsWith('@deepseek-ai/')) continue
      try {
        const entry = resolvePatchEntry(bundleRoot, row.name, pkg.name ?? '')
        if (entry) add(relative(bundleRoot, entry))
      } catch {
        // 逃逸/解析失败由 manifest 检查报告
      }
    }
  }
  return out
}

/**
 * Resolve the dynamic runner's entrypoints without changing static reachability
 * semantics. Every manifest or patch entry must be an existing regular file
 * contained by the scanned directory; one unresolved entry refuses the run.
 */
function deriveDynamicDirectoryEntrypoints(scanRoot, bundleRoot) {
  const out = new Set()
  const pkg = readJsonSafe(join(bundleRoot, 'package.json'))
  if (!pkg) return []
  let unresolved = false
  const add = (rel) => {
    if (typeof rel !== 'string' || rel.length === 0) return
    try {
      const entry = resolveInside(bundleRoot, rel, { mustExist: true })
      const scoped = relative(scanRoot, entry)
      if (scoped.startsWith('..') || isAbsolute(scoped) || !statSync(entry).isFile()) throw new Error('entrypoint outside scan scope')
      out.add(entry)
    } catch {
      unresolved = true
    }
  }
  if (typeof pkg.main === 'string') add(pkg.main)
  if (pkg.exports && typeof pkg.exports === 'object' && !Array.isArray(pkg.exports)) {
    for (const value of Object.values(pkg.exports)) {
      const target = typeof value === 'string' ? value : value?.default
      if (typeof target === 'string' && target.startsWith('.')) add(target)
    }
  }
  if (pkg.bin) {
    const bins = typeof pkg.bin === 'string' ? { [pkg.name ?? 'bin']: pkg.bin } : pkg.bin
    for (const value of Object.values(bins ?? {})) if (typeof value === 'string') add(value)
  }
  if (pkg.dsh?.bundle?.patch && typeof pkg.dsh.bundle.patch === 'string') {
    let patchPath
    try {
      patchPath = resolveInside(bundleRoot, pkg.dsh.bundle.patch, { mustExist: true })
    } catch {
      unresolved = true
    }
    if (patchPath) {
      for (const row of parsePatchRows(readMaybe(patchPath) ?? '')) {
        if (!row.name || row.name.startsWith('cordis:') || row.name.startsWith('@deepseek-ai/')) continue
        try {
          const entry = resolvePatchEntry(bundleRoot, row.name, pkg.name ?? '')
          if (!entry) throw new Error('entrypoint unresolved')
          add(relative(bundleRoot, entry))
        } catch {
          unresolved = true
        }
      }
    }
  }
  return unresolved ? [] : [...out]
}

function deriveDynamicSingleFileEntrypoint(target) {
  try {
    const entry = resolveInside(dirname(target), basename(target), { mustExist: true })
    return statSync(entry).isFile() ? [target] : []
  } catch {
    return []
  }
}

/**
 * Scan a directory or a single file for security & health issues.
 * @param {string} target - path to a plugin repo/directory (or a file).
 * @param {object} opts - {mode, maxFiles, maxBytesPerFile, maxFindings, ignore, includeBuildArtifacts}
 * @returns {Promise<object>} canonical report
 */
export async function scan(target, opts = {}) {
  const started = Date.now()
  const abs = resolve(target)
  const limits = { ...DEFAULT_LIMITS, ...opts }
  let findings = []
  let findingsTotal = 0
  let filesAnalyzed = 0
  let filesDiscovered = 0
  let scanComplete = true
  let scanCoverage = { sourceFiles: 0, buildFiles: 0, binaryFiles: 0, largeFiles: 0, parseFailures: 0, hardSkippedFiles: 0 }
  let filesSkipped = { binary: 0, big: 0, dirs: 0, ignored: 0 }
  let languages = {}
  let largestFiles = []
  let manifest = { ok: false, name: '', version: '', isBundle: false, patch: '', license: '', description: '' }
  let allStats = emptyAllStats()
  let ignored = []
  let hardSkipped = []
  let analysisLayers = { moduleGraph: { nodes: [], edges: [], unresolved: [], failures: [], complete: true } }
  let attackChains = []
  let coverageSkips = []
  let dependencyGraph = null
  let runtimeEntrypoints = []
  const targetIsFile = existsSync(abs) && statSync(abs).isFile()

  if (targetIsFile) {
    runtimeEntrypoints = deriveDynamicSingleFileEntrypoint(abs)
    const size = statSync(abs).size
    // 单文件超过 hardMax:只做 metadata 记录并强制 incomplete(绝不 silent skip)。
    if (size > limits.hardMaxBytesPerFile) {
      const { hardSkippedMetadata } = await import('./scanner.js')
      const meta = await hardSkippedMetadata(abs, size)
      meta.path = target
      scanComplete = false
      filesDiscovered = 1
      scanCoverage.hardSkippedFiles = 1
      filesSkipped.big = 1
      hardSkipped = [meta]
    } else {
      const content = readFileSync(abs, 'utf8')
      const collector = new FindingCollector({ maxFindings: limits.maxFindings })
      const minified = isMinifiedContent(content)
      const tagMinified = (list) => {
        for (const f of list) {
          f.bundleFile = true
          f.analysisMode = 'minified'
        }
      }
      for (const rule of RULES) {
        if (rule.category === 'manifest' || rule.category === 'hygiene') continue
        if (rule.category === 'agent' || rule.category === 'taint') continue
        const r = applyRule(rule, target, content)
        findingsTotal += r.total
        if (minified) tagMinified(r.findings)
        collector.addRuleHits(rule, r.total, r.findings, target)
      }
      if (CODE_EXT.test(target)) {
        const sem = semanticScan(content, target)
        findingsTotal += sem.length
        if (minified) tagMinified(sem)
        collector.addSemantic(sem, target)
      }
      collector.finalizeFile(target)
      // 直接扫描 package.json 时,顺带对其所在目录做完整 manifest 体检。
      if (basename(abs) === 'package.json') {
        const bundle = inspectBundle(dirname(abs))
        collector.addSemantic(bundle.findings, 'package.json')
        collector.finalizeFile('package.json')
        findingsTotal += bundle.findings.length
        manifest = bundle.manifest
      }
      findings = collector.findings()
      allStats = collector.stats()
      const moduleGraph = CODE_EXT.test(target)
        ? buildModuleGraph(dirname(abs), [basename(abs)])
        : { nodes: [], edges: [], unresolved: [], failures: [], complete: true }
      filesAnalyzed = 1
      filesDiscovered = 1
      largestFiles = [{ file: target, bytes: content.length }]
      const ext = target.includes('.') ? target.slice(target.lastIndexOf('.') + 1) : 'text'
      languages = { [ext]: 1 }
      analysisLayers = { moduleGraph }
    }
  } else {
    // Manifest 检查先行:得到 runtime entries,用于 test 文件降权的 reachability 判断。
    const bundleRoot = findBundleRoot(abs)
    const bundle = inspectBundle(bundleRoot)
    const runtimeEntries = computeRuntimeEntries(bundleRoot)
    runtimeEntrypoints = deriveDynamicDirectoryEntrypoints(abs, bundleRoot)
    const testReachableFiles = new Set()
    for (const rel of runtimeEntries) {
      const relToTarget = relative(abs, join(bundleRoot, rel)).replace(/\\/g, '/')
      if (!relToTarget.startsWith('..') && !isAbsolute(relToTarget)) testReachableFiles.add(relToTarget)
    }
    const tree = await scanTree(abs, { ...limits, mode: opts.mode ?? 'source', testReachableFiles })
    findings = tree.findings
    findingsTotal = tree.findingsTotal
    allStats = tree.allStats
    filesAnalyzed = tree.filesAnalyzed
    filesDiscovered = tree.filesDiscovered
    scanComplete = tree.scanComplete
    scanCoverage = tree.scanCoverage
    filesSkipped = tree.filesSkipped
    languages = tree.languages
    largestFiles = tree.largestFiles
    ignored = tree.ignored
    hardSkipped = tree.hardSkipped
    const crossFile = analyzeCrossFileTaint(abs, tree.moduleGraph)
    const lockfileNames = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'bun.lockb']
    const hasLockfile = lockfileNames.some((name) => existsSync(join(abs, name)))
    dependencyGraph = hasLockfile ? buildDependencyGraph(abs) : null
    const crossCollector = new FindingCollector({ maxFindings: limits.maxFindings, testReachableFiles })
    crossCollector.addSemantic(crossFile.findings, 'cross-file')
    crossCollector.finalizeFile('cross-file')
    findings = [...findings, ...crossCollector.findings()]
    findingsTotal += crossFile.findings.length
    allStats = mergeStats(allStats, crossCollector.stats())
    attackChains = crossFile.attackChains
    coverageSkips = [...(tree.coverageSkips ?? []), ...crossFile.failures]
    // 模块图失败(JS 跨文件分析不完整)参与 scanComplete;
    // 依赖图解析失败(pnpm/yarn lockfile 复杂格式)只是辅助层降级,不判扫描不完整。
    scanComplete = scanComplete && crossFile.complete
    analysisLayers = {
      moduleGraph: { ...tree.moduleGraph, crossFile },
      ...(dependencyGraph ? { dependencyGraph } : {}),
    }
    // Manifest findings 并入统计与缓冲(路径 remap 到相对 target)。
    const bundleCollector = new FindingCollector({ maxFindings: limits.maxFindings, testReachableFiles })
    const remapped = bundle.findings.map((f) => ({ ...f, file: relative(abs, join(bundleRoot, f.file)) }))
    bundleCollector.addSemantic(remapped, 'package.json')
    bundleCollector.finalizeFile('package.json')
    findings = [...findings, ...bundleCollector.findings()]
    findingsTotal += bundle.findings.length
    allStats = mergeStats(allStats, bundleCollector.stats())
    manifest = bundle.manifest
  }

  // Capability graph is derived from retained evidence; an optional policy can
  // add explicit undeclared-capability findings without executing the plugin.
  const capabilityGraph = buildCapabilityGraph(findings)
  if (opts.capabilityPolicy && typeof opts.capabilityPolicy === 'object') {
    const policyFindings = evaluateCapabilityPolicy(capabilityGraph, opts.capabilityPolicy)
    if (policyFindings.length > 0) {
      const policyCollector = new FindingCollector({ maxFindings: limits.maxFindings })
      policyCollector.addSemantic(policyFindings, 'capability-policy')
      policyCollector.finalizeFile('capability-policy')
      findings = [...findings, ...policyCollector.findings()]
      findingsTotal += policyFindings.length
      allStats = mergeStats(allStats, policyCollector.stats())
    }
  }
  analysisLayers = { ...analysisLayers, capabilityGraph }

  // Phase A dynamic analysis is strictly opt-in and runs only after the
  // complete static verdict, its runtime entries, and explicit high-risk
  // blockers are known. Evidence remains in its dedicated layer.
  const dynamicBlockers = findings
    .filter((finding) => finding.severity === 'critical' || finding.severity === 'high')
    .map((finding) => ({ severity: finding.severity, code: finding.id ?? finding.ruleId }))
  const dynamic = await runDynamicAnalysis({
    target: abs,
    options: opts,
    backend: opts.dynamicBackendAdapter,
    preflight: {
      scanComplete,
      entrypoints: runtimeEntrypoints,
      blockers: dynamicBlockers,
    },
    signal: opts.signal ?? null,
  })
  analysisLayers = { ...analysisLayers, dynamic }

  return buildReport(
    {
      kind: 'path',
      path: abs,
      name: '',
      findings,
      findingsTotal,
      allStats,
      filesAnalyzed,
      filesDiscovered,
      scanComplete,
      scanCoverage,
      manifest,
      filesScanned: filesAnalyzed,
      filesSkipped,
      languages,
      largestFiles,
      ignored,
      hardSkipped,
      pluginsScanned: [],
      pluginsSkipped: [],
      scanMs: Date.now() - started,
      analysisLayers,
      attackChains,
      coverageSkips,
      supplyChain: dependencyGraph ? {
        dependencyGraph: {
          lockfile: dependencyGraph.lockfile,
          nodes: dependencyGraph.nodes.length,
          edges: dependencyGraph.edges.length,
          complete: dependencyGraph.complete,
          buildRequirements: dependencyGraph.buildRequirements ?? [],
        },
      } : {},
    },
    limits.maxFindings,
  )
}

/** 从 node_modules 解析包目录('@scope/pkg' 与 'pkg' 两种形态)。 */
function findModuleDir(modulesDir, name) {
  if (name.startsWith('@')) {
    const [scope, pkg] = name.split('/')
    if (!pkg) return null
    return join(modulesDir, scope, pkg)
  }
  return join(modulesDir, name)
}

/** 是否"看起来是 DSH 插件":有 dsh.bundle 声明 / cordis.patch.yml / plugin 目录。 */
function isDshPluginDir(pkgDir) {
  const pkg = readJsonSafe(join(pkgDir, 'package.json'))
  if (pkg?.dsh?.bundle) return true
  if (existsSync(join(pkgDir, 'cordis.patch.yml'))) return true
  if (existsSync(join(pkgDir, 'plugin'))) return true
  return false
}

/** 从 direct 依赖构建依赖图(深度受限),返回 name → {parent, deps}。 */
function buildDepGraph(modulesDir, roots) {
  const graph = new Map()
  const queue = []
  for (const name of roots) {
    if (!graph.has(name)) {
      graph.set(name, { parent: null, deps: [] })
      queue.push(name)
    }
  }
  let guard = 0
  while (queue.length > 0 && guard < 20000) {
    guard += 1
    const name = queue.shift()
    const pkg = readJsonSafe(join(findModuleDir(modulesDir, name), 'package.json'))
    const deps = Object.keys(pkg?.dependencies ?? {})
    const info = graph.get(name)
    info.deps = deps
    for (const d of deps) {
      if (!graph.has(d)) {
        graph.set(d, { parent: name, deps: [] })
        queue.push(d)
      }
    }
  }
  return graph
}

/**
 * Audit every user-installed third-party plugin in a profile.
 *
 * Discovery(§11):profile package.json direct dependencies → dsh.profile manifest
 * bundles → cordis patch 引用的包 → node_modules 中声明 dsh.bundle 的候选。
 * 依赖图其余节点只做 metadata audit(install/supplychain 规则),不触发
 * SEN-MAN-002 等 manifest 误报。
 * @param {string} profile - profile name (defaults to 'web').
 * @param {object} opts - {maxFiles, maxPlugins, maxFindings, maxBytesPerFile, home}
 * @returns {Promise<object>} canonical report (kind: 'profile')
 */
export async function scanProfile(profile = 'web', opts = {}) {
  const started = Date.now()
  const home = resolveDshHome(opts.env ?? process.env)
  const profileDir = resolve(join(home, 'profiles', profile))
  const modulesDir = join(profileDir, 'node_modules')
  const normalizedDynamicOptions = normalizeDynamicOptions(opts)
  const dynamic = normalizedDynamicOptions.requested
    ? normalizeDynamicLayer({
      status: 'unavailable',
      profile: normalizedDynamicOptions.profile,
      failures: [{ reason: 'backend-unavailable', code: 'profile-dynamic-not-supported' }],
    })
    : emptyDynamicLayer()
  const maxPlugins = opts.maxPlugins ?? 12
  const maxTransitive = opts.maxTransitive ?? 500
  const perPluginMaxFiles = Math.max(200, Math.floor((opts.maxFiles ?? 3000) / Math.max(1, maxPlugins)))
  // 受信 scope:默认 @deepseek-ai;--include-builtins 时也全量扫描。
  const trustedScopes = opts.trustedScopes ?? ['@deepseek-ai']
  const includeBuiltins = opts.includeBuiltins === true
  const isTrustedScope = (name) => trustedScopes.some((s) => name === s || name.startsWith(s + '/'))

  const profilePkg = readJsonSafe(join(profileDir, 'package.json'))
  const profileManifest = profilePkg?.dsh?.profile ?? null
  const directDeps = new Set(Object.keys(profilePkg?.dependencies ?? {}))
  const manifestBundles = new Set(
    (profileManifest?.bundles ?? []).map((b) => (typeof b === 'string' ? b : b?.name)).filter(Boolean),
  )
  // cordis patch 引用的包名(去掉 /entry 子路径)。
  const patchBundleNames = new Set()
  const profilePatch = readMaybe(join(profileDir, 'cordis.patch.yml'))
  if (profilePatch) {
    for (const row of parsePatchRows(profilePatch)) {
      if (!row.name || row.name.startsWith('cordis:')) continue
      const parts = row.name.split('/')
      patchBundleNames.add(parts.length >= 2 ? parts.slice(0, -1).join('/') : parts[0])
    }
  }

  const findings = []
  let findingsTotal = 0
  let allStats = emptyAllStats()
  const pluginsScanned = []
  const pluginsSkipped = []
  const plugins = []
  let filesAnalyzed = 0
  let filesDiscovered = 0
  let scanComplete = true
  const coverage = { sourceFiles: 0, buildFiles: 0, binaryFiles: 0, largeFiles: 0, parseFailures: 0, hardSkippedFiles: 0 }
  const skipped = { binary: 0, big: 0, dirs: 0, ignored: 0 }
  const languages = {}
  const largestFiles = []
  let manifest = { ok: false, name: `dsh-profile-${profile}`, version: '', isBundle: false, patch: '', license: '', description: '' }

  const absorb = (result, prefix, { role, parent } = {}) => {
    pluginsScanned.push(result.name)
    findings.push(...result.findings)
    findingsTotal += result.findingsTotal
    allStats = mergeStats(allStats, result.allStats)
    filesAnalyzed += result.filesAnalyzed
    filesDiscovered += result.filesDiscovered
    scanComplete = scanComplete && result.scanComplete
    skipped.binary += result.skipped.binary
    skipped.big += result.skipped.big
    skipped.dirs += result.skipped.dirs
    skipped.ignored += result.skipped.ignored ?? 0
    coverage.sourceFiles += result.scanCoverage.sourceFiles
    coverage.buildFiles += result.scanCoverage.buildFiles
    coverage.binaryFiles += result.scanCoverage.binaryFiles
    coverage.largeFiles += result.scanCoverage.largeFiles
    coverage.hardSkippedFiles += result.scanCoverage.hardSkippedFiles ?? 0
    for (const [k, v] of Object.entries(result.languages)) languages[k] = (languages[k] ?? 0) + v
    largestFiles.push(...result.largestFiles.map((f) => ({ file: `${prefix}/${f.file}`, bytes: f.bytes })))
    plugins.push({
      name: result.name,
      version: result.version,
      role,
      direct: directDeps.has(result.name),
      transitive: role === 'transitive-dependency',
      parent: parent ?? '',
      dependencies: result.dependencies,
      findings: result.findings.length,
    })
  }

  if (!existsSync(modulesDir)) {
    findings.push({
      ruleId: 'SEN-MAN-001', severity: 'medium', category: 'manifest',
      message: `profile "${profile}" 不存在或没有已安装插件(${modulesDir})`,
      file: 'node_modules', line: 1, snippet: '', recommendation: '先安装插件:dsh plugin --profile <name> add <pkg>',
      package: '',
    })
  } else {
    // ── 1. 组装 full-scan 候选(direct deps + manifest bundles + patch 引用) ──
    const planned = new Map() // name → {dir, source}
    const consider = (name, source) => {
      if (!name || planned.has(name)) return
      if (isTrustedScope(name) && !includeBuiltins) {
        pluginsSkipped.push({ name, reason: 'trusted-scope' })
        return
      }
      if (name === SELF_PACKAGE) {
        pluginsSkipped.push({ name, reason: 'self' })
        return
      }
      const dir = findModuleDir(modulesDir, name)
      if (!dir || !existsSync(dir)) {
        pluginsSkipped.push({ name, reason: 'not-installed' })
        return
      }
      planned.set(name, { dir, source })
    }
    for (const name of directDeps) consider(name, 'direct')
    for (const name of manifestBundles) consider(name, 'bundle')
    for (const name of patchBundleNames) consider(name, 'patch')

    // ── 2. 回退发现:node_modules 中声明 dsh.bundle 的包(未在上面的) ──
    let unrelatedCount = 0
    const unrelatedNames = []
    for (const entry of readdirSync(modulesDir, { withFileTypes: true })) {
      const names = []
      if (entry.name.startsWith('@') && entry.isDirectory()) {
        const scopeDir = join(modulesDir, entry.name)
        for (const sub of readdirSync(scopeDir, { withFileTypes: true })) {
          if (sub.isDirectory()) names.push(`${entry.name}/${sub.name}`)
        }
      } else if (entry.isDirectory()) {
        names.push(entry.name)
      }
      for (const name of names) {
        if (planned.has(name)) continue
        if (isTrustedScope(name) && !includeBuiltins) {
          pluginsSkipped.push({ name, reason: 'trusted-scope' })
          continue
        }
        if (name === SELF_PACKAGE) {
          pluginsSkipped.push({ name, reason: 'self' })
          continue
        }
        const dir = findModuleDir(modulesDir, name)
        if (!dir || !existsSync(dir)) continue
        if (isDshPluginDir(dir)) planned.set(name, { dir, source: 'discovered' })
        else {
          unrelatedCount += 1
          if (unrelatedNames.length < 20) unrelatedNames.push(name)
        }
      }
    }
    if (unrelatedCount > 0) {
      pluginsSkipped.push({
        name: unrelatedNames.length > 0
          ? `${unrelatedNames.join(', ')}(+${unrelatedCount - unrelatedNames.length} more)`
          : `${unrelatedCount} unrelated packages`,
        reason: 'not-a-dsh-plugin',
      })
    }

    // ── 3. maxPlugins 只截断 full-scan;截断必须标记 incomplete(P0-7) ──
    const plannedList = [...planned.values()].map((p, i) => ({ name: [...planned.keys()][i], ...p }))
    const plannedNames = new Set(plannedList.map((p) => p.name))
    if (plannedList.length > maxPlugins) {
      for (const p of plannedList.slice(maxPlugins)) {
        pluginsSkipped.push({ name: p.name, reason: 'maxPlugins-limit' })
      }
      scanComplete = false
    }

    // ── 4. 依赖图(transitive 判定 + metadata audit 名单) ──
    const graph = buildDepGraph(modulesDir, [...directDeps, ...manifestBundles])

    for (const p of plannedList.slice(0, maxPlugins)) {
      const result = await scanOnePlugin(p.dir, perPluginMaxFiles, opts, { full: true })
      if (result === null) continue
      const role = p.source === 'direct' && !isDshPluginDir(p.dir) ? 'direct-dependency' : 'direct-plugin'
      absorb(result, `node_modules/${p.name}`, { role })
    }

    // ── 5. transitive 依赖:metadata audit(不跑 manifest 规则,避免误报) ──
    const transitiveList = [...graph.keys()].filter((name) => !plannedNames.has(name))
      .filter((name) => !(isTrustedScope(name) && !includeBuiltins) && name !== SELF_PACKAGE)
    for (let i = 0; i < transitiveList.length; i += 1) {
      if (i >= maxTransitive) {
        pluginsSkipped.push({ name: `transitive deps beyond ${maxTransitive}`, reason: 'maxTransitive-limit' })
        scanComplete = false
        break
      }
      const name = transitiveList[i]
      const dir = findModuleDir(modulesDir, name)
      if (!dir || !existsSync(dir)) continue
      const result = await scanOnePlugin(dir, perPluginMaxFiles, opts, { full: false })
      if (result === null) continue
      absorb(result, `node_modules/${name}`, { role: 'transitive-dependency', parent: graph.get(name)?.parent ?? '' })
    }
  }

  // direct/transitive 兼容标注:被其他已扫插件依赖且非 direct 的视为 transitive。
  for (const p of plugins) {
    if (p.direct || p.role === 'transitive-dependency') continue
    p.transitive = plugins.some((q) => q !== p && (q.role === 'direct-plugin' || q.role === 'direct-dependency') && q.dependencies > 0)
  }

  largestFiles.sort((a, b) => b.bytes - a.bytes)
  manifest = {
    ...manifest,
    ok: true,
    profile: profileManifest,
  }

  const policySkips = pluginsSkipped.filter((s) => ['trusted-scope', 'self', 'not-a-dsh-plugin'].includes(s.reason))
  const coverageSkips = pluginsSkipped.filter((s) => ['maxPlugins-limit', 'maxTransitive-limit', 'not-installed', 'error'].includes(s.reason))

  return buildReport(
    {
      kind: 'profile',
      path: modulesDir,
      name: profile,
      findings,
      findingsTotal,
      allStats,
      filesAnalyzed,
      filesDiscovered,
      scanComplete,
      scanCoverage: coverage,
      manifest,
      filesScanned: filesAnalyzed,
      filesSkipped: skipped,
      languages,
      largestFiles: largestFiles.slice(0, 5),
      pluginsScanned,
      pluginsSkipped,
      plugins,
      policySkips,
      coverageSkips,
      scanMs: Date.now() - started,
      ...(normalizedDynamicOptions.requested ? { analysisLayers: { dynamic } } : {}),
    },
    opts.maxFindings,
  )
}

function readJsonSafe(absPath) {
  try {
    return JSON.parse(readFileSync(absPath, 'utf8'))
  } catch {
    return null
  }
}

/** 扫描器自身的包名:profile 审计时排除自己(审计者不出现在被审计名单里)。 */
export const SELF_PACKAGE = 'deepseek-harness-sentinel'

/**
 * 扫描单个已安装插件(package mode)。
 * full=true  :完整扫描(scanTree + manifest 规则),用于真正 DSH 插件
 * full=false :metadata audit(仅 install/supplychain 规则),用于 transitive 依赖——
 *              普通依赖不产生 SEN-MAN-002 等 manifest 误报(§11.3)
 */
async function scanOnePlugin(pkgDir, maxFiles, opts, { full = true } = {}) {
  let realDir = pkgDir
  try {
    realDir = realpathSync(pkgDir)
  } catch {
    return null
  }
  const pkg = readJsonSafe(join(realDir, 'package.json'))
  const name = pkg?.name ?? ''
  if (!name) return null
  // 排除扫描器自身:规则库的字面量会自指命中,审计自己的规则集没有意义。
  if (name === SELF_PACKAGE) return { name, self: true }

  if (!full) {
    // metadata audit:只对 package.json 跑 install / supplychain 规则。
    const pkgText = readMaybe(join(realDir, 'package.json')) ?? ''
    const findings = []
    let findingsTotal = 0
    for (const rule of RULES) {
      if (rule.category !== 'install' && rule.category !== 'supplychain') continue
      const r = applyRule(rule, 'package.json', pkgText)
      findingsTotal += r.total
      findings.push(...r.findings.map((f) => ({ ...f, package: name })))
    }
    return {
      name,
      version: String(pkg.version ?? ''),
      dependencies: Object.keys(pkg.dependencies ?? {}).length,
      dependenciesOf: pkg.dependencies ?? {},
      findings,
      findingsTotal,
      allStats: emptyAllStats(),
      filesAnalyzed: 1,
      filesDiscovered: 1,
      scanComplete: true,
      scanCoverage: { sourceFiles: 0, buildFiles: 0, binaryFiles: 0, largeFiles: 0, parseFailures: 0, hardSkippedFiles: 0 },
      skipped: { binary: 0, big: 0, dirs: 0, ignored: 0 },
      languages: { json: 1 },
      largestFiles: [],
    }
  }

  // package mode:dist/build/lib/out 等实际执行产物必须扫描。
  const tree = await scanTree(realDir, {
    maxFiles,
    maxBytesPerFile: opts.maxBytesPerFile,
    maxFindings: opts.maxFindings,
    mode: 'package',
  })
  const isPlugin = isDshPluginDir(realDir)
  const bundle = isPlugin
    ? inspectBundle(realDir)
    : { findings: [], manifest: { ok: false, name, version: String(pkg.version ?? ''), isBundle: false, patch: '', license: pkg.license ?? '', description: pkg.description ?? '' } }
  const collector = new FindingCollector({ maxFindings: opts.maxFindings ?? 300 })
  collector.addSemantic(bundle.findings.map((f) => ({ ...f, package: name })), 'package.json')
  collector.finalizeFile('package.json')
  return {
    name,
    version: String(pkg.version ?? ''),
    dependencies: Object.keys(pkg.dependencies ?? {}).length,
    dependenciesOf: pkg.dependencies ?? {},
    findings: [...tree.findings.map((f) => ({ ...f, package: name })), ...collector.findings()],
    findingsTotal: tree.findingsTotal + bundle.findings.length,
    allStats: mergeStats(tree.allStats, collector.stats()),
    filesAnalyzed: tree.filesAnalyzed,
    filesDiscovered: tree.filesDiscovered,
    scanComplete: tree.scanComplete,
    scanCoverage: tree.scanCoverage,
    skipped: tree.filesSkipped,
    languages: tree.languages,
    largestFiles: tree.largestFiles,
  }
}
