/**
 * File walking + rule matching + semantic pass.
 *
 * The scanner is read-only: it never executes plugin code, never follows
 * directory symlinks, and treats every manifest-derived path as untrusted
 * (path containment, see engine/path-safety.js).
 *
 * Completeness contract (安全工具的红线):
 *   - findings 上限只限制"报告保存条数"(findingsReturned),绝不提前停止分析
 *   - 每个文件的每条规则命中都会被计数(findingsTotal)并进入 allStats(评分依据)
 *   - 大文件不跳过:走 large-file-lite 分析并标记 analysisMode
 *   - 超过 hardMaxBytesPerFile 的文件绝不 silent skip:记录 metadata
 *     (path/size/sha256/extension/分类/采样信号)并强制 scanComplete=false
 *   - 可执行二进制(.wasm/.exe/.dll/.so/.node…)做 metadata-level audit
 *   - 任何截断/跳过都会在报告中显式体现(scanComplete / filesSkipped /
 *     scanCoverage / ignored / hardSkipped)
 *
 * Scoring contract:
 *   - allStats 基于全部有效命中(与 findingsTotal 一致),与报告展示解耦
 *   - 报告保存采用"优先级有界缓冲"(critical > high > medium > low > info),
 *     critical/high 即使出现在后面也不会因为 cap 丢失
 *   - 同源重叠抑制只影响评分(证据保留)
 */

import { readdirSync, readFileSync, lstatSync, statSync, openSync, readSync, closeSync, createReadStream } from 'node:fs'
import { join, relative, sep, dirname } from 'node:path'
import { createHash } from 'node:crypto'
import { RULES, CODE_EXT, SEVERITY_ORDER, CATEGORIES, severityWeight } from './rules.js'
import { buildModuleGraph } from './semantic/module-graph.js'
import { resolveInside, PathEscapeError } from './path-safety.js'
import { isTestPath, isDevelopmentPath, scoredSeverity, OVERLAP_SUPPRESSION } from './report.js'
import { semanticScan } from './semantic/index.js'
import { auditBinarySample } from './binary/inspect.js'

export const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp', '.avif', '.tiff',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.pdf', '.zip', '.gz', '.tgz', '.tar', '.7z', '.rar',
  '.mp3', '.mp4', '.mov', '.avi', '.mkv', '.webm', '.wav', '.flac',
  '.db', '.sqlite', '.sqlite3', '.lockb',
])

/** 可执行/原生二进制:不做整体跳过,走 metadata-level audit(SEN-BIN-*)。 */
export const EXEC_BINARY_EXTENSIONS = new Set([
  '.wasm', '.exe', '.dll', '.so', '.dylib', '.node', '.o', '.a', '.obj',
  '.class', '.pyc', '.pyd', '.jar', '.bin', '.msi', '.dmg', '.apk', '.deb', '.rpm', '.ko',
])

/** source mode 跳过的目录(GitHub 源码仓库视角)。 */
export const SKIP_DIRECTORIES = new Set([
  '.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.nuxt',
  '.svelte-kit', '__pycache__', '.venv', 'venv', 'vendor', '.pytest_cache',
  '.turbo', '.cache', '.idea', '.vscode', 'target', 'out', 'scratch',
])

/** package/profile mode 仍跳过的目录:实际执行产物(dist/build/lib/out/bundle)必须扫描。 */
export const SKIP_PACKAGE_DIRECTORIES = new Set([
  '.git', 'node_modules', 'coverage', '__pycache__', '.venv', 'venv',
  '.pytest_cache', '.cache', '.idea', '.vscode', 'scratch',
])

export const DEFAULT_LIMITS = Object.freeze({
  maxFiles: 3000,
  maxBytesPerFile: 512 * 1024,
  hardMaxBytesPerFile: 20 * 1024 * 1024, // 超过此值连 lite 都不做:记录 metadata 并强制 incomplete
  maxFindings: 300,
  binaryMaxFiles: 500, // 可执行二进制审计数量上限,超出 → incomplete
})

/** 目录路径是否属于构建产物(dist/build/out/bundle)。 */
export function isBuildPath(relPath) {
  return /(^|[\\/])(?:dist|build|out|bundle)([\\/]|$)/i.test(relPath)
}

/**
 * 压缩/打包产物启发式:存在超长单行(>3000 字符)。
 * bundleFile/minified 只作为 evidence/context 标记,绝不自动改变 severity
 * (见 engine/report.js 的 confidence 模型)。
 */
export function isMinifiedContent(content) {
  let start = 0
  const max = Math.min(content.length, 2 * 1024 * 1024)
  for (let i = 0; i < max; i += 1) {
    if (content.charCodeAt(i) === 10) {
      if (i - start > 3000) return true
      start = i + 1
    }
  }
  return content.length - start > 3000
}

/** Does this relative path look like a (non-executable) binary we should skip? */
export function isBinaryPath(relPath) {
  const lower = relPath.toLowerCase()
  return BINARY_EXTENSIONS.has(extOf(lower))
}

/** Does this relative path look like an executable/native binary to audit? */
export function isExecBinaryPath(relPath) {
  const lower = relPath.toLowerCase()
  return EXEC_BINARY_EXTENSIONS.has(extOf(lower))
}

function extOf(name) {
  const i = name.lastIndexOf('.')
  return i < 0 ? '' : name.slice(i)
}

/** Extract the first line number containing `index` (0-based char offset). */
function lineOf(content, index) {
  let line = 1
  for (let i = 0; i < index && i < content.length; i += 1) {
    if (content.charCodeAt(i) === 10) line += 1
  }
  return line
}

/** Trim a snippet to a readable window around the match. */
function makeSnippet(lineText, max = 240) {
  const t = lineText.replace(/\s+/g, ' ').trim()
  if (t.length <= max) return t
  return t.slice(0, max - 1) + '…'
}

/** 简单 glob → RegExp(双星任意深度、单星单段、问号单字符)。 */
export function globToRegExp(pattern) {
  const normalized = String(pattern).replace(/\\/g, '/')
  let out = ''
  let i = 0
  while (i < normalized.length) {
    const ch = normalized[i]
    if (ch === '*') {
      if (normalized[i + 1] === '*') {
        out += '.*'
        i += 2
        if (normalized[i] === '/') {
          out += '/?'
          i += 1
        }
        continue
      }
      out += '[^/]*'
      i += 1
      continue
    }
    if (ch === '?') {
      out += '[^/]'
      i += 1
      continue
    }
    out += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&')
    i += 1
  }
  return new RegExp(`^${out}$`)
}

/**
 * Recursively collect files under root, applying mode-dependent skip rules.
 * 大文件(> maxBytesPerFile,<= hardMaxBytesPerFile)单独收集,后续走 lite 分析;
 * 超过 hardMaxBytesPerFile 的文件收集进 hardSkipped(绝不 silent skip);
 * 可执行二进制收集进 binaries(metadata audit)。
 * @returns {{ files: Array, largeFiles: Array, binaries: Array, hardSkipped: Array,
 *             skipped: {binary, big, dirs, ignored}, ignored: Array, truncated: boolean,
 *             traversalFailures: Array<{path, stage: 'walk'|'stat', reason}> }}
 */
export function collectFiles(root, {
  maxFiles = DEFAULT_LIMITS.maxFiles,
  maxBytesPerFile = DEFAULT_LIMITS.maxBytesPerFile,
  hardMaxBytesPerFile = DEFAULT_LIMITS.hardMaxBytesPerFile,
  mode = 'source',
  includeBuildArtifacts = false,
  ignore = [],
  __io = {},
} = {}) {
  const readdir = __io.readdir ?? readdirSync
  const lstat = __io.lstat ?? lstatSync
  let skipDirs = mode === 'source' ? SKIP_DIRECTORIES : SKIP_PACKAGE_DIRECTORIES
  if (mode === 'source' && includeBuildArtifacts) skipDirs = SKIP_PACKAGE_DIRECTORIES
  const ignoreRules = (ignore ?? []).map((pattern) => ({ pattern: String(pattern), re: globToRegExp(String(pattern)) }))
  const ignoredCounts = new Map() // pattern → 匹配条目数 + 被剪枝目录数
  const entries = []
  const binaries = []
  const hardSkipped = []
  const traversalFailures = []
  const skipped = { binary: 0, big: 0, dirs: 0, ignored: 0 }
  let truncated = false

  const isIgnored = (relPath, kind = 'file') => {
    const norm = relPath.replace(/\\/g, '/')
    for (const rule of ignoreRules) {
      if (rule.re.test(norm)) {
        const current = ignoredCounts.get(rule.pattern) ?? { count: 0, directories: 0 }
        current.count += 1
        if (kind === 'directory') current.directories += 1
        ignoredCounts.set(rule.pattern, current)
        return true
      }
    }
    return false
  }

  const walk = (dir, relPrefix = '') => {
    if (entries.length >= maxFiles) {
      truncated = true
      return
    }
    let dirEntries
    try {
      dirEntries = readdir(dir, { withFileTypes: true })
    } catch (e) {
      traversalFailures.push({ path: relPrefix || dir, stage: 'walk', reason: e.code ?? e.message })
      return
    }
    for (const entry of dirEntries) {
      if (entries.length >= maxFiles) {
        truncated = true
        return
      }
      const abs = join(dir, entry.name)
      const rel = relPrefix ? `${relPrefix}/${entry.name}` : entry.name
      let stat
      try {
        stat = lstat(abs)
      } catch (e) {
        traversalFailures.push({ path: rel, stage: 'stat', reason: e.code ?? e.message })
        continue
      }
      if (stat.isSymbolicLink()) continue // never follow symlinks
      if (stat.isDirectory()) {
        if (skipDirs.has(entry.name)) {
          skipped.dirs += 1
          continue
        }
        if (ignoreRules.length > 0 && isIgnored(rel + '/', 'directory')) {
          skipped.ignored += 1
          continue
        }
        walk(abs, rel)
        continue
      }
      if (!stat.isFile()) continue
      if (ignoreRules.length > 0 && isIgnored(rel)) {
        skipped.ignored += 1
        continue
      }
      // 可执行/原生二进制:收集进审计列表(metadata-level audit),绝不整体跳过
      if (isExecBinaryPath(rel)) {
        binaries.push({ abs, rel, size: stat.size })
        continue
      }
      if (isBinaryPath(rel)) {
        skipped.binary += 1
        continue
      }
      if (stat.size > hardMaxBytesPerFile) {
        skipped.big += 1
        hardSkipped.push({ abs, rel, size: stat.size })
        continue
      }
      entries.push({ abs, rel, size: stat.size })
    }
  }
  walk(root)
  const files = []
  const largeFiles = []
  for (const e of entries) {
    if (e.size > maxBytesPerFile) largeFiles.push(e)
    else files.push(e)
  }
  // Ignore directories are intentionally not traversed. `count` therefore means matched
  // entries, while `directories` explicitly discloses how many directory trees were pruned.
  const ignored = [...ignoredCounts].map(([pattern, stats]) => ({ pattern, ...stats }))
  return { files, largeFiles, binaries, hardSkipped, skipped, ignored, truncated, traversalFailures }
}

/**
 * Apply one rule to one file.
 * 完整度契约:total 计所有独立命中(按行去重,exclude/comment 不计入),
 * findings 只存前 10 条(防刷屏),绝不因单规则命中多而丢失全量计数。
 * 正确顺序:seenLines 去重 → excludes → ignoreComments → total+1 → 保存。
 * @returns {{ findings: Array, total: number }}
 */
export function applyRule(rule, relPath, content) {
  if (rule.filePattern && !rule.filePattern.test(relPath)) return { findings: [], total: 0 }

  const findings = []
  const seenLines = new Set()
  let total = 0
  const lines = content.split('\n') // 每文件预计算一次,避免每条命中重复 split(性能)
  const isCommentLine = (lineText) => /^\s*(\/\/|\*|\/\*)/.test(lineText)
  const push = (line, note) => {
    if (seenLines.has(line)) return
    const lineText = lines[line - 1] ?? ''
    // Rule-level exclusions: known-safe idioms on the same line.
    if (rule.excludes?.some((re) => re.test(lineText))) return
    // Comment lines carry prose/JSDoc, not executable code.
    if (rule.ignoreComments && isCommentLine(lineText)) return
    seenLines.add(line)
    total += 1
    if (findings.length >= 10) return // 存储上限,计数已保留
    findings.push({
      ruleId: rule.id,
      severity: rule.severity,
      category: rule.category,
      message: rule.message + (note ? `(${note})` : ''),
      file: relPath,
      line,
      snippet: makeSnippet(lineText),
      recommendation: rule.recommendation ?? '',
    })
  }

  for (const p of rule.linePatterns ?? []) {
    if (p.needsImport) {
      const impRe = new RegExp(`(?:require|import)[^;\\n]{0,80}['"][^'"]{0,40}${p.needsImport}['"]`)
      if (!impRe.test(content)) continue
    }
    const re = new RegExp(p.re.source, p.re.flags.includes('g') ? p.re.flags : p.re.flags + 'g')
    let m
    let guard = 0
    while ((m = re.exec(content)) !== null && guard < 200) {
      guard += 1
      push(lineOf(content, m.index), p.note)
      if (m.index === re.lastIndex) re.lastIndex += 1
    }
  }

  for (const p of rule.contentPatterns ?? []) {
    p.re.lastIndex = 0 // 防跨文件 lastIndex 状态污染(RegExp state bug)
    const m = p.re.exec(content)
    if (m !== null) push(lineOf(content, m.index), p.note)
  }

  return { findings, total }
}

/** 大文件 lite 分析使用的规则子集(廉价行模式)。 */
const LITE_RULE_IDS = new Set(['SEN-OBF-002', 'SEN-EXEC-003', 'SEN-EXEC-002', 'SEN-NET-001', 'SEN-CRED-003', 'SEN-OBF-001'])

/**
 * 大文件(512KB–20MB)lite 分析:复用规则子集 + 文件 hash,标记 analysisMode。
 * @returns {{ findings: Array, total: number, hits: Array<{rule, total, findings}> }}
 */
export function analyzeLargeFileLite(content, relPath, { hash, bytes }) {
  const findings = []
  const hits = []
  let total = 0
  for (const rule of RULES) {
    if (!LITE_RULE_IDS.has(rule.id)) continue
    const r = applyRule(rule, relPath, content)
    total += r.total
    for (const f of r.findings) {
      f.analysisMode = 'large-file-lite'
      f.fileHash = hash
      f.fileBytes = bytes
      findings.push(f)
    }
    if (r.total > 0) hits.push({ rule, total: r.total, findings: r.findings })
  }
  return { findings, total, hits }
}

// ─────────────────────────── 评分统计(P0-1 核心) ───────────────────────────

/**
 * 优先级有界缓冲:始终保留风险最高的 max 条(critical > high > medium > low > info),
 * 而不是最先出现的 max 条。critical/high 即使出现在后面也不会因为 cap 丢失。
 */
const PRIORITY = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

export class FindingBuffer {
  constructor(max) {
    this.max = Math.max(1, Number(max) || 300)
    this.buckets = { critical: [], high: [], medium: [], low: [], info: [] }
    this.count = 0
  }

  add(f) {
    const sev = f.severity ?? 'info'
    const incomingPriority = PRIORITY[sev] ?? 0
    if (this.count < this.max) {
      this.buckets[sev].push(f)
      this.count += 1
      return true
    }
    // 满:只允许更高优先级条目淘汰当前最低非空桶的最早条目;
    // 更低或相同优先级一律拒绝(incoming < lowest → drop;== → 保留最先出现)。
    for (const bucketSev of ['info', 'low', 'medium', 'high', 'critical']) {
      const arr = this.buckets[bucketSev]
      if (arr.length === 0) continue
      const existingPriority = PRIORITY[bucketSev]
      if (incomingPriority < existingPriority) return false
      if (incomingPriority === existingPriority) return false
      arr.shift()
      this.buckets[sev].push(f)
      return true
    }
    return false
  }

  /** 按优先级从高到低输出(报告展示前会再次排序)。 */
  drain() {
    const out = []
    for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
      out.push(...this.buckets[sev])
    }
    return out
  }
}

/** 空的全量统计(评分依据,与报告展示解耦)。 */
export function emptyAllStats() {
  return {
    bySeverity: Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0])),
    byCategory: Object.fromEntries(CATEGORIES.map((c) => [c, 0])),
    byContext: { source: 0, test: 0, development: 0 },
    rawScoreByContext: { source: 0, test: 0, development: 0 },
    findingCount: 0,
    rawScore: 0,
  }
}

/** 同文件同行的 specific 命中 → 标记 generic 命中 suppressedForScore(评分剔除,证据保留)。 */
export function markSuppressed(findings) {
  const specific = new Set()
  for (const f of findings) {
    if (OVERLAP_SUPPRESSION.some((p) => p.specific === f.ruleId)) {
      specific.add(`${f.ruleId}|${f.file}|${f.line ?? 1}|${f.package ?? ''}`)
    }
  }
  if (specific.size === 0) return
  for (const f of findings) {
    if (OVERLAP_SUPPRESSION.some((p) =>
      p.generic === f.ruleId && specific.has(`${p.specific}|${f.file}|${f.line ?? 1}|${f.package ?? ''}`))) {
      f.suppressedForScore = true
    }
  }
}

/**
 * 收集器:全量统计(allStats,评分依据)+ 优先级有界缓冲(展示)。
 * 用法:addRuleHits/addSemantic 累积 → 每文件处理完调用 finalizeFile。
 */
export class FindingCollector {
  constructor({ maxFindings = 300, testReachableFiles = new Set() } = {}) {
    this.buffer = new FindingBuffer(maxFindings)
    this.allStats = emptyAllStats()
    this.testReachableFiles = testReachableFiles instanceof Set ? testReachableFiles : new Set()
    this.staged = []
  }

  /** Runtime-reachable files are source; tests and explicit dev runners use reduced scoring. */
  context(relPath) {
    if (this.testReachableFiles.has(relPath)) return 'source'
    if (isTestPath(relPath)) return 'test'
    if (isDevelopmentPath(relPath)) return 'development'
    return 'source'
  }

  /** 正则规则批量命中:所有命中同 severity/category,total 可能大于保存条数。 */
  addRuleHits(rule, total, saved, relPath) {
    if (total <= 0) return
    this.allStats.bySeverity[rule.severity] += total
    this.allStats.byCategory[rule.category] += total
    const context = this.context(relPath)
    this.allStats.byContext[context] += total
    this.allStats.findingCount += total
    const excess = total - saved.length
    if (excess > 0) {
      const w = scoredSeverity(rule.severity, { context })
      const points = severityWeight(w) * excess
      this.allStats.rawScore += points
      this.allStats.rawScoreByContext[context] += points
    }
    this.staged.push(...saved)
  }

  /** 语义/二进制/manifest finding:逐条统计。 */
  addSemantic(findings, relPath) {
    if (!findings || findings.length === 0) return
    const context = this.context(relPath)
    for (const f of findings) {
      this.allStats.bySeverity[f.severity] = (this.allStats.bySeverity[f.severity] ?? 0) + 1
      this.allStats.byCategory[f.category] = (this.allStats.byCategory[f.category] ?? 0) + 1
      this.allStats.byContext[context] += 1
      this.allStats.findingCount += 1
    }
    this.staged.push(...findings)
  }

  /** 文件处理完毕:重叠抑制标记 + 精确 rawScore + 入缓冲。 */
  finalizeFile(relPath) {
    markSuppressed(this.staged)
    const context = this.context(relPath)
    for (const f of this.staged) {
      if (!f.suppressedForScore) {
        const w = scoredSeverity(f.severity, { context, confidence: f.confidence })
        const points = severityWeight(w)
        this.allStats.rawScore += points
        this.allStats.rawScoreByContext[context] += points
      }
      this.buffer.add(f)
    }
    this.staged = []
  }

  findings() {
    return this.buffer.drain()
  }

  stats() {
    return this.allStats
  }
}

/** 合并两份 allStats(scanTree 结果 + manifest/其他 collector)。 */
export function mergeStats(a, b) {
  const bySeverity = { ...a.bySeverity }
  const byCategory = { ...a.byCategory }
  const byContext = { ...a.byContext }
  const rawScoreByContext = { ...(a.rawScoreByContext ?? { source: a.rawScore ?? 0, test: 0, development: 0 }) }
  for (const [k, v] of Object.entries(b?.bySeverity ?? {})) bySeverity[k] = (bySeverity[k] ?? 0) + v
  for (const [k, v] of Object.entries(b?.byCategory ?? {})) byCategory[k] = (byCategory[k] ?? 0) + v
  for (const [k, v] of Object.entries(b?.byContext ?? {})) byContext[k] = (byContext[k] ?? 0) + v
  const bScoreByContext = b?.rawScoreByContext ?? { source: b?.rawScore ?? 0 }
  for (const [k, v] of Object.entries(bScoreByContext)) rawScoreByContext[k] = (rawScoreByContext[k] ?? 0) + v
  return {
    bySeverity,
    byCategory,
    byContext,
    rawScoreByContext,
    findingCount: a.findingCount + (b?.findingCount ?? 0),
    rawScore: a.rawScore + (b?.rawScore ?? 0),
  }
}

// ─────────────────────────── hard-skip / binary metadata ───────────────────────────

/** 流式 sha256(大文件不整读入内存)。 */
export function hashFileStream(abs) {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256')
    const stream = createReadStream(abs)
    stream.on('data', (chunk) => hash.update(chunk))
    stream.on('end', () => resolve(hash.digest('hex')))
    stream.on('error', reject)
  })
}

/** 读取文件头尾采样(各 ≤ 64KB)。 */
export function sampleHeadTail(abs, size) {
  const fd = openSync(abs, 'r')
  try {
    const headLen = Math.min(size, 65536)
    const head = Buffer.alloc(headLen)
    readSync(fd, head, 0, headLen, 0)
    let tail = null
    if (size > headLen) {
      const tailLen = Math.min(size - headLen, 65536)
      tail = Buffer.alloc(tailLen)
      readSync(fd, tail, 0, tailLen, size - tailLen)
    }
    return { head, tail }
  } finally {
    closeSync(fd)
  }
}

/** 超过 hardMax 的文件:metadata 级记录(绝不 silent skip)。 */
export async function hardSkippedMetadata(abs, size) {
  const { head, tail } = sampleHeadTail(abs, size)
  let classification = 'binary'
  for (let i = 0; i < Math.min(head.length, 4096); i += 1) {
    if (head[i] === 0) {
      classification = 'binary'
      break
    }
    if (i === Math.min(head.length, 4096) - 1) classification = 'text'
  }
  const headText = head.toString('utf8')
  const tailText = tail ? tail.toString('utf8') : ''
  const hints = {
    urls: (headText.match(/https?:\/\/[^\s"'<>]{4,120}/g) ?? []).slice(0, 5),
    execKeywords: /(?:exec|eval|child_process|spawn|curl|wget)/i.test(headText + tailText),
    base64Blob: /[A-Za-z0-9+/]{200,}={0,2}/.test(headText),
    highEntropyEstimate: /[A-Za-z0-9+/]{80,}/.test(headText.slice(0, 4096)),
  }
  const sha256 = await hashFileStream(abs)
  return {
    path: '', // 由调用方填入相对路径
    size,
    sha256,
    extension: extOf(abs) || '',
    classification,
    hints,
  }
}

/** 可执行二进制 audit finding 生成(SEN-BIN-001/002/003、SEN-WASM-001)。 */
export function binaryFindingsFor(meta) {
  const findings = []
  const base = {
    file: meta.rel,
    line: 1,
    snippet: `binary ${meta.rel}(${meta.size} bytes, kind=${meta.kind}, magic=${meta.magic}, entropy=${meta.entropy})`,
    recommendation: '核对二进制来源与构建产物;与源码仓库对比验证,无文档说明的原生代码需人工复核。',
  }
  if (meta.kind === 'wasm') {
    findings.push({
      ruleId: 'SEN-WASM-001', severity: 'info', category: 'binary',
      message: '包含 WebAssembly 模块(wasm module present)',
      ...base,
    })
  } else {
    findings.push({
      ruleId: 'SEN-BIN-001', severity: 'info', category: 'binary',
      message: '携带原生二进制(native binary present)',
      ...base,
    })
  }
  if (meta.entropy > 7.2) {
    findings.push({
      ruleId: 'SEN-BIN-003', severity: 'medium', category: 'binary',
      message: '高熵二进制(疑似压缩/加密/加壳)',
      file: meta.rel, line: 1,
      snippet: `entropy=${meta.entropy}(head sample)`,
      recommendation: '高熵不代表恶意,但加壳二进制难以静态核验,建议与构建产物对比。',
    })
  }
  if (meta.highSignals.length > 0) {
    findings.push({
      ruleId: 'SEN-BIN-002', severity: 'high', category: 'binary',
      message: `二进制内发现可疑字符串(${meta.highSignals.join(', ')})`,
      file: meta.rel, line: 1,
      snippet: `strings: ${meta.highSignals.join(', ')}`,
      recommendation: '原生代码中出现外传端点/凭据标记,需人工确认;无正当理由视为高度可疑。',
    })
  } else if (meta.mediumSignals.length > 0) {
    findings.push({
      ruleId: 'SEN-BIN-002', severity: 'medium', category: 'binary',
      message: `二进制内发现可疑字符串(${meta.mediumSignals.join(', ')})`,
      file: meta.rel, line: 1,
      snippet: `strings: ${meta.mediumSignals.join(', ')}`,
      recommendation: '原生代码引用 shell 工具/凭据路径,需人工确认用途。',
    })
  }
  return findings
}

/**
 * Scan a directory tree: regex fast pass + semantic deep pass + binary audit.
 * @returns {Promise<object>} 完整度字段见返回对象。
 */
export async function scanTree(root, opts = {}) {
  const limits = { ...DEFAULT_LIMITS, ...opts }
  const io = limits.__io ?? {}
  const readFile = io.readFile ?? readFileSync
  const hashFile = io.hashFile ?? hashFileStream
  const {
    files, largeFiles, binaries, hardSkipped, skipped, ignored, truncated,
    traversalFailures,
  } = collectFiles(root, limits)

  const collector = new FindingCollector({
    maxFindings: limits.maxFindings,
    testReachableFiles: limits.testReachableFiles,
  })
  let findingsTotal = 0
  const languages = {}
  const largest = []
  let sourceFiles = 0
  let buildFiles = 0
  let filesAnalyzed = 0
  const analysisFailures = []

  for (const file of files) {
    let content
    try {
      content = readFile(file.abs, 'utf8')
    } catch (e) {
      analysisFailures.push({ path: file.rel, stage: 'read', reason: e.code ?? e.message })
      continue
    }
    const ext = extOf(file.rel).replace(/^\./, '') || 'text'
    languages[ext] = (languages[ext] ?? 0) + 1
    largest.push({ file: file.rel, bytes: file.size })
    if (isBuildPath(file.rel)) buildFiles += 1
    else sourceFiles += 1
    const minified = isMinifiedContent(content)
    const tagMinified = (list) => {
      for (const f of list) {
        f.bundleFile = true
        f.analysisMode = 'minified'
      }
    }
    // regex fast pass
    for (const rule of RULES) {
      if (rule.category === 'manifest' || rule.category === 'hygiene') continue
      if (rule.category === 'agent' || rule.category === 'taint') continue // semantic 引擎处理
      const r = applyRule(rule, file.rel, content)
      findingsTotal += r.total
      if (minified) tagMinified(r.findings)
      collector.addRuleHits(rule, r.total, r.findings, file.rel)
    }
    // semantic deep pass(JS/TS 工具类)
    if (CODE_EXT.test(file.rel)) {
      const sem = semanticScan(content, file.rel)
      findingsTotal += sem.length
      if (minified) tagMinified(sem)
      collector.addSemantic(sem, file.rel)
    }
    collector.finalizeFile(file.rel)
    filesAnalyzed += 1
  }

  for (const lf of largeFiles) {
    let content
    try {
      content = readFile(lf.abs, 'utf8')
    } catch (e) {
      analysisFailures.push({ path: lf.rel, stage: 'read', reason: e.code ?? e.message })
      continue
    }
    const ext = extOf(lf.rel).replace(/^\./, '') || 'text'
    languages[ext] = (languages[ext] ?? 0) + 1
    largest.push({ file: lf.rel, bytes: lf.size })
    if (isBuildPath(lf.rel)) buildFiles += 1
    else sourceFiles += 1
    const hash = createHash('sha256').update(content).digest('hex').slice(0, 16)
    const lite = analyzeLargeFileLite(content, lf.rel, { hash, bytes: lf.size })
    findingsTotal += lite.total
    if (isMinifiedContent(content)) {
      for (const f of lite.findings) {
        f.bundleFile = true
        f.analysisMode = 'minified'
      }
    }
    for (const h of lite.hits) collector.addRuleHits(h.rule, h.total, h.findings, lf.rel)
    collector.finalizeFile(lf.rel)
    filesAnalyzed += 1
  }

  // 可执行二进制 metadata audit(SEN-BIN-*/SEN-WASM-*)
  let binarySkippedCount = 0
  const binaryLimit = limits.binaryMaxFiles ?? DEFAULT_LIMITS.binaryMaxFiles
  for (const bin of binaries.slice(0, binaryLimit)) {
    let hash
    try {
      hash = await hashFile(bin.abs)
    } catch (e) {
      analysisFailures.push({ path: bin.rel, stage: 'hash', reason: e.code ?? e.message })
      continue
    }
    let head
    try {
      head = sampleHeadTail(bin.abs, bin.size).head
    } catch (e) {
      analysisFailures.push({ path: bin.rel, stage: 'binary-sample', reason: e.code ?? e.message })
      continue
    }
    const audit = auditBinarySample(head, bin.rel)
    const meta = { ...bin, hash, ...audit }
    const fs = binaryFindingsFor(meta)
    findingsTotal += fs.length
    collector.addSemantic(fs, bin.rel)
    collector.finalizeFile(bin.rel)
    filesAnalyzed += 1
  }
  if (binaries.length > binaryLimit) binarySkippedCount = binaries.length - binaryLimit

  // 超过 hardMax 的文件:metadata 记录(scanComplete 由调用方置 false)
  const hardSkippedMeta = []
  for (const h of hardSkipped) {
    try {
      const meta = await hardSkippedMetadata(h.abs, h.size)
      hardSkippedMeta.push({ ...meta, path: h.rel })
    } catch (e) {
      hardSkippedMeta.push({ path: h.rel, size: h.size, sha256: '', extension: extOf(h.rel), classification: 'unknown', hints: {} })
      analysisFailures.push({ path: h.rel, stage: 'metadata', reason: e.code ?? e.message })
    }
  }

  largest.sort((a, b) => b.bytes - a.bytes)
  const graphSeeds = [...files, ...largeFiles]
    .filter((f) => CODE_EXT.test(f.rel))
    .map((f) => f.rel)
  const moduleGraph = buildModuleGraph(root, graphSeeds)
  const readFailures = analysisFailures.filter((f) => f.stage === 'read').length
  const hashFailures = analysisFailures.filter((f) => f.stage === 'hash').length
  const binarySampleFailures = analysisFailures.filter((f) => f.stage === 'binary-sample').length
  return {
    findings: collector.findings(),
    allStats: collector.stats(),
    findingsTotal,
    filesAnalyzed,
    filesDiscovered: filesAnalyzed + hardSkipped.length + skipped.binary + skipped.ignored + binarySkippedCount + analysisFailures.length,
    scanComplete: !truncated && hardSkipped.length === 0 && binarySkippedCount === 0
      && analysisFailures.length === 0 && traversalFailures.length === 0,
    scanCoverage: {
      sourceFiles,
      buildFiles,
      binaryFiles: binaries.slice(0, binaryLimit).length,
      largeFiles: largeFiles.length,
      parseFailures: 0,
      hardSkippedFiles: hardSkipped.length,
      binarySkippedFiles: binarySkippedCount,
      readFailures,
      hashFailures,
      binarySampleFailures,
      analysisFailures: analysisFailures.length,
      traversalFailures: traversalFailures.length,
    },
    coverageSkips: [...analysisFailures, ...traversalFailures],
    traversalFailures,
    filesSkipped: skipped,
    hardSkipped: hardSkippedMeta,
    ignored,
    languages,
    largestFiles: largest.slice(0, 5),
    moduleGraph,
  }
}

/**
 * Resolve a patch row `name` (e.g. `dsh-sentinel/plugin`) against a package
 * root, with path containment:任何解析结果必须位于包根之内,否则抛 PathEscapeError。
 */
export function resolvePatchEntry(packageRoot, name, packageName = '') {
  if (!name || name.startsWith('cordis:') || name.startsWith('@deepseek-ai/')) return null
  let rel
  if (packageName && (name === packageName || name.startsWith(packageName + '/'))) {
    rel = name === packageName ? '' : name.slice(packageName.length + 1)
  } else {
    rel = name
  }
  const candidates = []
  const pkgText = readMaybe(join(packageRoot, 'package.json'))
  if (pkgText !== null) {
    let exportsMap = null
    try {
      exportsMap = JSON.parse(pkgText).exports
    } catch {
      exportsMap = null
    }
    if (exportsMap !== null && typeof exportsMap === 'object') {
      const key = rel === '' ? '.' : `./${rel.replace(/\\/g, '/')}`
      let target = exportsMap[key]
      if (target !== null && typeof target === 'object' && !Array.isArray(target)) {
        target = target.default
      }
      if (typeof target === 'string' && target.startsWith('./')) {
        candidates.push(join(packageRoot, ...target.slice(2).split('/')))
      }
    }
    if (rel === '') {
      try {
        const main = JSON.parse(pkgText).main
        if (typeof main === 'string' && main.length > 0) {
          candidates.push(join(packageRoot, ...main.replace(/\\/g, '/').split('/')))
        }
      } catch {
        // unparseable manifest — fall through to index conventions
      }
    }
  }
  if (rel === '') {
    candidates.push(join(packageRoot, 'index.js'), join(packageRoot, 'index.mjs'))
  } else {
    const parts = rel.replace(/\\/g, '/').split('/')
    const base = join(packageRoot, ...parts)
    candidates.push(base, base + '.js', base + '.mjs', join(base, 'index.js'), join(base, 'index.mjs'))
  }
  for (const c of candidates) {
    // containment:manifest 派生的任何路径都不可信(词法 + realpath + symlink)
    try {
      resolveInside(packageRoot, c)
    } catch {
      throw new PathEscapeError(c)
    }
    try {
      if (statSync(c).isFile()) return c
    } catch {
      // not a file — try next candidate
    }
  }
  return null
}

/** Cheap line-based extraction of rows from a patch file. */
export function parsePatchRows(patchText) {
  const rows = []
  let current = null
  for (const rawLine of patchText.split('\n')) {
    const line = rawLine.trim()
    const idMatch = /^-\s*id:\s*(\S+)/.exec(line)
    if (idMatch) {
      if (current) rows.push(current)
      current = { id: idMatch[1] }
      continue
    }
    if (!current) {
      const nameOnly = /^-\s*name:\s*['"]?([^'"]+)['"]?\s*$/.exec(line)
      if (nameOnly) {
        if (current) rows.push(current)
        current = { name: nameOnly[1].trim() }
      }
      continue
    }
    const nameMatch = /^name:\s*['"]?([^'"]+)['"]?\s*$/.exec(line)
    if (nameMatch) current.name = nameMatch[1].trim()
    if (/^disabled:\s*true/i.test(line)) current.disabled = true
  }
  if (current) rows.push(current)
  return rows
}

export function readMaybe(absPath) {
  try {
    return readFileSync(absPath, 'utf8')
  } catch {
    return null
  }
}

/**
 * 插件入口契约校验:Cordis/DSH 插件必须同时导出 name 与 apply。
 * 支持 ESM 命名导出、export default 对象、CJS module.exports/exports.default 对象。
 */
export function hasExportContract(absPath) {
  const content = readMaybe(absPath)
  if (content === null) return false
  const has = (re) => re.test(content)
  const hasNamedExport = (identifier) => new RegExp(
    `export\\s+(?:(?:const|let|class|default)\\s+${identifier}\\b|(?:async\\s+)?function\\s+${identifier}\\b)`,
  ).test(content)

  // ESM 命名导出:export const name / export function apply 等。
  if (hasNamedExport('name') && hasNamedExport('apply')) {
    return true
  }
  // ESM 导出列表形态:export { name, apply }(压缩 bundle 常用)
  const listExports = [...content.matchAll(/export\s*\{([^}]*)\}/g)]
  if (listExports.length > 0) {
    const listNames = new Set(listExports.flatMap((m) => m[1].split(',').map((s) => s.trim().split(/\s+as\s+/).pop()).filter(Boolean)))
    if (listNames.has('name') && listNames.has('apply')) return true
  }
  // export default 对象:必须同时含 name 与 apply(键或方法简写)。
  const defStart = content.search(/export\s+default\s*\{/m)
  if (defStart >= 0) {
    const body = content.slice(defStart)
    return /\bname\s*:/.test(body) && /\bapply\s*[:(]/.test(body)
  }
  // Cordis service class:class declaration exported as default is itself a valid plugin.
  if (/export\s+default\s+class(?:\s+[A-Za-z_$][\w$]*)?\s*\{/m.test(content)) return true
  const defaultIdentifier = /export\s+default\s+([A-Za-z_$][\w$]*)\s*;?/m.exec(content)?.[1]
  if (defaultIdentifier) {
    const escaped = defaultIdentifier.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    if (new RegExp(`(?:export\\s+)?class\\s+${escaped}\\b`).test(content)) return true
  }
  // CommonJS:module.exports = {...} / exports.default = {...},必须含两个键。
  const cjsRe = /(?:module\.exports|exports\.default)\s*=\s*\{([\s\S]*?)\n?\}/m
  const cjs = cjsRe.exec(content)
  if (cjs) {
    return /\bname\s*:/.test(cjs[1]) && /\bapply\s*[:(]/.test(cjs[1])
  }
  // 仅 module.exports = require(...) 等转发形态:无法静态确认,视为不合格。
  return false
}
