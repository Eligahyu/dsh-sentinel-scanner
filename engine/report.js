/**
 * Report assembly: scoring, verdict, and the canonical JSON shape.
 *
 * 完整度契约:
 *   - findings 上限只影响 findingsReturned,不影响实际分析(filesAnalyzed)
 *   - 评分基于全部有效命中(allStats,scoreBasedOnAllFindings),与展示解耦:
 *     critical/high 即使出现在 cap 之后也不会丢失计分(P0-1)
 *   - bundleFile/minified 只作为 evidence/context 标记,绝不自动降 severity
 *     (confidence 模型:regex-only=medium,AST/taint=high,见 engine/rules.js)
 *   - 同源重叠抑制(specific > generic)只剔除评分,证据保留
 *   - 任何截断(scanComplete=false)都会强制裁决不低于 review 并显式标记
 *   - 所有 snippet 中的 secret 一律脱敏(redactSecrets),绝不二次泄露
 *
 * The emitted object keeps every legacy key for compatibility.
 */

import { SEVERITY_ORDER, CATEGORIES, severityWeight } from './rules.js'
import { VERSION } from './version.js'
import { redactSecrets } from './redact.js'
import { attachFingerprints } from './report/fingerprint.js'
import { incompleteLayerReasons, normalizeAnalysisLayers } from './report/schema.js'

export const VERDICTS = Object.freeze({
  safe: { min: 0, max: 19, label: 'safe', emoji: '✅' },
  review: { min: 20, max: 49, label: 'review', emoji: '👀' },
  risky: { min: 50, max: 79, label: 'risky', emoji: '⚠️' },
  dangerous: { min: 80, max: 100, label: 'dangerous', emoji: '🚨' },
})

/**
 * Test-file findings are usually deliberate fixtures (malicious strings,
 * base64 blobs, env-gated tests) rather than shipped code. They are still
 * listed with their detected severity, but SCORED one level lower — UNLESS
 * the file is reachable from a runtime entry (main/exports/bin/patch), in
 * which case it is NOT downgraded (reachability-aware downgrade, §13).
 */
export const TEST_SEVERITY_DOWNGRADE = Object.freeze({
  critical: 'high',
  high: 'medium',
  medium: 'low',
  low: 'info',
  info: 'info',
})

/** Unreachable tests and explicit development helpers remain visible, but cannot dominate a package verdict. */
export const NON_RUNTIME_CONTEXT_SCORE_CAP = 20

/** Low-confidence heuristic evidence is scored one severity level lower. */
export function scoredSeverity(severity, { context = 'source', confidence = 'medium' } = {}) {
  let weighted = context === 'source' ? severity : (TEST_SEVERITY_DOWNGRADE[severity] ?? severity)
  if (confidence === 'low') weighted = TEST_SEVERITY_DOWNGRADE[weighted] ?? weighted
  return weighted
}

function scoreFromContextStats(allStats) {
  const byContext = allStats?.rawScoreByContext
  if (!byContext) return allStats?.rawScore ?? 0
  return (byContext.source ?? 0)
    + Math.min(NON_RUNTIME_CONTEXT_SCORE_CAP, byContext.test ?? 0)
    + Math.min(NON_RUNTIME_CONTEXT_SCORE_CAP, byContext.development ?? 0)
}

/**
 * 同源重叠抑制:同一文件同一行的"更具体规则"命中时,抑制"更泛规则"的评分
 * (证据保留在报告中,见 scanner.markSuppressed)。
 * 例:eval(atob(...)) 同时命中 SEN-EXEC-004(解码执行,具体)与 SEN-EXEC-003(裸 eval,泛);
 *     SEN-AGENT-001(语义流)抑制同一行泛化的 SEN-EXEC-002。
 */
export const OVERLAP_SUPPRESSION = [
  { specific: 'SEN-EXEC-004', generic: 'SEN-EXEC-003' },
  { specific: 'SEN-TAINT-003', generic: 'SEN-EXEC-003' },
  { specific: 'SEN-AGENT-001', generic: 'SEN-EXEC-002' },
]

/**
 * Heuristic: is this relative path a test file or under a test directory?
 * Matches `test/`, `tests/`, `__tests__/`, `spec/`, `e2e/` segments and
 * `.spec.` / `.test.` / `.e2e.` filename markers.
 */
export function isTestPath(relPath) {
  return /(^|[\\/])(?:test|tests|__tests__|spec|e2e)([\\/]|\.)|\.(?:spec|test|e2e)\./i.test(relPath)
}

/** Non-runtime evaluation/release helpers:reported at full severity, scored one level lower. */
export function isDevelopmentPath(relPath) {
  const normalized = String(relPath ?? '').replace(/\\/g, '/')
  if (/(^|\/)(?:evals?|bench|benchmark|benchmarks|examples?|fixtures)(\/|$)/i.test(normalized)) return true
  if (/(^|\/)scripts\//i.test(normalized)
    && !/(^|\/)(?:preinstall|install|postinstall|prepare|prepublish)(?:[.\/-]|$)/i.test(normalized)) return true
  return /(^|\/)(?:scripts\/)?(?:release|live-e2e|check|check-package|dev-run|docs-list)(?:[.\/-]|$)/i.test(normalized)
}

export function verdictFor(score) {
  for (const v of Object.values(VERDICTS)) {
    if (score >= v.min && score <= v.max) return v
  }
  return VERDICTS.dangerous
}

export function emptyCounts() {
  return {
    bySeverity: Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0])),
    byCategory: Object.fromEntries(CATEGORIES.map((c) => [c, 0])),
  }
}

/** 保留供无 allStats 的旧调用路径使用:同文件同行 specific 抑制 generic。 */
export function suppressOverlaps(findings) {
  const specific = new Set()
  for (const f of findings) {
    if (OVERLAP_SUPPRESSION.some((p) => p.specific === f.ruleId)) {
      specific.add(`${f.ruleId}|${f.file}|${f.line ?? 1}|${f.package ?? ''}`)
    }
  }
  if (specific.size === 0) return findings
  return findings.filter((f) => {
    const g = OVERLAP_SUPPRESSION.find((p) => p.generic === f.ruleId)
    if (!g) return true
    return !specific.has(`${g.specific}|${f.file}|${f.line ?? 1}|${f.package ?? ''}`)
  })
}

/**
 * Build the canonical report object.
 * @param {object} parts - 见调用方;新增完整度字段:
 *   findingsTotal, filesAnalyzed, filesDiscovered, scanComplete, scanCoverage,
 *   allStats(评分依据,来自 scanner FindingCollector)
 */
export function buildReport(parts, maxFindings = 300) {
  const analysisLayers = normalizeAnalysisLayers(parts.analysisLayers)
  const layerIncompleteReasons = incompleteLayerReasons(analysisLayers)
  const counts = parts.allStats
    ? { bySeverity: { ...parts.allStats.bySeverity }, byCategory: { ...parts.allStats.byCategory } }
    : emptyCounts()
  const contextCounts = parts.allStats?.byContext
    ? { ...parts.allStats.byContext }
    : { source: 0, test: 0, development: 0 }

  let score = 0
  let total = 0
  const scoreBasedOnAllFindings = Boolean(parts.allStats)
  if (parts.allStats) {
    score = Math.min(100, scoreFromContextStats(parts.allStats))
    total = parts.allStats.findingCount
  } else {
    // Legacy path(无 allStats):从 findings 计算
    for (const f of suppressOverlaps(parts.findings ?? [])) {
      total += 1
      const context = isTestPath(f.file) ? 'test' : isDevelopmentPath(f.file) ? 'development' : 'source'
      contextCounts[context] = (contextCounts[context] ?? 0) + 1
      counts.bySeverity[f.severity] = (counts.bySeverity[f.severity] ?? 0) + 1
      counts.byCategory[f.category] = (counts.byCategory[f.category] ?? 0) + 1
      const weighted = scoredSeverity(f.severity, { context, confidence: f.confidence })
      score += severityWeight(weighted)
    }
    // Legacy callers do not carry per-context scores, so reconstruct them from findings.
    const legacyScores = { source: 0, test: 0, development: 0 }
    for (const f of suppressOverlaps(parts.findings ?? [])) {
      const context = isTestPath(f.file) ? 'test' : isDevelopmentPath(f.file) ? 'development' : 'source'
      legacyScores[context] += severityWeight(scoredSeverity(f.severity, { context, confidence: f.confidence }))
    }
    score = Math.min(100, legacyScores.source
      + Math.min(NON_RUNTIME_CONTEXT_SCORE_CAP, legacyScores.test)
      + Math.min(NON_RUNTIME_CONTEXT_SCORE_CAP, legacyScores.development))
  }

  let verdict = verdictFor(score)

  const scanComplete = parts.scanComplete !== false && layerIncompleteReasons.length === 0
  const findingsTotal = parts.findingsTotal ?? total

  // 不完整扫描绝不能显示 clean:强制至少 review 并显式标记。
  if (!scanComplete) {
    if (verdict.label === 'safe') {
      score = Math.max(score, 20)
      verdict = verdictFor(score)
    }
  }

  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  const seen = new Set()
  const capped = [...(parts.findings ?? [])]
    .filter((f) => {
      // §13.5:去重键必须含 source+sink——同一行多个独立 flow 不得折叠。
      const key = `${f.ruleId}|${f.file}|${f.line ?? 1}|${f.source?.name ?? ''}|${f.sink?.callee ?? ''}|${f.package ?? ''}`
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
    .sort((a, b) => order[a.severity] - order[b.severity] || a.file.localeCompare(b.file) || a.line - b.line)
    .slice(0, maxFindings)
    .map((f) => {
      const redacted = redactSecrets(f.snippet ?? '')
      return {
        id: f.ruleId,
        severity: f.severity,
        category: f.category,
        confidence: f.confidence ?? 'medium',
        message: f.message,
        file: f.file,
        line: f.line ?? 1,
        snippet: redacted.text,
        recommendation: f.recommendation ?? '',
        package: f.package ?? '',
        testFile: isTestPath(f.file),
        ...(isDevelopmentPath(f.file) ? { developmentFile: true } : {}),
        ...(redacted.redacted ? { redacted: true, secretFingerprints: redacted.fingerprints } : {}),
        ...(f.analysisMode ? { analysisMode: f.analysisMode } : {}),
        ...(f.bundleFile ? { bundleFile: true } : {}),
        ...(f.suppressedForScore ? { suppressedForScore: true } : {}),
        ...(f.source ? { source: f.source } : {}),
        ...(f.sink ? { sink: f.sink } : {}),
        ...(f.flow ? { flow: f.flow } : {}),
        ...(f.flowSteps ? { flowSteps: f.flowSteps } : {}),
        ...(f.functionName ? { functionName: f.functionName } : {}),
        ...(f.enclosingFunction ? { enclosingFunction: f.enclosingFunction } : {}),
        ...(f.toolName ? { toolName: f.toolName } : {}),
        ...(f.startColumn ? { startColumn: f.startColumn } : {}),
        ...(f.endLine ? { endLine: f.endLine } : {}),
        ...(f.endColumn ? { endColumn: f.endColumn } : {}),
        ...(f.ssrfTarget ? { ssrfTarget: true } : {}),
        ...(f.detail ? { detail: f.detail } : {}),
        ...(f.crossFile ? { crossFile: true } : {}),
        ...(f.modulePath ? { modulePath: f.modulePath } : {}),
        ...(f.attackChainId ? { attackChainId: f.attackChainId } : {}),
        ...(f.capabilities ? { capabilities: f.capabilities } : {}),
      }
    })

  const findingsReturned = capped.length
  const findingsTruncated = findingsTotal > findingsReturned

  const report = {
    schemaVersion: 2,
    tool: 'dsh-sentinel',
    version: VERSION,
    scannedAt: new Date().toISOString(),
    target: {
      kind: parts.kind,
      path: parts.path,
      name: parts.name ?? '',
    },
    summary: {
      verdict: verdict.label,
      score,
      // 完整度
      scanComplete,
      incompleteScan: !scanComplete,
      incompleteReasons: [
        ...(parts.scanComplete === false ? ['scan'] : []),
        ...layerIncompleteReasons,
      ],
      filesDiscovered: parts.filesDiscovered ?? parts.filesScanned ?? 0,
      filesAnalyzed: parts.filesAnalyzed ?? parts.filesScanned ?? 0,
      findingsTotal,
      findingsReturned,
      findingsTruncated,
      scoreBasedOnAllFindings,
      // 兼容旧字段
      filesScanned: parts.filesAnalyzed ?? parts.filesScanned ?? 0,
      filesSkipped: parts.filesSkipped?.binary ?? 0,
      totalFindings: total,
      bySeverity: counts.bySeverity,
      byCategory: counts.byCategory,
      byContext: contextCounts,
      scanMs: parts.scanMs,
    },
    scanCoverage: {
      sourceFiles: parts.scanCoverage?.sourceFiles ?? 0,
      buildFiles: parts.scanCoverage?.buildFiles ?? 0,
      binaryFiles: parts.scanCoverage?.binaryFiles ?? parts.filesSkipped?.binary ?? 0,
      largeFiles: parts.scanCoverage?.largeFiles ?? 0,
      parseFailures: parts.scanCoverage?.parseFailures ?? 0,
      hardSkippedFiles: parts.scanCoverage?.hardSkippedFiles ?? 0,
      binarySkippedFiles: parts.scanCoverage?.binarySkippedFiles ?? 0,
      readFailures: parts.scanCoverage?.readFailures ?? 0,
      hashFailures: parts.scanCoverage?.hashFailures ?? 0,
      analysisFailures: parts.scanCoverage?.analysisFailures ?? 0,
      traversalFailures: parts.scanCoverage?.traversalFailures ?? 0,
    },
    manifest: parts.manifest,
    profile: {
      name: parts.name ?? '',
      pluginsScanned: parts.pluginsScanned ?? [],
      pluginsSkipped: parts.pluginsSkipped ?? [],
      plugins: parts.plugins ?? [],
    },
    findings: capped,
    attackChains: parts.attackChains ?? [],
    analysisLayers,
    ignored: parts.ignored ?? [],
    hardSkipped: parts.hardSkipped ?? [],
    policySkips: parts.policySkips ?? [],
    coverageSkips: parts.coverageSkips ?? [],
    supplyChain: parts.supplyChain ?? {},
    stats: {
      languages: parts.languages ?? {},
      largestFiles: (parts.largestFiles ?? []).map((f) => ({ file: f.file, bytes: f.bytes })),
    },
  }
  // P1-6 方案 B:在报告层附加稳定指纹(字段裁剪后仍保有 source/sink,指纹完整)。
  attachFingerprints(report)
  return report
}
