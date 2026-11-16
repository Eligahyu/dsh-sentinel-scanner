/**
 * SARIF 2.1.0 输出:供 GitHub Code Scanning / 各 SARIF 消费者使用。
 *
 * 注意:SARIF 是"结果标准化"格式,不是检测引擎本身。
 *
 * 约定:
 *   - severity 映射:critical/high → error,medium → warning,low/info → note
 *   - 路径尽量输出仓库相对路径(basePath 提供时)。basePath 若是文件则相对其目录,
 *     单文件扫描也不会得到空 uri
 *   - 区域是 1-based;小于 1 的行号/列号钳到 1,并保证 endLine/endColumn 不早于起点
 *   - 稳定指纹放 properties.dshFingerprint,不写 partialFingerprints
 *   - invocations[0].executionSuccessful 在 summary.scanComplete === false 时为 false
 *   - 扫描不完整或 findingsTruncated 时写 toolExecutionNotifications
 */

import { statSync } from 'node:fs'
import { relative, isAbsolute, resolve, dirname, basename } from 'node:path'
import { VERSION } from '../version.js'
import { fingerprintOf } from '../report/fingerprint.js'

const SEVERITY_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' }

/** @param {unknown} value */
function atLeastOne(value) {
  const n = Number(value)
  if (!Number.isFinite(n)) return null
  return Math.max(1, Math.trunc(n))
}

/** SARIF region。行号缺省为 1;列号只在原字段存在时写出。 */
function regionFor(finding) {
  const startLine = atLeastOne(finding.line) ?? 1
  const region = { startLine }
  if (finding.startColumn != null) {
    const startColumn = atLeastOne(finding.startColumn)
    if (startColumn != null) region.startColumn = startColumn
  }
  if (finding.endLine != null) {
    const endLine = atLeastOne(finding.endLine)
    if (endLine != null) region.endLine = Math.max(startLine, endLine)
  }
  if (finding.endColumn != null) {
    const endColumn = atLeastOne(finding.endColumn)
    if (endColumn != null) {
      const sameLine = region.endLine == null || region.endLine === startLine
      const minColumn = sameLine ? (region.startColumn ?? 1) : 1
      region.endColumn = Math.max(minColumn, endColumn)
    }
  }
  return region
}

/** basePath 是文件时改用其所在目录,这样 relative(file, file) 不会变成空字符串。 */
function sarifBase(raw) {
  if (!raw) return null
  let abs
  try {
    abs = resolve(String(raw))
  } catch {
    return null
  }
  try {
    if (statSync(abs).isFile()) return dirname(abs)
  } catch {
    // 路径不存在时仍按调用方给出的目录做相对化。
  }
  return abs
}

function toUri(p, basePath) {
  const raw = String(p ?? '')
  const norm = raw.replace(/\\/g, '/')
  if (basePath && raw && isAbsolute(raw)) {
    let rel = ''
    try {
      rel = relative(basePath, raw).replace(/\\/g, '/')
    } catch {
      rel = ''
    }
    if (rel === '') return basename(raw).replace(/\\/g, '/') || 'file'
    if (!rel.startsWith('..')) return rel
  }
  if (!norm) return 'file'
  return norm
}

function invocationFor(report) {
  const summary = report.summary ?? {}
  const incomplete = summary.scanComplete === false
  const notifications = []
  if (incomplete) {
    const reasons = Array.isArray(summary.incompleteReasons)
      ? summary.incompleteReasons.filter((reason) => typeof reason === 'string' && reason)
      : []
    const reasonText = reasons.length ? ` (${reasons.join(', ')})` : ''
    notifications.push({
      descriptor: { id: 'dsh-scan-incomplete' },
      message: { text: `Static scan did not complete${reasonText}. SARIF results are partial.` },
      level: 'error',
    })
  }
  if (summary.findingsTruncated === true) {
    const returned = summary.findingsReturned
    const total = summary.findingsTotal
    const counts = Number.isFinite(returned) && Number.isFinite(total)
      ? ` (${returned} of ${total} returned)`
      : ''
    notifications.push({
      descriptor: { id: 'dsh-findings-truncated' },
      message: { text: `Findings were truncated${counts}. This SARIF file contains only the returned findings.` },
      level: 'warning',
    })
  }
  return {
    executionSuccessful: !incomplete,
    ...(notifications.length ? { toolExecutionNotifications: notifications } : {}),
  }
}

/** 报告 → SARIF 2.1.0 JSON。@param {object} opts - {basePath: 仓库根或单个目标文件} */
export function toSarif(report, opts = {}) {
  const basePath = sarifBase(opts.basePath)
  const rules = new Map()
  for (const f of report.findings ?? []) {
    if (!rules.has(f.id)) {
      rules.set(f.id, {
        id: f.id,
        name: f.id,
        shortDescription: { text: f.message },
        defaultConfiguration: { level: SEVERITY_LEVEL[f.severity] ?? 'warning' },
        help: { text: f.recommendation ?? '', markdown: f.recommendation ?? '' },
        properties: { category: f.category, severity: f.severity, confidence: f.confidence ?? 'medium' },
      })
    }
  }
  const results = (report.findings ?? []).map((f) => ({
    ruleId: f.id,
    level: SEVERITY_LEVEL[f.severity] ?? 'warning',
    message: { text: `${f.message}${f.detail ? ` — ${f.detail}` : ''}` },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: toUri(f.file, basePath) },
        region: regionFor(f),
      },
    }],
    // 不写 partialFingerprints:那会冒充 primaryLocationLineHash。稳定指纹在 dshFingerprint。
    properties: {
      severity: f.severity,
      confidence: f.confidence ?? 'medium',
      dshFingerprint: f.fingerprint ?? fingerprintOf(f),
      ...(f.flow ? { flow: f.flow } : {}),
      ...(f.flowSteps ? { flowSteps: f.flowSteps } : {}),
      ...(f.source?.name ? { source: f.source.name } : {}),
      ...(f.sink?.callee ? { sink: f.sink.callee } : {}),
      ...(f.toolName ? { toolName: f.toolName } : {}),
      ...(f.ssrfTarget ? { ssrfTarget: true } : {}),
    },
  }))
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'dsh-sentinel',
          version: VERSION,
          informationUri: 'https://github.com/Eligahyu/dsh-sentinel-scanner',
          rules: [...rules.values()],
        },
      },
      invocations: [invocationFor(report)],
      results,
      properties: {
        summary: report.summary,
      },
    }],
  }
}
