/**
 * OSV 漏洞查询(Phase 8):--advisories,默认关闭。
 * 只上传 package name + version,绝不上传源码。
 * 查询失败/离线时静默降级(报告标注 advisories: 'unavailable')。
 */

import { boundedHttpRequest } from './http-client.js'

export const OSV_API = 'https://api.osv.dev/v1/query'
export const OSV_MAX_BYTES = 5 * 1024 * 1024
export const OSV_TIMEOUT_MS = 20_000

/**
 * 查询某个包的已知漏洞。
 * 只 POST `{package:{name,ecosystem},version}`。传输失败、非 2xx 或非 JSON
 * 都降级为 unavailable,不抛给扫描主路径。
 * @param {string} name
 * @param {string} version
 * @param {object} [opts] - {endpoint, timeoutMs, maxBytes}
 * @returns {Promise<{status: 'ok'|'unavailable', vulnerabilities: Array}>}
 */
export async function queryOsv(name, version, opts = {}) {
  const endpoint = opts.endpoint ?? OSV_API
  try {
    const result = await boundedHttpRequest(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ package: { name, ecosystem: 'npm' }, version }),
      maxBytes: opts.maxBytes ?? OSV_MAX_BYTES,
      timeoutMs: opts.timeoutMs ?? OSV_TIMEOUT_MS,
      followRedirects: false,
    })
    if (result.status < 200 || result.status >= 300 || !result.body) {
      return { status: 'unavailable', vulnerabilities: [] }
    }
    const doc = JSON.parse(result.body.toString('utf8'))
    const vulnerabilities = (doc.vulns ?? []).map((v) => ({
      id: v.id,
      summary: v.summary ?? '',
      severity: v.severity?.[0]?.score ? `CVSS ${v.severity[0].score}` : '',
      modified: v.modified ?? '',
    }))
    return { status: 'ok', vulnerabilities }
  } catch {
    return { status: 'unavailable', vulnerabilities: [] }
  }
}

/** 把 OSV 结果并入报告。 */
export function attachAdvisories(report, result) {
  report.advisories = {
    status: result.status,
    vulnerabilities: result.vulnerabilities,
  }
  if (result.status === 'ok' && result.vulnerabilities.length > 0) {
    report.findings.push(...result.vulnerabilities.map((v) => ({
      id: 'SEN-OSV-001',
      severity: 'medium',
      category: 'supplychain',
      confidence: 'high',
      message: `已知漏洞:${v.id} — ${v.summary}`,
      file: 'package.json',
      line: 1,
      snippet: v.summary.slice(0, 200),
      recommendation: '升级到修复版本;如无法升级,评估缓解措施。',
    })))
  }
  return report
}
