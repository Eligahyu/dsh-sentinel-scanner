/**
 * Bounded cross-file taint analysis built on the safe module graph.
 *
 * The first pass models the high-value DSH shape: a tool entry passes args.*
 * into an imported function, whose exported parameter reaches a dangerous
 * sink. Unresolved graph edges are evidence of incomplete analysis.
 */

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const SINKS = [
  { names: ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork'], type: 'shell', ruleId: 'SEN-AGENT-001', severity: 'critical', module: 'child_process' },
  { names: ['readFile', 'readFileSync', 'createReadStream', 'openSync'], type: 'file-read', ruleId: 'SEN-AGENT-002', severity: 'high', module: 'fs' },
  { names: ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream'], type: 'file-write', ruleId: 'SEN-AGENT-003', severity: 'high', module: 'fs' },
  { names: ['fetch', 'axios', 'WebSocket', 'sendBeacon'], type: 'network', ruleId: 'SEN-AGENT-004', severity: 'high', module: null },
]

const escapeRe = (value) => String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

function braceEnd(text, open) {
  let depth = 0
  let quote = null
  let escaped = false
  for (let i = open; i < text.length; i += 1) {
    const ch = text[i]
    if (quote) {
      if (escaped) escaped = false
      else if (ch === '\\') escaped = true
      else if (ch === quote) quote = null
      continue
    }
    if (ch === "'" || ch === '"' || ch === '`') quote = ch
    else if (ch === '{') depth += 1
    else if (ch === '}' && --depth === 0) return i
  }
  return -1
}

function importsForSpecifier(content, specifier) {
  const quoted = escapeRe(specifier)
  const out = []
  const named = new RegExp(`import\\s*\\{([\\s\\S]*?)\\}\\s*from\\s*['"]${quoted}['"]`, 'g')
  let match
  while ((match = named.exec(content)) !== null) {
    for (const part of match[1].split(',')) {
      const bits = part.trim().split(/\s+as\s+/)
      const imported = bits[0]?.trim()
      const local = bits[1]?.trim() ?? imported
      if (local) out.push({ imported, local })
    }
  }
  const defaultImport = new RegExp(`import\\s+([A-Za-z_$][\\w$]*)\\s+from\\s*['"]${quoted}['"]`, 'g')
  while ((match = defaultImport.exec(content)) !== null) out.push({ imported: 'default', local: match[1] })
  const commonJsNamed = new RegExp(`(?:const|let|var)\\s*\\{([^{}]*)\\}\\s*=\\s*require\\s*\\(\\s*['"]${quoted}['"]\\s*\\)`, 'g')
  while ((match = commonJsNamed.exec(content)) !== null) {
    for (const part of match[1].split(',')) {
      const bits = part.trim().split(/\s*:\s*/)
      const imported = bits[0]?.trim()
      const local = bits[1]?.trim() ?? imported
      if (imported && local) out.push({ imported, local })
    }
  }
  return out
}

function exportedFunction(content, name) {
  const escaped = escapeRe(name)
  const patterns = [
    new RegExp(`export\\s+(?:async\\s+)?function\\s+${escaped}\\s*\\(\\s*([A-Za-z_$][\\w$]*)[^)]*\\)\\s*\\{`, 'm'),
    new RegExp(`(?:module\\s*\\.\\s*exports|exports)\\s*\\.\\s*${escaped}\\s*=\\s*(?:async\\s+)?function(?:\\s+[A-Za-z_$][\\w$]*)?\\s*\\(\\s*([A-Za-z_$][\\w$]*)[^)]*\\)\\s*\\{`, 'm'),
  ]
  const match = patterns.map((pattern) => pattern.exec(content)).find(Boolean)
  if (match) {
    const open = match.index + match[0].length - 1
    const end = braceEnd(content, open)
    if (end < 0) return null
    return { param: match[1], body: content.slice(open + 1, end), start: match.index }
  }

  const arrow = new RegExp(`(?:module\\s*\\.\\s*exports|exports)\\s*\\.\\s*${escaped}\\s*=\\s*(?:async\\s+)?(?:\\(\\s*([A-Za-z_$][\\w$]*)[^)]*\\)|([A-Za-z_$][\\w$]*))\\s*=>\\s*`, 'm').exec(content)
  if (!arrow) return null
  const param = arrow[1] ?? arrow[2]
  const bodyStart = arrow.index + arrow[0].length
  if (content[bodyStart] === '{') {
    const end = braceEnd(content, bodyStart)
    if (end < 0) return null
    return { param, body: content.slice(bodyStart + 1, end), start: arrow.index }
  }
  const lineEnd = content.slice(bodyStart).search(/[;\r\n]/)
  const bodyEnd = lineEnd < 0 ? content.length : bodyStart + lineEnd
  return { param, body: content.slice(bodyStart, bodyEnd), start: arrow.index }
}

function boundSink(body, param, content) {
  for (const sink of SINKS) {
    const names = sink.names.map(escapeRe).join('|')
    const call = new RegExp(`\\b(${names})\\s*\\(\\s*${escapeRe(param)}(?:\\b|[.[])`)
    const match = call.exec(body)
    if (!match) continue
    if (sink.module && !new RegExp(`(?:from|require\\s*\\()\\s*['"](?:node:)?${sink.module}['"]`).test(content)) continue
    return { ...sink, callee: match[1] }
  }
  return null
}

function sourceInvocation(content, local) {
  const call = new RegExp(`\\b${escapeRe(local)}\\s*\\(\\s*(args\\.[A-Za-z_$][\\w$]*)`)
  const match = call.exec(content)
  return match ? { source: match[1], start: match.index } : null
}

function chainId(chain) {
  return createHash('sha256').update(JSON.stringify(chain)).digest('hex').slice(0, 16)
}

/**
 * @param {string} root scan root
 * @param {{nodes: object[], edges: object[], unresolved: object[], failures: object[], complete: boolean}} graph
 */
export function analyzeCrossFileTaint(root, graph, { maxDepth = 4 } = {}) {
  const findings = []
  const attackChains = []
  const failures = []
  if (!graph?.complete || (graph?.failures?.length ?? 0) > 0) {
    failures.push({ reason: 'module-graph-incomplete', details: graph?.failures ?? [] })
  }
  const sourceByPath = new Map()
  for (const node of graph?.nodes ?? []) {
    try {
      sourceByPath.set(node.path, readFileSync(join(root, node.path), 'utf8'))
    } catch (error) {
      failures.push({ path: node.path, reason: 'read-error', detail: error?.code ?? error?.message })
    }
  }

  for (const edge of graph?.edges ?? []) {
    if (maxDepth < 1) {
      failures.push({ from: edge.from, to: edge.to, reason: 'depth-limit' })
      continue
    }
    const from = sourceByPath.get(edge.from)
    const to = sourceByPath.get(edge.to)
    if (!from || !to) continue
    for (const binding of importsForSpecifier(from, edge.specifier)) {
      const invocation = sourceInvocation(from, binding.local)
      if (!invocation) continue
      const exported = exportedFunction(to, binding.imported === 'default' ? binding.local : binding.imported)
      if (!exported) continue
      const sink = boundSink(exported.body, exported.param, to)
      if (!sink) continue
      const chain = {
        source: invocation.source,
        modulePath: [edge.from, edge.to],
        functionPath: [`${binding.local}(...)`, `${binding.imported}(${exported.param})`],
        sink: sink.callee,
      }
      const attackChainId = chainId(chain)
      attackChains.push({ id: attackChainId, ...chain, confidence: 'high' })
      findings.push({
        ruleId: sink.ruleId,
        severity: sink.severity,
        category: 'agent',
        confidence: 'high',
        message: `跨文件污点流:${invocation.source} → ${sink.callee}`,
        file: edge.to,
        line: (to.slice(0, exported.start).match(/\n/g) ?? []).length + 1,
        snippet: exported.body.trim().split('\n')[0].slice(0, 240),
        recommendation: sink.type === 'shell'
          ? '跨文件调用链仍接收模型输入;对工具输入做白名单校验并避免 shell 解释。'
          : '跨文件调用链必须限制目标与路径,并验证数据不会越权流出。',
        source: { type: 'tool-argument', name: invocation.source },
        sink: { type: sink.type, callee: sink.callee },
        flow: [invocation.source, `${binding.local}(...)`, `${sink.callee}(...)`],
        flowSteps: [invocation.source, `${binding.imported}(${exported.param})`, sink.callee],
        modulePath: [edge.from, edge.to],
        crossFile: true,
        attackChainId,
      })
    }
  }
  return {
    findings,
    attackChains,
    reachability: attackChains.map((x) => ({ id: x.id, path: x.modulePath, reachable: true })),
    failures,
    complete: failures.length === 0,
  }
}
