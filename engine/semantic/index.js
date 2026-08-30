/**
 * Semantic engine(Phase 4+5):AST 优先,正则兜底。
 *
 *   AST 可用  → astTaintScan(confidence: high)
 *   解析失败  → regexSemanticScan(confidence: medium,旧版行为保留)
 *
 * 红线不变:只读静态分析,绝不执行被扫描代码。
 */

import { CODE_EXT } from '../rules.js'
import { parseJavaScript } from './ast.js'
import { astTaintScan } from './taint.js'
import { enrichHarnessFindings, scanPromptPoisoning, scanCapabilityMismatch } from './harness.js'

/** 语义扫描入口(taint + harness 专属 + poisoning + mismatch)。 */
export function semanticScan(content, relPath) {
  if (!CODE_EXT.test(relPath)) return []
  const ast = parseJavaScript(content)
  let findings = []
  if (ast !== null) {
    try {
      findings = astTaintScan(ast, content, relPath)
    } catch {
      findings = regexSemanticScan(content, relPath)
    }
  } else {
    findings = regexSemanticScan(content, relPath)
  }
  enrichHarnessFindings(findings, content)
  findings.push(...scanPromptPoisoning(content, relPath))
  findings.push(...scanCapabilityMismatch(content, relPath))
  return findings
}

// ─────────────────────────── 正则兜底版(旧行为,confidence: medium)───────────────────────────

const SINKS = [
  { names: ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork'], type: 'shell', ruleId: 'SEN-AGENT-001', severity: 'critical' },
  { names: ['readFile', 'readFileSync', 'createReadStream', 'openSync'], type: 'file-read', ruleId: 'SEN-AGENT-002', severity: 'high' },
  { names: ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream'], type: 'file-write', ruleId: 'SEN-AGENT-003', severity: 'high' },
  { names: ['fetch', 'axios', 'http.request', 'https.request', 'WebSocket', 'sendBeacon', 'net.connect', 'net.createConnection', 'dgram.createSocket'], type: 'network', ruleId: 'SEN-AGENT-004', severity: 'high' },
]

const SINK_NAMES = new Set(SINKS.flatMap((s) => s.names))

const MESSAGES = {
  'SEN-AGENT-001': '模型可控输入进入 shell 执行(execute(args) → exec/spawn)',
  'SEN-AGENT-002': '模型可控输入进入文件读取(execute(args) → readFile)',
  'SEN-AGENT-003': '模型可控输入进入文件写入(execute(args) → writeFile)',
  'SEN-AGENT-004': '模型可控输入进入网络请求目标(execute(args) → fetch/axios)',
}

const RECOMMENDATIONS = {
  'SEN-AGENT-001': '拒绝把模型输入直接拼进 shell 命令;用参数数组形式 spawn(cmd, [args]) 并做白名单校验。',
  'SEN-AGENT-002': '文件读取必须做 workspace containment(先 resolve 再校验在根目录内),否则模型可读取任意文件。',
  'SEN-AGENT-003': '文件写入必须做 workspace containment,并拒绝写入 HOME / 系统目录 / DSH profile。',
  'SEN-AGENT-004': '模型控制 URL 即 SSRF 面。限制协议(http/https)与目标(禁 localhost/内网/云元数据 169.254.169.254)。',
}

/** 粗略括号配对。 */
function matchBrace(content, openIdx, open = '{', close = '}') {
  let depth = 0
  let inStr = null
  let esc = false
  for (let i = openIdx; i < content.length; i += 1) {
    const ch = content[i]
    if (inStr) {
      if (esc) esc = false
      else if (ch === '\\') esc = true
      else if (ch === inStr) inStr = null
      continue
    }
    if (ch === '"' || ch === "'" || ch === '`') inStr = ch
    else if (ch === open) depth += 1
    else if (ch === close) {
      depth -= 1
      if (depth === 0) return i
    }
  }
  return -1
}

/** 收集 child_process 别名。 */
export function collectAliasesForRegex(content) {
  const aliases = new Map()
  const destructureRe = /\{([^{}]*)}\s*=\s*(?:require|await\s+import)\s*\(\s*['"](?:node:)?child_process['"]\s*\)/g
  let m
  while ((m = destructureRe.exec(content)) !== null) {
    for (const part of m[1].split(',')) {
      const t = part.trim()
      if (!t) continue
      const mm = /([A-Za-z_$][\w$]*)\s*(?::\s*([A-Za-z_$][\w$]*))?/.exec(t)
      if (mm) aliases.set(mm[2] ?? mm[1], mm[1])
    }
  }
  const importRe = /import\s*\{([^{}]*)}\s*from\s*['"](?:node:)?child_process['"]/g
  while ((m = importRe.exec(content)) !== null) {
    for (const part of m[1].split(',')) {
      const t = part.trim()
      const mm = /([A-Za-z_$][\w$]*)\s*(?:as\s+([A-Za-z_$][\w$]*))?/.exec(t)
      if (mm) aliases.set(mm[2] ?? mm[1], mm[1])
    }
  }
  const cpVarRe = /(?:const|let|var)\s+(cp|child_process)\s*=\s*require\s*\(\s*['"](?:node:)?child_process['"]\s*\)/g
  while ((m = cpVarRe.exec(content)) !== null) {
    for (const name of SINK_NAMES) aliases.set(`${m[1]}.${name}`, name)
  }
  return aliases
}

/** Escape every regular-expression metacharacter before interpolating a static alias. */
export function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/** 正则版语义扫描(解析失败时的兜底)。 */
export function regexSemanticScan(content, relPath) {
  const findings = []
  const fileLines = content.split('\n')
  const makeSnippet = (lineNo, max = 240) => {
    const t = (fileLines[lineNo - 1] ?? '').replace(/\s+/g, ' ').trim()
    return t.length <= max ? t : t.slice(0, max - 1) + '…'
  }

  const defineRe = /\bdefineTool\s*\(\s*\{/g
  let dm
  while ((dm = defineRe.exec(content)) !== null) {
    const regionEnd = matchBrace(content, dm.index + dm[0].length - 1)
    if (regionEnd < 0) continue
    const region = content.slice(dm.index, regionEnd + 1)
    // execute(args) / execute(args: { command: string })(TS 标注,edge-ts-tool)
    const execRe = /\b(?:async\s+)?execute\s*(?::\s*(?:async\s*)?)?\(\s*([A-Za-z_$][\w$]*)\s*(?::[^)]*)?\)\s*(?:=>\s*)?\{/g
    let em
    while ((em = execRe.exec(region)) !== null) {
      const bodyStart = em.index + em[0].length - 1
      const bodyEnd = matchBrace(region, bodyStart)
      if (bodyEnd < 0) continue
      const body = region.slice(bodyStart + 1, bodyEnd)
      const argName = em[1] ?? 'args'
      const aliases = collectAliasesForRegex(content)
      const beforeBody = content.slice(0, dm.index + bodyStart).split('\n')
      const fileLine = (bodyLine) => beforeBody.length + bodyLine - 1

      const tainted = new Set()
      const argRe = new RegExp(`\\b${argName}\\s*\\.\\s*([A-Za-z_$][\\w$]*)`, 'g')
      let am
      while ((am = argRe.exec(body)) !== null) tainted.add(`${argName}.${am[1]}`)
      const assignRe = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)/g
      const assigns = []
      let asm
      while ((asm = assignRe.exec(body)) !== null) assigns.push({ name: asm[1], expr: asm[2] })
      for (const a of assigns) if (a.expr.includes(`${argName}.`)) tainted.add(a.name)
      let changed = true
      while (changed) {
        changed = false
        for (const a of assigns) {
          if (tainted.has(a.name)) continue
          if (a.expr.trim().match(/^[A-Za-z_$][\w$]*$/) && tainted.has(a.expr.trim())) {
            tainted.add(a.name)
            changed = true
          }
        }
      }

      const aliasSinks = []
      for (const [alias, original] of aliases) {
        const sink = SINKS.find((s) => s.names.includes(original))
        if (sink) aliasSinks.push({ alias, sink })
      }
      const checkSink = (callee, sink, openParenIdx) => {
        const callEnd = matchBrace(body, openParenIdx, '(', ')')
        const argText = callEnd > 0 ? body.slice(openParenIdx + 1, callEnd) : ''
        const taintedHit = [...tainted].find((t) => {
          const short = t.split('.')[1]
          return argText.includes(t) || (argText.includes(short) && short.length > 2)
        })
        if (!taintedHit) return
        const lineNo = fileLine(body.slice(0, openParenIdx).split('\n').length)
        findings.push({
          ruleId: sink.ruleId,
          severity: sink.severity,
          category: 'agent',
          confidence: 'medium',
          message: MESSAGES[sink.ruleId],
          file: relPath,
          line: lineNo,
          snippet: makeSnippet(lineNo),
          recommendation: RECOMMENDATIONS[sink.ruleId],
          source: { type: 'tool-argument', name: taintedHit },
          sink: { type: sink.type, callee },
          flow: [taintedHit, `${callee}(...)`],
        })
      }
      for (const sink of SINKS) {
        const calleeRe = new RegExp(`\\b(${sink.names.join('|')})\\s*\\(`, 'g')
        let sm
        while ((sm = calleeRe.exec(body)) !== null) checkSink(sm[1], sink, sm.index + sm[0].length - 1)
      }
      for (const { alias, sink } of aliasSinks) {
        const aliasRe = new RegExp(`\\b${escapeRegExp(alias)}\\s*\\(`, 'g')
        let sm
        while ((sm = aliasRe.exec(body)) !== null) checkSink(alias, sink, sm.index + sm[0].length - 1)
      }
    }
  }
  return findings
}
