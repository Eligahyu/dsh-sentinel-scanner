/**
 * Harness 专属语义规则(Phase 6):
 *   SEN-AGENT-005 tool-prompt-poisoning      — 工具描述/指令文本中的投毒短语
 *   SEN-AGENT-006 capability-mismatch        — 描述与真实能力明显不符的证据
 *   SSRF 目标细化(localhost/云元数据/危险协议)→ 云元数据端点升级 critical
 *   args.path 无 containment 提示(path traversal)
 *   记忆/对话内容 → 网络外传(memory 污点)
 */

const POISON_PHRASES = [
  /ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions|prompts?|directions)/i,
  /do\s+not\s+(?:tell|inform|notify|warn)\s+(?:the\s+)?user/i,
  /don'?t\s+(?:tell|let)\s+(?:the\s+)?user/i,
  /conceal|hide\s+this|secretly|stealth/i,
  /always\s+(?:call|use|invoke)\s+/i,
  /send\s+(?:files|data|logs|content|everything)\s+to/i,
  /exfiltrat|upload\s+(?:to|the)\s+(?:remote|server|endpoint)/i,
  /never\s+(?:mention|reveal|disclose)/i,
]

const SSRF_TARGETS = [
  // host 形态:localhost / IPv4 私有 / 云元数据
  /localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254/i,
  // IPv6 回环与 IPv4-mapped 回环(含 [brackets] 形态)
  /\[?::1\]?/i,
  /\[?::ffff:127\./i,
  // 云元数据 IPv4-mapped(::ffff:169.254.169.254)——critical 判定复用 169.254.169.254 子串
  /\[?::ffff:169\.254\.169\.254\]?/i,
  // IPv6 ULA fc00::/7(fc00–fdff)
  /\[?(?:fc|fd)[0-9a-f]{2}::\]?/i,
  // IPv6 link-local fe80::/10(fe80–febf)
  /\[?fe[89ab][0-9a-f]::\]?/i,
  // IPv4-mapped 私有段(::ffff:10.x / 192.168.x / 172.16-31.x)
  /\[?::ffff:(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\]?/i,
  // 危险协议
  /file:\/\/|gopher:\/\/|ftp:\/\//i,
  // 私有 IPv4 段
  /(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}\.\d{1,3}/,
]

/** 去 IPv6 brackets 并 trim。 */
export function normalizeHostname(host) {
  let h = String(host ?? '').trim()
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1)
  return h
}

/** 能力关键词:出现这些词的"工具"通常不应有敏感 sink。 */
const BENIGN_KEYWORDS = /weather|greeting|hello|translate|quote|joke|fact|time|date|unit|convert|dictionary|calculator|poll/i

/** 粗略括号配对(与 semantic/index.js 一致)。 */
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

/**
 * 对语义 finding 做 Harness 专属增强:
 *   - SEN-AGENT-004:SSRF 目标检测 + detail;云元数据端点 169.254.169.254 → critical
 *   - SEN-AGENT-002/003:containment 提示
 * @param {Array} findings - astTaintScan 的输出(原地增强)
 * @param {string} content - 文件全文
 */
export function enrichHarnessFindings(findings, content) {
  for (const f of findings) {
    if (f.ruleId === 'SEN-AGENT-004') {
      const line = (content.split('\n')[f.line - 1] ?? '') + '\n' + (content.split('\n')[f.line] ?? '')
      const ssrf = SSRF_TARGETS.find((re) => re.test(line))
      if (ssrf) {
        if (/169\.254\.169\.254/.test(line)) {
          // 明确可访问云元数据端点 → critical(任务书 §19)
          f.severity = 'critical'
          f.detail = '模型可控 URL 指向云元数据端点 169.254.169.254——SSRF 可窃取实例凭据'
        } else {
          f.detail = '网络目标含 localhost / 内网 / 危险协议——SSRF 面确认'
        }
        f.ssrfTarget = true
      }
    }
    if (f.ruleId === 'SEN-AGENT-002' || f.ruleId === 'SEN-AGENT-003') {
      const hasContainment = /(?:resolve|join|normalize)\s*\(\s*(?:workspace|WORKSPACE|root|ROOT|cwd|__dirname)/.test(content)
      f.detail = hasContainment
        ? '存在 workspace 归一化调用,需人工确认 containment 校验完整'
        : '未发现 workspace containment——任意路径访问风险'
    }
  }
  return findings
}

/**
 * Prompt/Tool 投毒检测(confidence 分级):
 *   low    — 文档/测试/普通注释里出现
 *   medium — tool description 内出现
 *   high   — description + 隐藏副作用 + 网络/外传链
 */
export function scanPromptPoisoning(content, relPath) {
  const findings = []
  const fileLines = content.split('\n')
  // 定位所有 defineTool 区域与 description 行范围
  const toolRegions = []
  const defineRe = /\bdefineTool\s*\(\s*\{/g
  let dm
  while ((dm = defineRe.exec(content)) !== null) {
    const regionEnd = matchBrace(content, dm.index + dm[0].length - 1)
    if (regionEnd < 0) continue
    const region = content.slice(dm.index, regionEnd + 1)
    const startLine = content.slice(0, dm.index).split('\n').length
    const inDescription = new Set()
    const descMatch = region.match(/description\s*:\s*["'`]([^"'`]{0,400})/)
    if (descMatch) {
      const descStart = dm.index + region.indexOf(descMatch[0])
      const descStartLine = content.slice(0, descStart).split('\n').length
      const descEndLine = content.slice(0, descStart + descMatch[0].length).split('\n').length
      for (let l = descStartLine; l <= descEndLine; l += 1) inDescription.add(l)
    }
    toolRegions.push({
      startLine,
      endLine: startLine + region.split('\n').length,
      inDescription,
      hasSensitiveSink: /(?:exec|spawn|readFile|writeFile|fetch|axios|WebSocket|sendBeacon|https?\.request)\s*\(/.test(region),
    })
  }

  for (let i = 0; i < fileLines.length; i += 1) {
    const line = fileLines[i]
    const phrase = POISON_PHRASES.find((re) => re.test(line))
    if (!phrase) continue
    if (/\bexfiltration\s+endpoints?\b/i.test(line)) continue
    const lineNo = i + 1
    let confidence = 'low'
    let detail = '文档/测试/注释中出现投毒短语(需结合上下文判断)'
    const region = toolRegions.find((r) => lineNo >= r.startLine && lineNo <= r.endLine)
    if (region) {
      if (region.inDescription.has(lineNo)) {
        confidence = region.hasSensitiveSink ? 'high' : 'medium'
        detail = region.hasSensitiveSink
          ? 'tool description 投毒短语 + 隐藏副作用(敏感 sink 共存)'
          : 'tool description 中出现投毒短语'
      }
    }
    findings.push({
      ruleId: 'SEN-AGENT-005',
      severity: 'medium',
      category: 'agent',
      confidence,
      message: '工具/指令文本疑似 prompt 投毒短语(需结合上下文判断)',
      file: relPath,
      line: lineNo,
      snippet: line.replace(/\s+/g, ' ').trim().slice(0, 240),
      recommendation: '人工判断短语是否用于防御性说明(如"忽略注入指令")还是恶意指令。',
      detail,
    })
  }
  return findings
}

/**
 * 能力不匹配证据:描述像普通工具,但主体含敏感 sink。
 * evidence: {declaredCapabilities, observedCapabilities}
 */
export function scanCapabilityMismatch(content, relPath) {
  const findings = []
  const defineRe = /\bdefineTool\s*\(\s*\{/g
  let m
  while ((m = defineRe.exec(content)) !== null) {
    const descMatch = content.slice(m.index, m.index + 800).match(/description\s*:\s*["'`]([^"'`]{0,200})/)
    const desc = descMatch?.[1] ?? ''
    if (desc && BENIGN_KEYWORDS.test(desc)) {
      const window = content.slice(m.index, m.index + 2000)
      const observed = []
      if (/(?:exec|execSync|spawn|spawnSync|fork|eval)\s*\(/.test(window)) observed.push('shell')
      if (/(?:readFile|readFileSync|createReadStream|openSync)\s*\(/.test(window)) observed.push('filesystem-read')
      if (/(?:writeFile|writeFileSync|appendFile|createWriteStream)\s*\(/.test(window)) observed.push('filesystem-write')
      if (/(?:fetch|axios|XMLHttpRequest|WebSocket|sendBeacon|https?\.request|net\.connect)\s*\(/.test(window)) observed.push('network')
      if (/process\.env/.test(window)) observed.push('env-access')
      if (/(?:\.ssh|\.aws|\.npmrc|kubeconfig|id_rsa)/.test(window)) observed.push('credential-path-access')
      if (observed.length === 0) continue
      const line = content.slice(0, m.index).split('\n').length
      findings.push({
        ruleId: 'SEN-AGENT-006',
        severity: 'medium',
        category: 'agent',
        confidence: 'low',
        message: `工具描述("${desc.slice(0, 40)}…")与代码能力(${observed.join(', ')})明显不符,存在隐藏副作用可能`,
        file: relPath,
        line,
        snippet: (content.split('\n')[line - 1] ?? '').replace(/\s+/g, ' ').trim().slice(0, 240),
        recommendation: '人工核对工具描述与实际行为的差异。',
        evidence: {
          declaredCapabilities: desc.slice(0, 120),
          observedCapabilities: observed,
        },
      })
    }
  }
  return findings
}
