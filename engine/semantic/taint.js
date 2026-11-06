/**
 * AST 污点分析(Phase 5):source → propagation → sink。
 *
 * 检测流(confidence: high):
 *   SEN-AGENT-001/002/003/004  — defineTool execute(args) 内 args.* → shell/文件/网络
 *   SEN-TAINT-001 secret-to-network    — process.env.* 凭据 → 网络
 *   SEN-TAINT-002 workspace-to-network — readFile 结果 → 网络(潜在源码外传)
 *   SEN-TAINT-003 decode-to-exec       — base64/hex/URI 解码 → eval/Function/exec
 *   跨函数(同文件):本地函数参数传播,深度受限。
 */

import { walk, calleeName, staticStringOf, referencedIdentifiers, collectAliases, collectImports, unwrapExpression } from './ast.js'
import { normalizeHostname } from './harness.js'

const SINKS = [
  { names: ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork', 'eval', 'vm.runInNewContext', 'vm.runInThisContext', 'vm.runInContext'], type: 'shell', ruleId: 'SEN-AGENT-001', severity: 'critical' },
  { names: ['readFile', 'readFileSync', 'createReadStream', 'openSync'], type: 'file-read', ruleId: 'SEN-AGENT-002', severity: 'high' },
  { names: ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream'], type: 'file-write', ruleId: 'SEN-AGENT-003', severity: 'high' },
  { names: ['fetch', 'axios', 'http.request', 'https.request', 'WebSocket', 'sendBeacon', 'net.connect', 'net.createConnection', 'dgram.createSocket'], type: 'network', ruleId: 'SEN-AGENT-004', severity: 'high' },
]
const SINK_NAMES = new Set(SINKS.flatMap((s) => s.names))
const DECODERS = new Set(['atob', 'decodeURIComponent', 'unescape', 'String.fromCharCode'])
const READERS = new Set(['readFile', 'readFileSync', 'createReadStream', 'openSync'])
const ITERATION_METHODS = new Set(['forEach', 'map', 'flatMap', 'filter', 'some', 'every', 'find', 'reduce', 'reduceRight'])
const FUNCTION_TYPES = new Set(['FunctionExpression', 'ArrowFunctionExpression', 'FunctionDeclaration'])
const SECRET_ENV = /(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|AUTH)/i

/**
 * P1-3:裸 sink 必须真正绑定 import 才 high-confidence。
 * shell / file-read / file-write 需要 child_process / node:fs 绑定;
 * eval / Function / fetch 是 JS built-in / global,免绑定(§12.5/12.6)。
 * member 形态(cp.exec / fs.readFileSync / http.request)限定性足够,放行。
 */
const BINDING_REQUIRED_KINDS = new Set(['shell', 'file-read', 'file-write'])
const BUILTIN_NO_BINDING = new Set(['eval', 'Function', 'fetch'])
const BINDING_MODULES = ['child_process', 'node:child_process', 'fs', 'node:fs', 'node:fs/promises', 'fs/promises']

/** raw 调用名是否确认绑定到内置模块(imports/aliases)。 */
export function bindingConfirmsBuiltin(raw, { aliases, imports, cpVars } = {}) {
  if (BUILTIN_NO_BINDING.has(raw)) return true
  if (typeof raw === 'string' && raw.includes('.')) {
    // member 形态通常已足够限定;但 RegExp.prototype.exec 与 child_process.exec
    // 同名,`.exec` 必须证明 receiver 绑定到 child_process。
    if (raw.slice(raw.lastIndexOf('.') + 1) !== 'exec') return true
    const root = raw.slice(0, raw.lastIndexOf('.'))
    if (aliases?.has(raw)) return true
    const rootMod = imports?.get(root)
    if (typeof rootMod === 'string'
      && BINDING_MODULES.some((m) => rootMod === m || rootMod.startsWith(m + ':'))) return true
    return cpVars?.has(root) === true
  }
  if (aliases?.has(raw)) return true // import/require 解构绑定
  const mod = imports?.get(raw)
  if (typeof mod === 'string' && BINDING_MODULES.some((m) => mod === m || mod.startsWith(m + ':'))) return true
  return false
}

/**
 * 凭据专属受信端点(P1-1):只有"secret 名匹配该凭据 + 目标是该凭据的官方端点"
 * 才豁免 secret 外传判定。"host 属于大厂"不再直接豁免——攻击者可以控制
 * 任意 bucket / app / endpoint(如 evil-bucket.s3.amazonaws.com)。
 */
const CREDENTIAL_DESTINATIONS = [
  { pattern: /^OPENAI_.*(?:KEY|TOKEN)$/i, hosts: ['api.openai.com'] },
  { pattern: /^DEEPSEEK_.*(?:KEY|TOKEN)$/i, hosts: ['api.deepseek.com'] },
  { pattern: /^ANTHROPIC_.*(?:KEY|TOKEN)$/i, hosts: ['api.anthropic.com'] },
  { pattern: /^GITHUB_.*(?:TOKEN|KEY)$/i, hosts: ['api.github.com', 'github.com'] },
]

/** 从 env 源头名提取 secret 名:process.env.DEEPSEEK_API_KEY → 'DEEPSEEK_API_KEY'。 */
export function secretNameFrom(sourceName) {
  const m = /^process\.env\.([A-Za-z_$][\w$]*)/.exec(sourceName ?? '')
  return m ? m[1] : null
}

/** host 是否属于已知大厂域名(仅辅助 evidence,绝不直接豁免)。 */
export function isKnownProviderHost(host) {
  return /(?:^|\.)(?:deepseek\.com|openai\.com|anthropic\.com|github\.com|googleapis\.com|azure\.(?:com|net)|aws\.com|amazonaws\.com)$/i.test(host)
}

/** 凭据名 + URL 是否是该凭据的官方目标(唯一允许的豁免条件)。 */
export function isExpectedCredentialDestination(secretName, url) {
  if (!secretName || !url) return false
  let host
  try {
    host = normalizeHostname(new URL(url).hostname)
  } catch {
    return false
  }
  return CREDENTIAL_DESTINATIONS.some((d) => d.pattern.test(secretName) && d.hosts.includes(host))
}

const MESSAGES = {
  'SEN-AGENT-001': '模型可控输入进入 shell 执行(execute(args) → exec/spawn)',
  'SEN-AGENT-002': '模型可控输入进入文件读取(execute(args) → readFile)',
  'SEN-AGENT-003': '模型可控输入进入文件写入(execute(args) → writeFile)',
  'SEN-AGENT-004': '模型可控输入进入网络请求目标(execute(args) → fetch/axios)',
  'SEN-TAINT-001': '凭据(env)流向网络请求,存在外传风险',
  'SEN-TAINT-002': '文件读取结果流向网络请求,存在源码/数据外传风险',
  'SEN-TAINT-003': '解码后的内容流向动态执行,疑似混淆载荷',
  'SEN-TAINT-004': '文件读取结果进入 shell 执行,存在代码注入面(文件内容可能来自构建产物/外部输入)',
  'SEN-TAINT-005': '文件读取结果写入文件,常见于构建/复制场景;若源文件可变且内容进入运行路径,需确认来源可信',
}
const RECOMMENDATIONS = {
  'SEN-AGENT-001': '拒绝把模型输入直接拼进 shell 命令;用参数数组形式 spawn(cmd, [args]) 并做白名单校验。',
  'SEN-AGENT-002': '文件读取必须做 workspace containment,否则模型可读取任意文件。',
  'SEN-AGENT-003': '文件写入必须做 workspace containment,并拒绝写入 HOME / 系统目录 / DSH profile。',
  'SEN-AGENT-004': '模型控制 URL 即 SSRF 面。限制协议与目标(禁 localhost/内网/云元数据)。',
  'SEN-TAINT-001': '确认请求目标完全可信;凭据绝不应流向非官方端点。',
  'SEN-TAINT-002': '确认工作区内容不会随网络请求离开本机。',
  'SEN-TAINT-003': '解码内容必须人工复核;无文档说明的解码执行按恶意处理。',
  'SEN-TAINT-004': '确认喂给子进程的文件内容来源可信(仅构建产物/白名单路径);避免把可变外部文件拼入命令。',
  'SEN-TAINT-005': '确认复制的文件来源可信(仅构建产物/白名单路径),且不会把敏感文件写入可执行位置。',
}

/** 归一化 callee:应用别名与 cp 变量。 */
function resolveCallee(raw, aliases) {
  if (SINK_NAMES.has(raw)) return raw
  if (aliases.has(raw) && SINK_NAMES.has(aliases.get(raw))) return aliases.get(raw)
  // cp.exec / child_process.exec 形态
  const dot = raw.lastIndexOf('.')
  if (dot > 0) {
    const tail = raw.slice(dot + 1)
    if (SINK_NAMES.has(tail)) return tail
  }
  return null
}

function lineSnippet(content, node) {
  const line = content.slice(0, node.start).split('\n').length
  const text = (content.split('\n')[line - 1] ?? '').replace(/\s+/g, ' ').trim()
  return { line, snippet: text.length > 240 ? text.slice(0, 239) + '…' : text }
}

/** offset → 1-based 列号。 */
function columnOf(content, offset) {
  const lineStart = content.lastIndexOf('\n', Math.max(0, offset - 1)) + 1
  return offset - lineStart + 1
}

/** offset → 1-based 行号。 */
function lineOfOffset(content, offset) {
  return content.slice(0, offset).split('\n').length
}

/** 表达式是否为 env 凭据读取(process.env['API_KEY'] / process.env['OPEN'+'AI_API_KEY'] 等)。 */
function isSecretEnvRead(node) {
  if (node?.type !== 'MemberExpression') return false
  const obj = node.object
  if (calleeName(obj) !== 'process.env') return false
  const key = staticStringOf(node.property) ?? (node.property.type === 'Identifier' ? node.property.name : null)
  return key !== null && SECRET_ENV.test(key)
}

/** 表达式是否为解码调用:atob/decodeURIComponent/unescape/fromCharCode,或带 base64/hex 编码参数的 Buffer.from。 */
function isDecodeCall(node) {
  if (node?.type !== 'CallExpression') return false
  const raw = calleeName(node.callee)
  if (DECODERS.has(raw)) return true
  if (raw === 'Buffer.from') {
    const enc = staticStringOf(node.arguments[1])
    return enc === 'base64' || enc === 'base64url' || enc === 'hex'
  }
  return false
}

/** 表达式是否为文件读取调用。 */
function isReadCall(node) {
  if (node?.type !== 'CallExpression') return false
  const raw = calleeName(node.callee)
  if (READERS.has(raw)) return true
  if (raw && /^fs\./.test(raw)) return READERS.has(raw.split('.').pop())
  return false
}

/** 表达式标签:'env' | 'decode' | 'read' | 'args' | 'memory' | null(扫描整棵表达式树)。 */
function sourceTag(node, toolArgName) {
  if (!node) return null
  let tag = null
  const visit = (n) => {
    if (tag) return
    if (isSecretEnvRead(n)) { tag = 'env'; return }
    if (isDecodeCall(n)) { tag = 'decode'; return }
    if (isReadCall(n)) { tag = 'read'; return }
    if (n?.type === 'Identifier' && /^(conversation|memory|history|chatHistory|session|context)$/.test(n.name)) {
      tag = 'memory'
      return
    }
    if (toolArgName && n?.type === 'MemberExpression' && n.object.type === 'Identifier' && n.object.name === toolArgName) {
      tag = 'args'
    }
  }
  walk(node, visit)
  visit(node)
  return tag
}

/**
 * 表达式中的所有独立污点(P1-4 §13.2):同一参数可携带多个 source
 * (如 `args.url + '?token=' + process.env.API_KEY` → args + env),
 * 每个 source 独立成流,不再只取第一个。
 * @returns {Array<{tag: string, source: string}>}
 */
export function expressionTaints(node, toolArgName) {
  const out = []
  const seen = new Set()
  const push = (tag, source) => {
    const k = `${tag}|${source}`
    if (seen.has(k)) return
    seen.add(k)
    out.push({ tag, source })
  }
  if (!node) return out
  const visit = (n) => {
    if (isSecretEnvRead(n)) { push('env', calleeName(n) ?? 'process.env'); return }
    if (isDecodeCall(n)) { push('decode', calleeName(n.callee)?.split('.').slice(0, 2).join('.') ?? 'decode'); return }
    if (isReadCall(n)) { push('read', calleeName(n.callee) ?? 'read'); return }
    if (n?.type === 'Identifier' && /^(conversation|memory|history|chatHistory|session|context)$/.test(n.name)) { push('memory', n.name); return }
    if (toolArgName && n?.type === 'MemberExpression' && n.object.type === 'Identifier' && n.object.name === toolArgName) {
      push('args', calleeName(n) ?? 'direct')
    }
  }
  walk(node, visit)
  visit(node)
  return out
}

/** 参数树中的源头表达式名(args.command / process.env.X / Buffer.from / readFileSync 等)。 */
function sourceNameInArg(node, toolArgName) {
  let found = null
  walk(node, (n) => {
    if (found) return
    if (toolArgName && n.type === 'MemberExpression' && n.object.type === 'Identifier' && n.object.name === toolArgName) {
      found = calleeName(n) ?? 'direct'
    } else if (isSecretEnvRead(n)) {
      found = calleeName(n) ?? 'direct'
    } else if (isDecodeCall(n)) {
      const raw = calleeName(n.callee)
      found = raw ? raw.split('.').slice(0, 2).join('.') : 'direct'
    } else if (isReadCall(n)) {
      found = calleeName(n.callee) ?? 'direct'
    }
  })
  if (!found) {
    walk(node, (n) => {
      if (found) return
      if (n.type === 'Identifier' && /^(conversation|memory|history|chatHistory|session|context)$/.test(n.name)) found = n.name
    })
  }
  return found ?? 'direct'
}

function functionNodeForCallback(node) {
  const fn = unwrapExpression(node)
  if (!fn || !FUNCTION_TYPES.has(fn.type) || !fn.body) return null
  return {
    params: (fn.params ?? []).map((p) => firstParamName(p)).filter(Boolean),
    bodyNode: fn.body.type === 'BlockStatement' ? fn.body : fn.body,
    raw: fn,
  }
}

function firstParamName(param) {
  const target = unwrapExpression(param)
  if (!target) return null
  if (target.type === 'Identifier') return target.name
  if (target.type === 'AssignmentPattern') return firstParamName(target.left)
  if (target.type === 'RestElement') return firstParamName(target.argument)
  return null
}

/** Resolve member/new chains such as `new Runner().run` and `runner.run`. */
function callTargetName(callee) {
  const direct = calleeName(callee)
  if (direct) return direct
  const target = unwrapExpression(callee)
  if (target?.type !== 'MemberExpression') return null
  const object = unwrapExpression(target.object)
  if (object?.type !== 'NewExpression') return null
  const className = calleeName(object.callee)
  const prop = target.computed ? staticStringOf(target.property) : target.property?.name
  return className && prop ? `${className}.${prop}` : null
}

/** Conservative receiver taint for array iteration: literals and already-tainted bindings. */
function receiverTaint(node, taints, toolArgName) {
  const target = unwrapExpression(node)
  if (!target) return null
  if (target.type === 'ArrayExpression') {
    for (const element of target.elements ?? []) {
      if (!element) continue
      const direct = sourceTag(element, toolArgName)
      if (direct) return { tag: direct, source: sourceNameInArg(element, toolArgName) }
      for (const name of referencedIdentifiers(element)) {
        if (taints.has(name)) return taints.get(name)
      }
    }
    return null
  }
  if (target.type === 'Identifier' && taints.has(target.name)) return taints.get(target.name)
  const direct = sourceTag(target, toolArgName)
  if (direct) return { tag: direct, source: sourceNameInArg(target, toolArgName) }
  for (const name of referencedIdentifiers(target)) {
    if (taints.has(name)) return taints.get(name)
  }
  return null
}

/**
 * 单个函数体的污点分析。
 * @param {object} ctx {content, aliases, file}
 * @param {object} fn {bodyNode, params, toolArgName, localFunctions}
 * @param {number} depth
 */
function taintFunction(ctx, fn, depth = 0) {
  const { content, aliases } = ctx
  const findings = []
  const taints = new Map(ctx.paramTaints ?? new Map()) // 变量名 → {tag, source}
  const declarators = []
  const calls = []

  const bodyNode = fn.bodyNode.type === 'BlockStatement' ? fn.bodyNode : { type: 'BlockStatement', body: [fn.bodyNode] }
  walk(bodyNode, (node) => {
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier') declarators.push(node)
    if (node.type === 'VariableDeclarator' && node.id.type === 'ObjectPattern' && node.init) {
      // 解构污点(edge-destructure):const { command } = args → command 携带 args.command 污点
      const src = node.init.type === 'Identifier' && node.init.name === fn.toolArgName
        ? 'args' // 裸 toolArgName:const { command } = args
        : sourceTag(node.init, fn.toolArgName)
      if (src) {
        const base = sourceNameInArg(node.init, fn.toolArgName)
        for (const prop of node.id.properties) {
          const local = prop.value?.name
          if (!local || taints.has(local)) continue
          // 直接解构 toolArgName 时 source 精确到属性名(args.command)
          const precise = node.init.type === 'Identifier' && node.init.name === fn.toolArgName
            && prop.key?.name
            ? `${fn.toolArgName}.${prop.key.name}`
            : base
          taints.set(local, { tag: src, source: precise })
        }
      }
    }
    if (node.type === 'CallExpression') calls.push(node)
  })

  // 传播到不动点
  let changed = true
  let rounds = 0
  while (changed && rounds < 6) {
    changed = false
    rounds += 1
    for (const d of declarators) {
      const name = d.id.name
      if (taints.has(name)) continue
      const direct = sourceTag(d.init, fn.toolArgName)
      if (direct) {
        taints.set(name, { tag: direct, source: sourceNameInArg(d.init, fn.toolArgName) })
        changed = true
        continue
      }
      const refs = referencedIdentifiers(d.init)
      for (const r of refs) {
        if (taints.has(r)) {
          taints.set(name, { tag: taints.get(r).tag, source: taints.get(r).source })
          changed = true
          break
        }
      }
    }
  }

  const pushFinding = (ruleId, severity, category, sourceName, sinkName, sinkType, call) => {
    const { line, snippet } = lineSnippet(content, call)
    findings.push({
      ruleId, severity, category, confidence: 'high',
      message: MESSAGES[ruleId], file: ctx.file, line, snippet,
      recommendation: RECOMMENDATIONS[ruleId],
      source: { type: 'tool-argument', name: sourceName },
      sink: { type: sinkType, callee: sinkName },
      flow: [sourceName, `${sinkName}(...)`],
      // P1-5:semantic evidence 完整保留(供 fingerprint/SARIF/baseline/IDE)
      flowSteps: [sourceName, sinkName],
      functionName: 'execute',
      enclosingFunction: fn.toolArgName ? `execute(${fn.toolArgName})` : 'execute',
      ...(fn.toolName ? { toolName: fn.toolName } : {}),
      startColumn: columnOf(content, call.start),
      endLine: lineOfOffset(content, call.end),
      endColumn: columnOf(content, call.end),
    })
  }

  for (const call of calls) {
    const raw = calleeName(call.callee)
    if (!raw) continue
    const sinkName = resolveCallee(raw, aliases)
    if (!sinkName) continue
    const sink = SINKS.find((s) => s.names.includes(sinkName))
    if (!sink) continue

    // P1-3:bare sink 必须绑定 import(§12)——未绑定的同名本地函数不产生 high-confidence。
    if (BINDING_REQUIRED_KINDS.has(sink.type) && !bindingConfirmsBuiltin(raw, ctx)) continue

    // 参数污点:同一参数的所有独立 source(P1-4 §13.3,一个 arg → 多个 flow)
    let argTaints = []
    for (const arg of call.arguments) {
      argTaints = expressionTaints(arg, fn.toolArgName)
      if (argTaints.length > 0) break
      const refs = referencedIdentifiers(arg)
      for (const r of refs) {
        if (taints.has(r)) { // 外层传播 Map(变量名 → {tag, source})
          const t = taints.get(r)
          argTaints = [{ tag: t.tag, source: t.source }]
          break
        }
      }
      if (argTaints.length > 0) break
    }
    if (argTaints.length === 0) continue

    // 每个独立 taint 各走规则选择 → 独立 semantic flow(去重键含 source+sink)
    for (const t of argTaints) {
      let ruleId = sink.ruleId
      let severity = sink.severity
      let category = 'agent'
      if (t.tag === 'env' && sink.type === 'network') {
        const lineText = (content.split('\n')[lineSnippet(content, call).line - 1] ?? '')
        // P1-1:凭据专属豁免——secret 名匹配 + 官方端点才放行;大厂 host 只作 evidence。
        const secretName = secretNameFrom(t.source)
        const urlMatch = /https?:\/\/[^\s"'<>)]+/.exec(lineText)
        if (secretName && urlMatch && isExpectedCredentialDestination(secretName, urlMatch[0])) {
          continue // 该凭据的官方 API 目标:正常使用,不产生 critical
        }
        ruleId = 'SEN-TAINT-001'; severity = 'critical'; category = 'taint'
      }
      else if ((t.tag === 'read' || t.tag === 'memory') && sink.type === 'network') { ruleId = 'SEN-TAINT-002'; severity = 'high'; category = 'taint' }
      else if (t.tag === 'decode' && sink.type === 'shell') { ruleId = 'SEN-TAINT-003'; severity = 'critical'; category = 'taint' }
      else if (t.tag === 'read' && sink.type === 'shell') { ruleId = 'SEN-TAINT-004'; severity = 'high'; category = 'taint' }
      else if (t.tag === 'read' && sink.type === 'file-write') { ruleId = 'SEN-TAINT-005'; severity = 'medium'; category = 'taint' }
      pushFinding(ruleId, severity, category, t.source, sinkName, sink.type, call)
    }
  }

  const runSub = (entry, paramTaints) => {
    if (!entry || paramTaints.size === 0) return
    const sub = taintFunction({ ...ctx, paramTaints }, {
      bodyNode: entry.bodyNode,
      params: entry.params,
      toolArgName: fn.toolArgName,
      localFunctions: fn.localFunctions,
    }, depth + 1)
    for (const f of sub) {
      if (!findings.some((x) => x.ruleId === f.ruleId && x.line === f.line)) findings.push(f)
    }
  }

  // 已知 source 形态的回调 API:readFile(path, (err, data) => ...) 的 data 是 read 污点。
  // 只建模已存在的 READERS,不把未知回调当作 passthrough。
  if (depth < 2) {
    for (const call of calls) {
      const raw = callTargetName(call.callee) ?? calleeName(call.callee)
      if (!raw) continue
      const tail = raw.slice(raw.lastIndexOf('.') + 1)
      if (READERS.has(tail)) {
        const callbackArg = [...call.arguments].reverse().find((arg) => {
          const node = unwrapExpression(arg)
          return FUNCTION_TYPES.has(node?.type)
            || (node?.type === 'Identifier' && fn.localFunctions?.has(node.name))
        })
        if (!callbackArg) continue
        const target = unwrapExpression(callbackArg)
        const entry = FUNCTION_TYPES.has(target?.type)
          ? functionNodeForCallback(target)
          : fn.localFunctions?.get(target?.name)
        if (!entry || !entry.params[1]) continue
        runSub(entry, new Map([[entry.params[1], { tag: 'read', source: raw }]]))
        continue
      }

      const method = [...ITERATION_METHODS].find((name) => raw.endsWith(`.${name}`))
      if (!method) continue
      const callee = unwrapExpression(call.callee)
      if (callee?.type !== 'MemberExpression') continue
      const inherited = receiverTaint(callee.object, taints, fn.toolArgName)
      if (!inherited) continue
      const callbackArg = call.arguments[0]
      const target = unwrapExpression(callbackArg)
      const entry = FUNCTION_TYPES.has(target?.type)
        ? functionNodeForCallback(target)
        : fn.localFunctions?.get(target?.name)
      if (!entry) continue
      const seed = new Map()
      if (method === 'reduce' || method === 'reduceRight') {
        for (const param of entry.params.slice(0, 2)) seed.set(param, inherited)
      } else if (entry.params[0]) {
        seed.set(entry.params[0], inherited)
      }
      runSub(entry, seed)
    }
  }

  // 跨函数(同文件,深度受限):本地函数/对象方法/类方法调用,参数带污点 → 递归分析。
  if (depth < 1 && fn.localFunctions) {
    for (const call of calls) {
      const raw = callTargetName(call.callee)
      if (!raw || SINK_NAMES.has(resolveCallee(raw, aliases) ?? '')) continue // sink 已处理
      const localFn = fn.localFunctions.get(raw)
      if (!localFn) continue
      const paramTaints = new Map()
      localFn.params.forEach((p, i) => {
        const arg = call.arguments[i]
        if (!arg) return
        const t = sourceTag(arg, fn.toolArgName)
        if (t) {
          paramTaints.set(p, { tag: t, source: sourceNameInArg(arg, fn.toolArgName) })
          return
        }
        const refs = referencedIdentifiers(arg)
        for (const r of refs) {
          if (taints.has(r)) {
            paramTaints.set(p, { tag: taints.get(r).tag, source: taints.get(r).source })
            break
          }
        }
      })
      runSub(localFn, paramTaints)
    }
  }
  return findings
}

/**
 * AST 污点扫描入口。
 * @param {object} ast - acorn AST
 * @param {string} content
 * @param {string} relPath
 * @returns {Array} findings
 */
export function astTaintScan(ast, content, relPath) {
  // AST 绑定是主路径;正则别名只作为同一份源码的补充证据(不跨文件、不执行)。
  const aliases = collectAliases(content)
  const collected = collectImports(ast)
  for (const [local, original] of collected.aliases) {
    if (!aliases.has(local)) aliases.set(local, original)
  }
  const imports = collected.imports
  const cpVars = collected.cpVars
  const localFunctions = new Map()
  const classMethods = new Map()
  const instances = []
  const executeFns = []

  const functionEntry = (node) => {
    const target = unwrapExpression(node)
    if (!FUNCTION_TYPES.has(target?.type) || !target.body) return null
    return {
      params: (target.params ?? []).map((p) => firstParamName(p)).filter(Boolean),
      bodyNode: target.body.type === 'BlockStatement'
        ? target.body
        : { type: 'BlockStatement', body: [target.body] },
    }
  }
  const addObjectMethods = (base, object) => {
    for (const prop of object?.properties ?? []) {
      if (prop?.type !== 'Property' || prop.computed) continue
      const key = prop.key?.name ?? staticStringOf(prop.key)
      const entry = functionEntry(prop.value)
      if (key && entry) localFunctions.set(`${base}.${key}`, entry)
    }
  }

  walk(ast, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id) {
      const entry = functionEntry(node)
      if (entry) localFunctions.set(node.id.name, entry)
    }
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && node.init) {
      const init = unwrapExpression(node.init)
      const entry = functionEntry(init)
      if (entry) localFunctions.set(node.id.name, entry)
      if (init?.type === 'ObjectExpression') addObjectMethods(node.id.name, init)
      if (init?.type === 'NewExpression') {
        const className = calleeName(init.callee)
        if (className) instances.push({ local: node.id.name, className })
      }
    }
    if (node.type === 'ClassDeclaration' && node.id?.name) {
      const methods = new Map()
      for (const member of node.body?.body ?? []) {
        if (member.type !== 'MethodDefinition' || member.computed) continue
        const key = member.key?.name ?? staticStringOf(member.key)
        const entry = functionEntry(member.value)
        if (!key || !entry) continue
        methods.set(key, entry)
        localFunctions.set(`${node.id.name}.prototype.${key}`, entry)
        if (member.static) localFunctions.set(`${node.id.name}.${key}`, entry)
      }
      classMethods.set(node.id.name, methods)
    }
    if (node.type === 'AssignmentExpression') {
      const left = calleeName(node.left)
      const entry = functionEntry(node.right)
      if (left && entry && left.includes('.')) localFunctions.set(left, entry)
    }
    if (node.type === 'CallExpression' && calleeName(node.callee) === 'defineTool') {
      const obj = node.arguments[0]
      if (obj?.type === 'ObjectExpression') {
        let toolName = null
        for (const prop of obj.properties) {
          const key = prop.key?.name ?? staticStringOf(prop.key)
          if (key === 'name') toolName = staticStringOf(prop.value) ?? prop.value?.name ?? null
        }
        for (const prop of obj.properties) {
          const key = prop.key?.name ?? staticString(prop.key)
          if (key === 'execute' && (prop.value?.type === 'FunctionExpression' || prop.value?.type === 'ArrowFunctionExpression')) {
            executeFns.push({ fn: prop.value, toolName })
          }
        }
      }
    }
  })

  // 实例方法别名:`const runner = new Runner()` → runner.method 复用类方法摘要。
  for (const { local, className } of instances) {
    const methods = classMethods.get(className)
    if (!methods) continue
    for (const [method, entry] of methods) {
      localFunctions.set(`${local}.${method}`, entry)
      localFunctions.set(`${className}.${method}`, entry)
    }
  }

  const ctx = { content, aliases, imports, cpVars, file: relPath }
  const findings = []

  // 1) execute(args) 上下文(SEN-AGENT)
  for (const { fn, toolName } of executeFns) {
    const argName = fn.params[0]?.name ?? 'args'
    const hits = taintFunction({ ...ctx, paramTaints: new Map() }, {
      bodyNode: fn.body,
      params: fn.params.map((p) => p.name).filter(Boolean),
      toolArgName: argName,
      toolName,
      localFunctions,
    }, 0)
    for (const h of hits) findings.push(h)
  }

  // 2) 全文件通用流(SEN-TAINT):env/decode/read → sink
  const gHits = taintFunction({ ...ctx, paramTaints: new Map() }, {
    bodyNode: ast,
    params: [],
    localFunctions,
  }, 0)
  for (const h of gHits) {
    if (!findings.some((f) => f.ruleId === h.ruleId && f.line === h.line)) findings.push(h)
  }

  return findings
}
