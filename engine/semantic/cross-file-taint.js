/**
 * Bounded cross-file taint analysis built on the safe module graph.
 *
 * The first pass models the high-value DSH shape: a tool entry passes args.*
 * into an imported function, whose exported parameter reaches a dangerous
 * sink. Statically recovered dynamic import()/require() edges are followed
 * the same way. Unresolved graph failures are evidence of incomplete analysis;
 * dynamic targets that stayed warnings are not guessed.
 */

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  calleeName,
  collectImports,
  importDeclarationHasRuntimeBinding,
  parseSource,
  referencedIdentifiers,
  staticString,
  unwrapExpression,
  walk,
} from './ast.js'
import { namedBindingsFromObjectPattern, requireCallKind } from './static-specifier.js'
import { bindingConfirmsBuiltin } from './taint.js'

const SINKS = [
  { names: ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork'], type: 'shell', ruleId: 'SEN-AGENT-001', severity: 'critical', module: 'child_process' },
  { names: ['readFile', 'readFileSync', 'createReadStream', 'openSync'], type: 'file-read', ruleId: 'SEN-AGENT-002', severity: 'high', module: 'fs' },
  { names: ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream'], type: 'file-write', ruleId: 'SEN-AGENT-003', severity: 'high', module: 'fs' },
  { names: ['fetch', 'axios', 'WebSocket', 'sendBeacon'], type: 'network', ruleId: 'SEN-AGENT-004', severity: 'high', module: null },
]

const SINK_NAMES = new Set(SINKS.flatMap((sink) => sink.names))
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
  const returnType = '(?::\\s*[A-Za-z_$][\\w$.<>\\[\\]|& \\t]{0,80})?'
  const patterns = [
    new RegExp(`export\\s+(?:async\\s+)?function\\s+${escaped}\\s*(?:<[A-Za-z_$][\\w$,\\s|&.]{0,80}>)?\\s*\\(\\s*([A-Za-z_$][\\w$]*)[^)]*\\)\\s*${returnType}\\s*\\{`, 'm'),
    new RegExp(`(?:module\\s*\\.\\s*exports|exports)\\s*\\.\\s*${escaped}\\s*=\\s*(?:async\\s+)?function(?:\\s+[A-Za-z_$][\\w$]*)?\\s*\\(\\s*([A-Za-z_$][\\w$]*)[^)]*\\)\\s*${returnType}\\s*\\{`, 'm'),
  ]
  const match = patterns.map((pattern) => pattern.exec(content)).find(Boolean)
  if (match) {
    const open = match.index + match[0].length - 1
    const end = braceEnd(content, open)
    if (end < 0) return null
    return { param: match[1], body: content.slice(open + 1, end), start: match.index }
  }

  const arrow = new RegExp(`(?:module\\s*\\.\\s*exports|exports)\\s*\\.\\s*${escaped}\\s*=\\s*(?:async\\s+)?(?:\\(\\s*([A-Za-z_$][\\w$]*)[^)]*\\)\\s*${returnType}|([A-Za-z_$][\\w$]*))\\s*=>\\s*`, 'm').exec(content)
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

function dedupeBindings(bindings) {
  const seen = new Set()
  const out = []
  for (const binding of bindings ?? []) {
    if (!binding?.imported || !binding?.local) continue
    if (!/^[A-Za-z_$][\w$]*$/.test(binding.imported) || !/^[A-Za-z_$][\w$]*$/.test(binding.local)) continue
    const key = `${binding.imported}\0${binding.local}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({ imported: binding.imported, local: binding.local })
  }
  return out
}

function astBindingsForSpecifier(ast, specifier) {
  const out = []
  if (!ast || typeof specifier !== 'string') return out
  walk(ast, (node) => {
    if (node.type === 'ImportDeclaration') {
      if (!importDeclarationHasRuntimeBinding(node)) return
      if (staticString(node.source) !== specifier) return
      for (const spec of node.specifiers ?? []) {
        if (spec.importKind === 'type') continue
        if (spec.type === 'ImportSpecifier') out.push({ imported: staticString(spec.imported) ?? spec.imported.name, local: spec.local.name })
        else if (spec.type === 'ImportDefaultSpecifier') out.push({ imported: 'default', local: spec.local.name })
      }
      return
    }
    if (node.type === 'TSImportEqualsDeclaration') {
      if (node.importKind === 'type') return
      if (staticString(node.moduleReference?.expression) !== specifier) return
      if (node.id?.name) out.push({ imported: 'default', local: node.id.name })
      return
    }
    if (node.type !== 'VariableDeclarator' || !node.init) return
    const init = unwrapExpression(node.init)
    if (init?.type === 'CallExpression' && requireCallKind(init.callee) === 'require'
      && staticString(init.arguments?.[0]) === specifier) {
      if (node.id?.type === 'ObjectPattern') out.push(...namedBindingsFromObjectPattern(node.id))
      else if (node.id?.type === 'Identifier') out.push({ imported: 'default', local: node.id.name })
      return
    }
    // `const run = require('./runner').run`
    if (init?.type === 'MemberExpression' && node.id?.type === 'Identifier') {
      const object = unwrapExpression(init.object)
      if (object?.type === 'CallExpression' && requireCallKind(object.callee) === 'require'
        && staticString(object.arguments?.[0]) === specifier) {
        const imported = init.computed ? staticString(init.property) : init.property?.name
        if (typeof imported === 'string') out.push({ imported, local: node.id.name })
      }
    }
  })
  return out
}

function bindingsForEdge(content, edge, ast) {
  if (edge?.kind === 'static-require-resolve') return []
  // Dynamic edges already carry the exact binding from their call site. Using
  // unrelated static imports of the same specifier would contaminate the chain.
  if (Array.isArray(edge?.bindings)) {
    const fromEdge = dedupeBindings(edge.bindings)
    if (fromEdge.length > 0) return fromEdge
    if (edge.fromCall) return []
  }
  // Static import/export edges are re-read from the importer AST so type-only
  // bindings never become sources.
  const fromAst = astBindingsForSpecifier(ast, edge?.specifier)
  if (fromAst.length > 0) return dedupeBindings(fromAst)
  return dedupeBindings(importsForSpecifier(content, edge?.specifier))
}

function firstParamName(param) {
  const target = unwrapExpression(param)
  if (!target) return null
  if (target.type === 'Identifier') return target.name
  if (target.type === 'AssignmentPattern') return firstParamName(target.left)
  if (target.type === 'RestElement') return firstParamName(target.argument)
  return null
}

function functionEntry(node) {
  const fn = unwrapExpression(node)
  if (!fn) return null
  if (!['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(fn.type)) return null
  if (!fn.body) return null // TS overload signature
  const body = fn.body.type === 'BlockStatement'
    ? fn.body
    : { type: 'BlockStatement', body: [{ type: 'ExpressionStatement', expression: fn.body, start: fn.body.start, end: fn.body.end }] }
  return { param: firstParamName(fn.params?.[0]), body, start: fn.start }
}

function assignmentExportName(left) {
  const name = calleeName(left)
  if (name === 'module.exports') return 'default'
  if (name?.startsWith('module.exports.')) return name.slice('module.exports.'.length)
  if (name?.startsWith('exports.')) return name.slice('exports.'.length)
  return null
}

function indexExports(ast) {
  const functions = new Map()
  const refs = new Map()
  const addFunction = (name, init) => {
    const entry = functionEntry(init)
    if (name && entry) functions.set(name, entry)
  }
  const addRef = (exported, value) => {
    if (!exported) return
    refs.set(exported, value)
  }
  const addDeclaration = (decl) => {
    if (!decl) return
    if (decl.type === 'FunctionDeclaration' && decl.id?.name) {
      addFunction(decl.id.name, decl)
      addRef(decl.id.name, { local: decl.id.name })
    } else if (decl.type === 'VariableDeclaration') {
      for (const item of decl.declarations ?? []) {
        if (item.id?.type !== 'Identifier') continue
        addFunction(item.id.name, item.init)
        addRef(item.id.name, { local: item.id.name })
      }
    }
  }
  const addAssignedValue = (exported, value) => {
    const target = unwrapExpression(value)
    if (!target) return
    if (['FunctionExpression', 'ArrowFunctionExpression', 'FunctionDeclaration'].includes(target.type)) {
      addRef(exported, { node: target })
      return
    }
    if (target.type === 'Identifier') {
      addRef(exported, { local: target.name })
      return
    }
    if (exported === 'default' && target.type === 'ObjectExpression') {
      for (const prop of target.properties ?? []) {
        if (prop?.type !== 'Property' || prop.computed) continue
        const key = prop.key?.name ?? staticString(prop.key)
        if (!key) continue
        const valueNode = unwrapExpression(prop.value)
        if (valueNode?.type === 'Identifier') addRef(key, { local: valueNode.name })
        else if (['FunctionExpression', 'ArrowFunctionExpression'].includes(valueNode?.type)) addRef(key, { node: valueNode })
      }
    }
  }

  for (const statement of ast?.body ?? []) {
    if (statement.type === 'ExportNamedDeclaration') {
      if (statement.exportKind === 'type') continue
      const decl = statement.declaration
      addDeclaration(decl)
      for (const spec of statement.specifiers ?? []) {
        if (spec.exportKind === 'type') continue
        const exported = spec.exported?.name ?? staticString(spec.exported)
        const local = spec.local?.name ?? staticString(spec.local)
        if (exported && local) addRef(exported, { local })
      }
      continue
    }
    if (statement.type === 'ExportDefaultDeclaration') {
      const decl = unwrapExpression(statement.declaration)
      if (decl?.type === 'FunctionDeclaration' && decl.id?.name) {
        addFunction(decl.id.name, decl)
        addRef('default', { local: decl.id.name })
      } else if (['FunctionExpression', 'ArrowFunctionExpression'].includes(decl?.type)) {
        addRef('default', { node: decl })
      } else if (decl?.type === 'Identifier') {
        addRef('default', { local: decl.name })
      }
      continue
    }
    if (statement.type === 'TSExportAssignment') {
      const expr = unwrapExpression(statement.expression)
      if (expr?.type === 'Identifier') addRef('default', { local: expr.name })
      continue
    }
    if (statement.type === 'FunctionDeclaration' && statement.id?.name) {
      addFunction(statement.id.name, statement)
      continue
    }
    if (statement.type === 'VariableDeclaration') {
      for (const item of statement.declarations ?? []) {
        if (item.id?.type === 'Identifier') addFunction(item.id.name, item.init)
      }
      continue
    }
    if (statement.type !== 'ExpressionStatement' || statement.expression?.type !== 'AssignmentExpression') continue
    const exported = assignmentExportName(statement.expression.left)
    if (!exported) continue
    addAssignedValue(exported, statement.expression.right)
  }

  return { functions, refs }
}

function exportedFunctionAst(ast, exportedName) {
  const { functions, refs } = indexExports(ast)
  const ref = refs.get(exportedName)
  if (ref?.local) return functions.get(ref.local) ?? null
  if (ref?.node) return functionEntry(ref.node)
  return null
}

function referencesAny(node, names) {
  if (names.size === 0) return false
  for (const name of referencedIdentifiers(node)) if (names.has(name)) return true
  return false
}

function resolveCrossFileSink(raw, collected) {
  if (SINK_NAMES.has(raw)) return raw
  if (collected.aliases.has(raw) && SINK_NAMES.has(collected.aliases.get(raw))) return collected.aliases.get(raw)
  const tail = raw.slice(raw.lastIndexOf('.') + 1)
  return SINK_NAMES.has(tail) ? tail : null
}

function boundSinkAst(body, param, ast) {
  if (!param) return null
  const collected = collectImports(ast)
  const tainted = new Set([param])
  let changed = true
  let rounds = 0
  while (changed && rounds < 5) {
    changed = false
    rounds += 1
    walk(body, (node) => {
      if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier' && node.init
        && !tainted.has(node.id.name) && referencesAny(node.init, tainted)) {
        // 跨文件层只做保守传播:不穿过未知函数调用(可能是 sanitizer,也可能是
        // resolve() 之类的路径归一化)。直接赋值/模板/字符串拼接仍然传播。
        const init = unwrapExpression(node.init)
        if (init?.type !== 'CallExpression' && init?.type !== 'NewExpression') {
          tainted.add(node.id.name)
          changed = true
        }
      }
      if (node.type === 'AssignmentExpression' && node.left?.type === 'Identifier'
        && !tainted.has(node.left.name) && referencesAny(node.right, tainted)) {
        tainted.add(node.left.name)
        changed = true
      }
    })
  }

  let hit = null
  walk(body, (node) => {
    if (hit || node.type !== 'CallExpression') return
    const raw = calleeName(node.callee)
    if (!raw) return
    const sinkName = resolveCrossFileSink(raw, collected)
    if (!sinkName) return
    const sink = SINKS.find((item) => item.names.includes(sinkName))
    if (!sink) return
    if (sink.module && !bindingConfirmsBuiltin(raw, collected)) return
    if (!(node.arguments ?? []).some((arg) => referencesAny(arg, tainted))) return
    hit = { ...sink, callee: sinkName, start: node.start }
  })
  return hit
}

function sourceInvocationAst(ast, local) {
  let found = null
  walk(ast, (node) => {
    if (found || node.type !== 'CallExpression' || calleeName(node.callee) !== local) return
    for (const arg of node.arguments ?? []) {
      let source = null
      walk(arg, (child) => {
        if (source) return
        if (child.type === 'MemberExpression' && child.object?.type === 'Identifier' && child.object.name === 'args') {
          source = calleeName(child)
        }
      })
      if (source) {
        found = { source, start: node.start }
        return
      }
    }
  })
  return found
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
      const content = readFileSync(join(root, node.path), 'utf8')
      sourceByPath.set(node.path, { content, ast: parseSource(content, node.path).ast })
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
    for (const binding of bindingsForEdge(from.content, edge, from.ast)) {
      const invocation = from.ast ? sourceInvocationAst(from.ast, binding.local) : sourceInvocation(from.content, binding.local)
      if (!invocation) continue
      const fallbackName = binding.imported === 'default' ? binding.local : binding.imported
      let exported = to.ast ? exportedFunctionAst(to.ast, binding.imported === 'default' ? 'default' : binding.imported) : null
      if (!exported && to.ast && binding.imported === 'default') exported = exportedFunctionAst(to.ast, binding.local)
      if (!exported && !to.ast) exported = exportedFunction(to.content, fallbackName)
      if (!exported) continue
      const sink = to.ast
        ? boundSinkAst(exported.body, exported.param, to.ast)
        : boundSink(exported.body, exported.param, to.content)
      if (!sink) continue
      const chain = {
        source: invocation.source,
        modulePath: [edge.from, edge.to],
        functionPath: [`${binding.local}(...)`, `${binding.imported}(${exported.param})`],
        sink: sink.callee,
      }
      const attackChainId = chainId(chain)
      const sinkOffset = Number.isInteger(sink.start) ? sink.start : exported.start
      const sinkLine = (to.content.slice(0, sinkOffset).match(/\n/g) ?? []).length + 1
      const sinkSnippet = (to.content.split('\n')[sinkLine - 1] ?? '').replace(/\s+/g, ' ').trim()
      attackChains.push({ id: attackChainId, ...chain, confidence: 'high' })
      findings.push({
        ruleId: sink.ruleId,
        severity: sink.severity,
        category: 'agent',
        confidence: 'high',
        message: `跨文件污点流:${invocation.source} → ${sink.callee}`,
        file: edge.to,
        line: sinkLine,
        snippet: sinkSnippet.length > 240 ? `${sinkSnippet.slice(0, 239)}…` : sinkSnippet,
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
