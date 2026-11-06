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
  staticStringOf,
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
    if (!/^(?:[A-Za-z_$][\w$]*|\*)$/.test(binding.imported) || !/^[A-Za-z_$][\w$]*$/.test(binding.local)) continue
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
        else if (spec.type === 'ImportNamespaceSpecifier') out.push({ imported: '*', local: spec.local.name })
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
  return {
    param: firstParamName(fn.params?.[0]),
    params: (fn.params ?? []).map((param) => firstParamName(param)).filter(Boolean),
    body,
    start: fn.start,
    name: fn.id?.name ?? null,
  }
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
  const values = new Map()
  const methods = new Map()
  const classMethods = new Map()
  const moduleBindings = new Set()
  const addFunction = (name, init) => {
    const entry = functionEntry(init)
    if (name && entry) functions.set(name, entry)
  }
  const addRef = (exported, value) => {
    if (!exported) return
    refs.set(exported, value)
  }
  const addObjectMethods = (base, object) => {
    for (const prop of object?.properties ?? []) {
      if (prop?.type !== 'Property' || prop.computed) continue
      const key = prop.key?.name ?? staticString(prop.key)
      const entry = functionEntry(prop.value)
      if (key && entry) methods.set(`${base}.${key}`, entry)
    }
  }
  const addClassMethods = (base, classNode) => {
    const byName = new Map()
    for (const member of classNode?.body?.body ?? []) {
      if (member.type !== 'MethodDefinition' || member.computed) continue
      const key = member.key?.name ?? staticString(member.key)
      const entry = functionEntry(member.value)
      if (!key || !entry) continue
      byName.set(key, entry)
      methods.set(`${base}.prototype.${key}`, entry)
      if (member.static) methods.set(`${base}.${key}`, entry)
    }
    if (byName.size > 0) classMethods.set(base, byName)
  }
  const recordValue = (name, init) => {
    if (!name || !init) return
    values.set(name, init)
    addFunction(name, init)
    const target = unwrapExpression(init)
    if (target?.type === 'ObjectExpression') addObjectMethods(name, target)
    if (target?.type === 'ClassExpression') addClassMethods(name, target)
  }
  const addDeclaration = (decl) => {
    if (!decl) return
    if (decl.type === 'FunctionDeclaration' && decl.id?.name) {
      addFunction(decl.id.name, decl)
      addRef(decl.id.name, { local: decl.id.name })
    } else if (decl.type === 'ClassDeclaration' && decl.id?.name) {
      addClassMethods(decl.id.name, decl)
      values.set(decl.id.name, decl)
      addRef(decl.id.name, { local: decl.id.name })
    } else if (decl.type === 'VariableDeclaration') {
      for (const item of decl.declarations ?? []) {
        if (item.id?.type !== 'Identifier') continue
        recordValue(item.id.name, item.init)
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
    if (target.type === 'ObjectExpression') {
      addObjectMethods(exported, target)
      for (const prop of target.properties ?? []) {
        if (prop?.type !== 'Property' || prop.computed) continue
        const key = prop.key?.name ?? staticString(prop.key)
        if (!key) continue
        const valueNode = unwrapExpression(prop.value)
        if (valueNode?.type === 'Identifier') addRef(key, { local: valueNode.name })
        else if (['FunctionExpression', 'ArrowFunctionExpression'].includes(valueNode?.type)) addRef(key, { node: valueNode })
      }
      return
    }
    if (target.type === 'ClassExpression') addClassMethods(exported, target)
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
      } else if (decl?.type === 'ObjectExpression') {
        addAssignedValue('default', decl)
      } else if (decl?.type === 'ClassDeclaration' || decl?.type === 'ClassExpression') {
        addClassMethods('default', decl)
        addRef('default', { node: decl })
      }
      continue
    }
    if (statement.type === 'TSExportAssignment') {
      const expr = unwrapExpression(statement.expression)
      if (expr?.type === 'Identifier') addRef('default', { local: expr.name })
      else addAssignedValue('default', expr)
      continue
    }
    if (statement.type === 'FunctionDeclaration' && statement.id?.name) {
      moduleBindings.add(statement.id.name)
      addFunction(statement.id.name, statement)
      continue
    }
    if (statement.type === 'ClassDeclaration' && statement.id?.name) {
      moduleBindings.add(statement.id.name)
      values.set(statement.id.name, statement)
      addClassMethods(statement.id.name, statement)
      continue
    }
    if (statement.type === 'VariableDeclaration') {
      for (const item of statement.declarations ?? []) {
        if (item.id?.type !== 'Identifier') continue
        moduleBindings.add(item.id.name)
        recordValue(item.id.name, item.init)
      }
      continue
    }
    if (statement.type !== 'ExpressionStatement' || statement.expression?.type !== 'AssignmentExpression') continue
    const expression = statement.expression
    const leftName = calleeName(expression.left)
    const assignedEntry = functionEntry(expression.right)
    if (leftName && assignedEntry) {
      methods.set(leftName, assignedEntry)
      functions.set(leftName, assignedEntry)
    }
    const exported = assignmentExportName(expression.left)
    if (!exported) continue
    addAssignedValue(exported, expression.right)
  }

  return { functions, refs, values, methods, classMethods, moduleBindings }
}

function resolveExportEntry(index, path, { instance = false } = {}) {
  if (!index || !Array.isArray(path) || path.length === 0) return null
  const [head, ...members] = path
  if (members.length === 0) {
    const ref = index.refs.get(head)
    if (ref?.local) {
      const entry = index.functions.get(ref.local)
      if (entry) return entry
    }
    if (ref?.node) {
      const entry = functionEntry(ref.node)
      if (entry) return entry
    }
    return index.functions.get(head) ?? null
  }
  const ref = index.refs.get(head)
  const base = ref?.local ?? head
  const memberPath = members.join('.')
  const candidates = []
  if (instance) candidates.push(`${base}.prototype.${memberPath}`)
  candidates.push(`${base}.${memberPath}`, `${base}.prototype.${memberPath}`, `${head}.${memberPath}`, `${head}.prototype.${memberPath}`)
  for (const candidate of candidates) {
    const entry = index.methods.get(candidate) ?? index.functions.get(candidate)
    if (entry) return entry
  }
  return null
}

function resolveCrossFileSink(raw, collected) {
  if (SINK_NAMES.has(raw)) return raw
  if (collected.aliases.has(raw) && SINK_NAMES.has(collected.aliases.get(raw))) return collected.aliases.get(raw)
  const tail = raw.slice(raw.lastIndexOf('.') + 1)
  return SINK_NAMES.has(tail) ? tail : null
}

const FUNCTION_NODE_TYPES = new Set(['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'])
const ITERATION_METHODS = new Set(['forEach', 'map', 'flatMap', 'filter', 'some', 'every', 'find', 'reduce', 'reduceRight'])
const READER_METHODS = new Set(['readFile', 'readFileSync', 'createReadStream', 'openSync'])
const DECODER_METHODS = new Set(['atob', 'decodeURIComponent', 'unescape', 'String.fromCharCode'])
const SECRET_ENV = /(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|AUTH)/i

function isFunctionNode(node) {
  return FUNCTION_NODE_TYPES.has(node?.type)
}

function functionEntryFromNode(node, name = null) {
  const fn = unwrapExpression(node)
  if (!isFunctionNode(fn) || !fn.body) return null
  const body = fn.body.type === 'BlockStatement'
    ? fn.body
    : { type: 'BlockStatement', body: [{ type: 'ExpressionStatement', expression: fn.body, start: fn.body.start, end: fn.body.end }] }
  return {
    param: firstParamName(fn.params?.[0]),
    params: (fn.params ?? []).map((param) => firstParamName(param)).filter(Boolean),
    body,
    start: fn.start,
    name: name ?? fn.id?.name ?? null,
  }
}

function isSecretEnvRead(node) {
  if (node?.type !== 'MemberExpression') return false
  if (calleeName(node.object) !== 'process.env') return false
  const key = staticStringOf(node.property) ?? (node.property?.type === 'Identifier' ? node.property.name : null)
  return key !== null && SECRET_ENV.test(key)
}

function sourceCallTag(node) {
  const raw = calleeName(node?.callee)
  if (!raw) return null
  const tail = raw.slice(raw.lastIndexOf('.') + 1)
  if (READER_METHODS.has(tail)) return { tag: 'read', source: raw }
  if (DECODER_METHODS.has(tail)) return { tag: 'decode', source: raw }
  if (raw === 'Buffer.from') {
    const encoding = staticStringOf(node.arguments?.[1])
    if (encoding === 'base64' || encoding === 'base64url' || encoding === 'hex') {
      return { tag: 'decode', source: raw }
    }
  }
  return null
}

/**
 * Conservative taint for an expression. It deliberately refuses to walk into
 * unknown calls/new expressions: such a call may sanitize or rewrite the value.
 * Only the already-modeled source-shaped calls (readFile/decode/env) can create
 * a new taint tag.
 */
function expressionTaint(node, taints, toolArgName = 'args') {
  const target = unwrapExpression(node)
  if (!target) return null
  if (target.type === 'ChainExpression') return expressionTaint(target.expression, taints, toolArgName)
  if (target.type === 'Identifier') return taints.get(target.name) ?? null
  if (target.type === 'MemberExpression') {
    if (isSecretEnvRead(target)) return { tag: 'env', source: calleeName(target) ?? 'process.env' }
    const objectName = target.object?.type === 'Identifier' ? target.object.name : null
    if (objectName && objectName === toolArgName) {
      return { tag: 'args', source: calleeName(target) ?? toolArgName }
    }
    if (target.object?.type === 'Identifier' && taints.has(target.object.name)) return taints.get(target.object.name)
    return expressionTaint(target.object, taints, toolArgName)
  }
  if (target.type === 'CallExpression') return sourceCallTag(target)
  if (target.type === 'NewExpression') return null
  if (target.type === 'ArrayExpression') {
    for (const element of target.elements ?? []) {
      const taint = expressionTaint(element, taints, toolArgName)
      if (taint) return taint
    }
    return null
  }
  if (target.type === 'ObjectExpression') {
    for (const prop of target.properties ?? []) {
      if (prop?.type === 'SpreadElement') {
        const taint = expressionTaint(prop.argument, taints, toolArgName)
        if (taint) return taint
      } else if (prop && prop.type === 'Property') {
        const taint = expressionTaint(prop.value, taints, toolArgName)
        if (taint) return taint
      }
    }
    return null
  }
  if (target.type === 'TemplateLiteral') {
    for (const expression of target.expressions ?? []) {
      const taint = expressionTaint(expression, taints, toolArgName)
      if (taint) return taint
    }
    return null
  }
  if (target.type === 'BinaryExpression' || target.type === 'LogicalExpression') {
    return expressionTaint(target.left, taints, toolArgName) ?? expressionTaint(target.right, taints, toolArgName)
  }
  if (target.type === 'ConditionalExpression') {
    return expressionTaint(target.consequent, taints, toolArgName) ?? expressionTaint(target.alternate, taints, toolArgName)
  }
  if (target.type === 'SequenceExpression') {
    for (let i = (target.expressions ?? []).length - 1; i >= 0; i -= 1) {
      const taint = expressionTaint(target.expressions[i], taints, toolArgName)
      if (taint) return taint
    }
    return null
  }
  if (target.type === 'AssignmentExpression') return expressionTaint(target.right, taints, toolArgName)
  if (target.type === 'AwaitExpression' || target.type === 'YieldExpression'
    || target.type === 'UnaryExpression' || target.type === 'UpdateExpression') {
    return expressionTaint(target.argument, taints, toolArgName)
  }
  if (target.type === 'SpreadElement') return expressionTaint(target.argument, taints, toolArgName)
  return null
}

function rootIdentifier(node) {
  let current = unwrapExpression(node)
  while (current?.type === 'MemberExpression') current = unwrapExpression(current.object)
  if (current?.type === 'Identifier') return current.name
  if (current?.type === 'NewExpression') {
    const ctor = callTargetParts(current.callee)
    return ctor?.path?.length === 0 ? ctor.root : null
  }
  return null
}

function callTargetParts(callee) {
  const target = unwrapExpression(callee)
  if (!target) return null
  if (target.type === 'Identifier') return { root: target.name, path: [], instance: false }
  if (target.type !== 'MemberExpression') return null
  const path = []
  let current = target
  while (current?.type === 'MemberExpression') {
    const property = current.computed ? staticStringOf(current.property) : current.property?.name
    if (typeof property !== 'string') {
      return { root: rootIdentifier(current.object), path: null, instance: false, unresolved: true }
    }
    path.unshift(property)
    current = unwrapExpression(current.object)
  }
  if (current?.type === 'Identifier') return { root: current.name, path, instance: false }
  if (current?.type === 'NewExpression') {
    const ctor = callTargetParts(current.callee)
    if (ctor && ctor.path?.length === 0 && ctor.root) return { root: ctor.root, path, instance: true }
  }
  return null
}

function collectTaintedLocals(ast) {
  const taints = new Map()
  let changed = true
  let rounds = 0
  while (changed && rounds < 6) {
    changed = false
    rounds += 1
    walk(ast, (node) => {
      if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier' && node.init) {
        if (taints.has(node.id.name)) return
        const taint = expressionTaint(node.init, taints)
        if (taint) {
          taints.set(node.id.name, taint)
          changed = true
        }
      }
      if (node.type === 'AssignmentExpression' && node.left?.type === 'Identifier') {
        if (taints.has(node.left.name)) return
        const taint = expressionTaint(node.right, taints)
        if (taint) {
          taints.set(node.left.name, taint)
          changed = true
        }
      }
    })
  }
  return taints
}

function collectInstances(ast, bindingLocal) {
  const instances = new Map()
  walk(ast, (node) => {
    if (node.type !== 'VariableDeclarator' || node.id?.type !== 'Identifier' || !node.init) return
    const init = unwrapExpression(node.init)
    if (init?.type !== 'NewExpression') return
    const parts = callTargetParts(init.callee)
    if (!parts || parts.root !== bindingLocal || parts.path === null) return
    instances.set(node.id.name, { path: parts.path })
  })
  return instances
}

function collectInvocationsForBinding(ast, binding, fileTaints) {
  const instances = collectInstances(ast, binding.local)
  const localFunctions = collectLocalFunctions(ast)
  const invocations = []
  const basePath = binding.imported === '*' ? [] : [binding.imported]
  walk(ast, (node) => {
    if (node.type !== 'CallExpression') return
    const parts = callTargetParts(node.callee)
    if (!parts) return
    let targetPath
    let instance = false
    if (parts.root === binding.local) {
      targetPath = parts.path === null ? null : [...basePath, ...parts.path]
      instance = parts.instance
    } else if (parts.root && instances.has(parts.root)) {
      targetPath = parts.path === null
        ? null
        : [...basePath, ...instances.get(parts.root).path, ...parts.path]
      instance = true
    } else {
      return
    }
    const argTaints = new Map()
    const callbacks = new Map()
    for (let index = 0; index < (node.arguments ?? []).length; index += 1) {
      const arg = node.arguments[index]
      const taint = expressionTaint(arg, fileTaints)
      if (taint) argTaints.set(index, taint)
      const value = unwrapExpression(arg)
      if (isFunctionNode(value)) {
        const entry = functionEntryFromNode(value)
        if (entry) callbacks.set(index, entry)
      } else if (value?.type === 'Identifier' && localFunctions.has(value.name)) {
        callbacks.set(index, localFunctions.get(value.name))
      }
    }
    invocations.push({
      call: node,
      targetPath,
      instance,
      argTaints,
      callbacks,
      start: node.start,
    })
  })
  return invocations
}

function collectLocalFunctions(ast) {
  const functions = new Map()
  walk(ast, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id?.name) {
      const entry = functionEntryFromNode(node, node.id.name)
      if (entry) functions.set(node.id.name, entry)
    }
    if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier'
      && (node.init?.type === 'FunctionExpression' || node.init?.type === 'ArrowFunctionExpression')) {
      const entry = functionEntryFromNode(node.init, node.id.name)
      if (entry) functions.set(node.id.name, entry)
    }
    if (node.type === 'AssignmentExpression') {
      const left = calleeName(node.left)
      const entry = functionEntryFromNode(node.right, left)
      if (left && entry) functions.set(left, entry)
    }
  })
  return functions
}

function localNamesOf(entry) {
  const names = new Set(entry.params)
  walk(entry.body, (node) => {
    if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier') names.add(node.id.name)
    if (node.type === 'FunctionDeclaration' && node.id?.name) names.add(node.id.name)
    if (node.type === 'ClassDeclaration' && node.id?.name) names.add(node.id.name)
  })
  return names
}

function mergeFlow(target, sub, prefix) {
  for (const hit of sub.hits) {
    target.hits.push({ ...hit, trace: prefix ? [prefix, ...(hit.trace ?? [])] : hit.trace })
  }
  target.callbacks.push(...sub.callbacks)
  target.closureWrites.push(...sub.closureWrites)
  target.coverage.push(...sub.coverage)
}

function analyzeFunctionFlow(entry, seedTaints, ctx, options = {}) {
  const depth = options.depth ?? 0
  const taints = new Map(seedTaints)
  const hits = []
  const callbacks = []
  const closureWrites = []
  const coverage = []
  const declarators = []
  const assignments = []
  const calls = []
  walk(entry.body, (node) => {
    if (node.type === 'VariableDeclarator') declarators.push(node)
    if (node.type === 'AssignmentExpression') assignments.push(node)
    if (node.type === 'CallExpression') calls.push(node)
  })
  const localNames = localNamesOf(entry)
  const localFunctions = collectLocalFunctions(entry.body)
  const callbackLookup = new Map(options.callbackScope ?? [])
  entry.params.forEach((param, index) => callbackLookup.set(param, { paramIndex: index }))

  let changed = true
  let rounds = 0
  while (changed && rounds < 6) {
    changed = false
    rounds += 1
    for (const declarator of declarators) {
      if (declarator.id?.type === 'Identifier' && declarator.init) {
        if (taints.has(declarator.id.name)) continue
        const taint = expressionTaint(declarator.init, taints, ctx.toolArgName ?? 'args')
        if (taint) {
          taints.set(declarator.id.name, taint)
          changed = true
        }
      } else if (declarator.id?.type === 'ObjectPattern' && declarator.init) {
        const taint = expressionTaint(declarator.init, taints, ctx.toolArgName ?? 'args')
        if (!taint) continue
        for (const prop of declarator.id.properties ?? []) {
          const name = prop.value?.name
          if (name && !taints.has(name)) {
            taints.set(name, taint)
            changed = true
          }
        }
      }
    }
    for (const assignment of assignments) {
      if (assignment.left?.type !== 'Identifier') continue
      const taint = expressionTaint(assignment.right, taints, ctx.toolArgName ?? 'args')
      if (!taint) continue
      const name = assignment.left.name
      if (ctx.moduleBindings?.has(name) && !localNames.has(name)) {
        closureWrites.push({ name, taint })
      }
      if (!taints.has(name)) {
        taints.set(name, taint)
        changed = true
      }
    }
  }

  const callbackEntryFor = (argNode) => {
    const value = unwrapExpression(argNode)
    if (isFunctionNode(value)) return functionEntryFromNode(value)
    if (value?.type === 'Identifier') {
      return localFunctions.get(value.name) ?? ctx.index?.functions?.get(value.name) ?? null
    }
    return null
  }

  for (const call of calls) {
    const raw = calleeName(call.callee)
    const tail = raw ? raw.slice(raw.lastIndexOf('.') + 1) : null

    // A function parameter invoked with tainted data is a callback bridge.
    const callbackBinding = raw ? callbackLookup.get(raw) : null
    if (callbackBinding) {
      for (let index = 0; index < (call.arguments ?? []).length; index += 1) {
        const taint = expressionTaint(call.arguments[index], taints, ctx.toolArgName ?? 'args')
        if (taint) {
          callbacks.push({ paramIndex: callbackBinding.paramIndex, argIndex: index, taint, label: `${raw}(...)` })
        }
      }
    }

    // Existing source-shaped APIs feed their callback's data parameter. This is
    // not a generic passthrough: only READERS/decoders already modeled by taint.js.
    const sourceTag = sourceCallTag(call)
    if (sourceTag) {
      const callbackArg = [...(call.arguments ?? [])].reverse().find((arg) => callbackEntryFor(arg))
      if (callbackArg) {
        const value = unwrapExpression(callbackArg)
        const bound = value?.type === 'Identifier' ? callbackLookup.get(value.name) : null
        if (bound) {
          callbacks.push({ paramIndex: bound.paramIndex, argIndex: 1, taint: sourceTag, label: `${raw}(...)` })
        } else {
          const cbEntry = callbackEntryFor(callbackArg)
          if (cbEntry?.params[1]) {
            const sub = analyzeFunctionFlow(cbEntry, new Map([[cbEntry.params[1], sourceTag]]), ctx, {
              depth: depth + 1,
              callbackScope: callbackLookup,
            })
            mergeFlow({ hits, callbacks, closureWrites, coverage }, sub, `${raw}(...)`)
          }
        }
      }
    }

    const method = tail && ITERATION_METHODS.has(tail) ? tail : null
    if (method) {
      const callee = unwrapExpression(call.callee)
      if (callee?.type === 'MemberExpression') {
        const inherited = expressionTaint(callee.object, taints, ctx.toolArgName ?? 'args')
        if (inherited) {
          const callbackArg = call.arguments?.[0]
          const value = unwrapExpression(callbackArg)
          const bound = value?.type === 'Identifier' ? callbackLookup.get(value.name) : null
          if (bound) {
            callbacks.push({ paramIndex: bound.paramIndex, argIndex: 0, taint: inherited, label: `${raw}(...)` })
          } else {
            const cbEntry = callbackEntryFor(callbackArg)
            if (cbEntry?.params[0]) {
              const seed = new Map([[cbEntry.params[0], inherited]])
              if (method === 'reduce' || method === 'reduceRight') {
                for (const param of cbEntry.params.slice(0, 2)) seed.set(param, inherited)
              }
              const sub = analyzeFunctionFlow(cbEntry, seed, ctx, {
                depth: depth + 1,
                callbackScope: callbackLookup,
              })
              mergeFlow({ hits, callbacks, closureWrites, coverage }, sub, `${raw}(...)`)
            }
          }
        }
      }
    }

    // Same-file helper calls are followed only when the callee binding is known.
    if (depth < 2 && raw && !callbackLookup.has(raw)) {
      const local = localFunctions.get(raw) ?? ctx.index?.functions?.get(raw)
      if (local && local !== entry) {
        const paramTaints = new Map()
        local.params.forEach((param, index) => {
          const arg = call.arguments?.[index]
          if (!arg) return
          const taint = expressionTaint(arg, taints, ctx.toolArgName ?? 'args')
          if (taint) paramTaints.set(param, taint)
        })
        if (paramTaints.size > 0) {
          const sub = analyzeFunctionFlow(local, paramTaints, ctx, {
            depth: depth + 1,
            callbackScope: callbackLookup,
          })
          mergeFlow({ hits, callbacks, closureWrites, coverage }, sub, `${raw}(...)`)
        }
      }
    }

    const sinkRaw = calleeName(call.callee) ?? callTargetName(call.callee)
    if (!sinkRaw) continue
    const sinkName = resolveCrossFileSink(sinkRaw, ctx.collected)
    if (!sinkName) continue
    const sink = SINKS.find((item) => item.names.includes(sinkName))
    if (!sink) continue
    if (sink.module && !bindingConfirmsBuiltin(sinkRaw, ctx.collected)) continue
    const taintedArg = (call.arguments ?? [])
      .map((arg) => expressionTaint(arg, taints, ctx.toolArgName ?? 'args'))
      .find(Boolean)
    if (!taintedArg) continue
    hits.push({ sink: { ...sink, callee: sinkName, start: call.start }, taint: taintedArg, call })
  }

  return { hits, callbacks, closureWrites, coverage }
}

function callTargetName(callee) {
  const direct = calleeName(callee)
  if (direct) return direct
  const parts = callTargetParts(callee)
  if (!parts?.root || !parts.path?.length) return null
  return [parts.root, ...parts.path].join('.')
}

function taintRule(taint, sink) {
  if (taint.tag === 'env' && sink.type === 'network') return { ruleId: 'SEN-TAINT-001', severity: 'critical', category: 'taint' }
  if ((taint.tag === 'read' || taint.tag === 'memory') && sink.type === 'network') return { ruleId: 'SEN-TAINT-002', severity: 'high', category: 'taint' }
  if (taint.tag === 'decode' && sink.type === 'shell') return { ruleId: 'SEN-TAINT-003', severity: 'critical', category: 'taint' }
  if (taint.tag === 'read' && sink.type === 'shell') return { ruleId: 'SEN-TAINT-004', severity: 'high', category: 'taint' }
  if (taint.tag === 'read' && sink.type === 'file-write') return { ruleId: 'SEN-TAINT-005', severity: 'medium', category: 'taint' }
  return { ruleId: sink.ruleId, severity: sink.severity, category: 'agent' }
}

function snippetAt(content, offset) {
  const line = (content.slice(0, offset).match(/\n/g) ?? []).length + 1
  return (content.split('\n')[line - 1] ?? '').replace(/\s+/g, ' ').trim()
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
  const coverageSkips = []
  const seenFindings = new Set()
  const seenSkips = new Set()
  if (!graph?.complete || (graph?.failures?.length ?? 0) > 0) {
    failures.push({ reason: 'module-graph-incomplete', details: graph?.failures ?? [] })
  }
  const sourceByPath = new Map()
  for (const node of graph?.nodes ?? []) {
    try {
      const content = readFileSync(join(root, node.path), 'utf8')
      const ast = parseSource(content, node.path).ast
      const index = ast ? indexExports(ast) : null
      sourceByPath.set(node.path, {
        path: node.path,
        content,
        ast,
        index,
        collected: ast ? collectImports(ast) : { imports: new Map(), aliases: new Map(), cpVars: new Set() },
        taints: ast ? collectTaintedLocals(ast) : new Map(),
        moduleBindings: new Set(index?.moduleBindings ?? []),
      })
    } catch (error) {
      failures.push({ path: node.path, reason: 'read-error', detail: error?.code ?? error?.message })
    }
  }

  const addSkip = (skip) => {
    const key = `${skip.reason}|${skip.path}|${skip.start ?? ''}|${skip.member ?? ''}`
    if (seenSkips.has(key)) return
    seenSkips.add(key)
    coverageSkips.push({ stage: 'cross-file', ...skip })
  }

  const addHit = ({ fromPath, toPath, source, sinkHit, binding, entry, trace, sinkFile }) => {
    const sinkOffset = Number.isInteger(sinkHit.sink.start) ? sinkHit.sink.start : entry.start
    const sinkLine = (sinkFile.content.slice(0, sinkOffset).match(/\n/g) ?? []).length + 1
    const sinkSnippet = snippetAt(sinkFile.content, sinkOffset)
    const rule = taintRule(sinkHit.taint, sinkHit.sink)
    const flowSteps = [
      source,
      `${binding.imported}(${(entry.params ?? []).join(', ')})`,
      ...(trace ?? []),
      sinkHit.sink.callee,
    ]
    const dedupeKey = `${fromPath}|${toPath}|${rule.ruleId}|${sinkFile.path}|${sinkLine}|${sinkHit.sink.callee}|${source}`
    if (seenFindings.has(dedupeKey)) return
    seenFindings.add(dedupeKey)
    const chain = {
      source,
      modulePath: [fromPath, toPath],
      functionPath: [`${binding.local}(...)`, `${binding.imported}(${entry.param ?? (entry.params ?? [])[0] ?? ''})`],
      sink: sinkHit.sink.callee,
    }
    const attackChainId = chainId(chain)
    attackChains.push({ id: attackChainId, ...chain, confidence: 'high' })
    findings.push({
      ruleId: rule.ruleId,
      severity: rule.severity,
      category: rule.category,
      confidence: 'high',
      message: `跨文件污点流:${source} → ${sinkHit.sink.callee}`,
      file: sinkFile.path,
      line: sinkLine,
      snippet: sinkSnippet.length > 240 ? `${sinkSnippet.slice(0, 239)}…` : sinkSnippet,
      recommendation: sinkHit.sink.type === 'shell'
        ? '跨文件调用链仍接收模型输入;对工具输入做白名单校验并避免 shell 解释。'
        : '跨文件调用链必须限制目标与路径,并验证数据不会越权流出。',
      source: { type: sinkHit.taint.tag === 'args' ? 'tool-argument' : sinkHit.taint.tag, name: source },
      sink: { type: sinkHit.sink.type, callee: sinkHit.sink.callee },
      flow: [source, `${binding.local}(...)`, `${sinkHit.sink.callee}(...)`],
      flowSteps,
      modulePath: [fromPath, toPath],
      crossFile: true,
      attackChainId,
    })
  }

  // Build invocation contexts from the module graph. Static import/require
  // bindings may resolve to a function, an exported object method, or a class
  // instance method. Unprovable receivers stay warnings and never become edges.
  const invocations = []
  for (const edge of graph?.edges ?? []) {
    if (maxDepth < 1) {
      failures.push({ from: edge.from, to: edge.to, reason: 'depth-limit' })
      continue
    }
    const from = sourceByPath.get(edge.from)
    const to = sourceByPath.get(edge.to)
    if (!from || !to) continue
    const bindings = bindingsForEdge(from.content, edge, from.ast)
    for (const binding of bindings) {
      if (!from.ast || !to.ast) {
        // Parser fallback keeps the original conservative text-level behavior.
        const invocation = sourceInvocation(from.content, binding.local)
        if (!invocation) continue
        const fallbackName = binding.imported === 'default' ? binding.local : binding.imported
        const exported = exportedFunction(to.content, fallbackName)
        if (!exported) continue
        const sink = boundSink(exported.body, exported.param, to.content)
        if (!sink) continue
        const rule = { ruleId: sink.ruleId, severity: sink.severity }
        const sinkOffset = Number.isInteger(sink.start) ? sink.start : exported.start
        const sinkLine = (to.content.slice(0, sinkOffset).match(/\n/g) ?? []).length + 1
        const sinkSnippet = snippetAt(to.content, sinkOffset)
        const chain = {
          source: invocation.source,
          modulePath: [edge.from, edge.to],
          functionPath: [`${binding.local}(...)`, `${binding.imported}(${exported.param})`],
          sink: sink.callee,
        }
        const attackChainId = chainId(chain)
        const key = `${edge.from}|${edge.to}|${rule.ruleId}|${edge.to}|${sinkLine}|${sink.callee}|${invocation.source}`
        if (!seenFindings.has(key)) {
          seenFindings.add(key)
          attackChains.push({ id: attackChainId, ...chain, confidence: 'high' })
          findings.push({
            ruleId: rule.ruleId,
            severity: rule.severity,
            category: 'agent',
            confidence: 'high',
            message: `跨文件污点流:${invocation.source} → ${sink.callee}`,
            file: edge.to,
            line: sinkLine,
            snippet: sinkSnippet.length > 240 ? `${sinkSnippet.slice(0, 239)}…` : sinkSnippet,
            recommendation: '跨文件调用链必须限制目标与路径,并验证数据不会越权流出。',
            source: { type: 'tool-argument', name: invocation.source },
            sink: { type: sink.type, callee: sink.callee },
            flow: [invocation.source, `${binding.local}(...)`, `${sink.callee}(...)`],
            flowSteps: [invocation.source, `${binding.imported}(${exported.param})`, sink.callee],
            modulePath: [edge.from, edge.to],
            crossFile: true,
            attackChainId,
          })
        }
        continue
      }
      for (const invocation of collectInvocationsForBinding(from.ast, binding, from.taints)) {
        if (invocation.targetPath === null) {
          if (invocation.argTaints.size > 0) {
            addSkip({
              reason: 'cross-file-method-unresolved',
              path: edge.from,
              member: binding.local,
              start: invocation.start,
            })
          }
          continue
        }
        const entry = resolveExportEntry(to.index, invocation.targetPath, { instance: invocation.instance })
        if (!entry) {
          if (invocation.targetPath.length > 1 && invocation.argTaints.size > 0) {
            addSkip({
              reason: 'cross-file-method-unresolved',
              path: edge.from,
              member: invocation.targetPath.join('.'),
              start: invocation.start,
            })
          }
          continue
        }
        invocations.push({ ...invocation, edge, binding, from, to, entry })
      }
    }
  }

  const moduleState = new Map()
  for (let round = 0; round < 3; round += 1) {
    let changed = false
    for (const invocation of invocations) {
      const key = `${invocation.edge.to}\0${invocation.edge.from}`
      const saved = moduleState.get(key) ?? new Map()
      const seed = new Map(saved)
      for (const [index, taint] of invocation.argTaints) {
        const param = invocation.entry.params?.[index]
        if (param) seed.set(param, taint)
      }
      if (seed.size === 0 && invocation.callbacks.size === 0) continue
      const flow = analyzeFunctionFlow(invocation.entry, seed, {
        content: invocation.to.content,
        ast: invocation.to.ast,
        index: invocation.to.index,
        collected: invocation.to.collected,
        moduleBindings: invocation.to.moduleBindings,
        file: invocation.edge.to,
      }, { depth: 0 })

      for (const write of flow.closureWrites) {
        if (!saved.has(write.name)) {
          saved.set(write.name, write.taint)
          changed = true
        }
      }
      if (saved.size > 0) moduleState.set(key, saved)

      for (const hit of flow.hits) {
        const source = hit.taint.source
        addHit({
          fromPath: invocation.edge.from,
          toPath: invocation.edge.to,
          source,
          sinkHit: hit,
          binding: invocation.binding,
          entry: invocation.entry,
          trace: hit.trace,
          sinkFile: invocation.to,
        })
      }

      for (const callback of flow.callbacks) {
        const cbEntry = invocation.callbacks.get(callback.paramIndex)
        if (!cbEntry) {
          addSkip({
            reason: 'cross-file-callback-unresolved',
            path: invocation.edge.from,
            member: invocation.binding.local,
            start: invocation.start,
          })
          continue
        }
        const callbackParam = cbEntry.params[callback.argIndex]
        if (!callbackParam) {
          addSkip({
            reason: 'cross-file-callback-unresolved',
            path: invocation.edge.from,
            member: invocation.binding.local,
            start: invocation.start,
          })
          continue
        }
        const callbackFlow = analyzeFunctionFlow(cbEntry, new Map([[callbackParam, callback.taint]]), {
          content: invocation.from.content,
          ast: invocation.from.ast,
          index: invocation.from.index,
          collected: invocation.from.collected,
          moduleBindings: invocation.from.moduleBindings,
          file: invocation.edge.from,
        }, { depth: 0 })
        for (const hit of callbackFlow.hits) {
          addHit({
            fromPath: invocation.edge.from,
            toPath: invocation.edge.to,
            source: hit.taint.source,
            sinkHit: { ...hit, trace: [...(callback.trace ?? []), callback.label, ...(hit.trace ?? [])] },
            binding: invocation.binding,
            entry: invocation.entry,
            trace: [callback.label, ...(hit.trace ?? [])],
            sinkFile: invocation.from,
          })
        }
      }
    }
    if (!changed) break
  }

  return {
    findings,
    attackChains,
    reachability: attackChains.map((x) => ({ id: x.id, path: x.modulePath, reachable: true })),
    coverageSkips,
    failures,
    complete: failures.length === 0,
  }
}
