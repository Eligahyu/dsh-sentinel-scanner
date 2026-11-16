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
  exportDeclarationHasRuntimeBinding,
  importDeclarationHasRuntimeBinding,
  parseSource,
  referencedIdentifiers,
  staticString,
  staticStringOf,
  unwrapExpression,
  walk,
} from './ast.js'
import { namedBindingsFromObjectPattern, requireCallKind } from './static-specifier.js'
import { applyAwaitImportBindings, bindingConfirmsBuiltin, fulfillmentNames, valueProducingReadTag } from './taint.js'

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
  const expressionBody = fn.body.type === 'BlockStatement' ? null : fn.body
  const body = expressionBody
    ? { type: 'BlockStatement', body: [{ type: 'ExpressionStatement', expression: fn.body, start: fn.body.start, end: fn.body.end }] }
    : fn.body
  return {
    param: firstParamName(fn.params?.[0]),
    params: (fn.params ?? []).map((param) => firstParamName(param)).filter(Boolean),
    paramNodes: fn.params ?? [],
    body,
    expressionBody,
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
  const reexports = new Map()
  const exportStars = []
  const recordReexport = (exported, imported, specifier, start) => {
    if (!exported || !imported || !specifier) return
    const list = reexports.get(exported) ?? []
    list.push({ specifier, imported, start })
    reexports.set(exported, list)
  }
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
      if (statement.source) {
        if (!exportDeclarationHasRuntimeBinding(statement)) continue
        const specifier = staticString(statement.source)
        for (const spec of statement.specifiers ?? []) {
          if (spec.exportKind === 'type') continue
          recordReexport(
            spec.exported?.name ?? staticString(spec.exported),
            spec.local?.name ?? staticString(spec.local),
            specifier,
            statement.source.start ?? statement.start,
          )
        }
        continue
      }
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
    if (statement.type === 'ExportAllDeclaration') {
      if (!exportDeclarationHasRuntimeBinding(statement)) continue
      const specifier = staticString(statement.source)
      if (!specifier) continue
      if (statement.exported) {
        recordReexport(
          statement.exported.name ?? staticString(statement.exported),
          '*',
          specifier,
          statement.source?.start ?? statement.start,
        )
      } else {
        exportStars.push({ specifier, start: statement.source?.start ?? statement.start })
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

  return { functions, refs, values, methods, classMethods, moduleBindings, reexports, exportStars }
}

function targetsForSpecifier(sourceByPath, graph, fromPath, specifier) {
  const targets = []
  for (const edge of graph?.edges ?? []) {
    if (edge.from !== fromPath || edge.specifier !== specifier) continue
    if (!sourceByPath.has(edge.to) || targets.includes(edge.to)) continue
    targets.push(edge.to)
  }
  return targets
}

/**
 * Follow a static re-export to the module that actually defines the export.
 * A local declaration wins. `export *` names that resolve to more than one
 * concrete function are ambiguous and are not guessed.
 */
function resolveReexport(sourceByPath, graph, filePath, exportPath, options = {}, depth = 0, seen = new Set()) {
  if (!filePath || depth > 4 || !Array.isArray(exportPath) || exportPath.length === 0) return { status: 'missing' }
  const key = `${filePath}\0${exportPath.join('.')}\0${options.instance ? '1' : '0'}`
  if (seen.has(key)) return { status: 'missing' }
  seen.add(key)
  const file = sourceByPath.get(filePath)
  if (!file?.index) return { status: 'missing' }
  const direct = resolveExportEntry(file.index, exportPath, options)
  if (direct) return { status: 'found', file, entry: direct, chain: [filePath] }

  const [head, ...members] = exportPath
  const named = file.index.reexports?.get(head) ?? []
  if (named.length > 1) return { status: 'ambiguous', file, name: head }
  if (named.length === 1) {
    const targets = targetsForSpecifier(sourceByPath, graph, filePath, named[0].specifier)
    if (targets.length !== 1) return { status: 'missing' }
    const nextPath = named[0].imported === '*' ? members : [named[0].imported, ...members]
    if (nextPath.length === 0) return { status: 'missing' }
    const inner = resolveReexport(sourceByPath, graph, targets[0], nextPath, options, depth + 1, seen)
    if (inner.status !== 'found') return inner
    return { ...inner, chain: [filePath, ...inner.chain] }
  }
  if (members.length > 0) return { status: 'missing' }

  const found = []
  let ambiguous = false
  for (const star of file.index.exportStars ?? []) {
    const targets = targetsForSpecifier(sourceByPath, graph, filePath, star.specifier)
    if (targets.length === 0) continue
    if (targets.length > 1) {
      ambiguous = true
      continue
    }
    const inner = resolveReexport(sourceByPath, graph, targets[0], [head], options, depth + 1, seen)
    if (inner.status === 'found') found.push(inner)
    else if (inner.status === 'ambiguous') ambiguous = true
  }
  const unique = []
  const seenEntry = new Set()
  for (const item of found) {
    const id = `${item.file.path}:${item.entry.start}`
    if (seenEntry.has(id)) continue
    seenEntry.add(id)
    unique.push(item)
  }
  if (unique.length > 1 || ambiguous) return { status: 'ambiguous', file, name: head }
  if (unique.length === 1) return { ...unique[0], chain: [filePath, ...unique[0].chain] }
  return { status: 'missing' }
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
// Keep in step with engine/semantic/taint.js: segment boundaries, not substrings.
const SECRET_ENV = /(?:^|_)(?:PRIVATE_KEY|ACCESS_KEY|API_KEY|CREDENTIAL|PASSWORD|PASSWD|SECRET|TOKEN|AUTH)(?:_|$)/i

function isFunctionNode(node) {
  return FUNCTION_NODE_TYPES.has(node?.type)
}

function functionEntryFromNode(node, name = null) {
  const fn = unwrapExpression(node)
  if (!isFunctionNode(fn) || !fn.body) return null
  const expressionBody = fn.body.type === 'BlockStatement' ? null : fn.body
  const body = expressionBody
    ? { type: 'BlockStatement', body: [{ type: 'ExpressionStatement', expression: fn.body, start: fn.body.start, end: fn.body.end }] }
    : fn.body
  return {
    param: firstParamName(fn.params?.[0]),
    params: (fn.params ?? []).map((param) => firstParamName(param)).filter(Boolean),
    paramNodes: fn.params ?? [],
    body,
    expressionBody,
    start: fn.start,
    name: name ?? fn.id?.name ?? null,
  }
}

function isThenCall(call) {
  let callee = unwrapExpression(call?.callee)
  if (callee?.type === 'ChainExpression') callee = unwrapExpression(callee.expression)
  if (callee?.type !== 'MemberExpression') return false
  if (!callee.computed) return callee.property?.name === 'then'
  return staticStringOf(callee.property) === 'then'
}

function walkOwn(node, visit) {
  if (!node || typeof node.type !== 'string' || FUNCTION_NODE_TYPES.has(node.type)) return
  visit(node)
  for (const key of Object.keys(node)) {
    if (key === 'type' || key === 'start' || key === 'end' || key === 'loc' || key === 'range') continue
    const child = node[key]
    const children = Array.isArray(child) ? child : [child]
    for (const item of children) {
      if (!item || typeof item.type !== 'string' || FUNCTION_NODE_TYPES.has(item.type)) continue
      walkOwn(item, visit)
    }
  }
}

function taintOptions(collected, extra = null) {
  return { collected, promiseValues: extra?.promiseValues ?? null, callReturns: extra?.callReturns ?? null }
}

/**
 * Proven source return of one function. Parameter passthrough and unknown
 * calls do not count. `touches` is true when a modeled source exists but the
 * returned value cannot be proven.
 */
function ownReturnTaint(entry, seed, collected, { allowArgs = false } = {}) {
  const taints = new Map(seed)
  const declarators = []
  let touches = false
  const note = (node) => {
    if (node.type === 'CallExpression' && sourceCallTag(node)) touches = true
    if (isSecretEnvRead(node)) touches = true
    if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier' && node.init) declarators.push(node)
    if (node.type === 'AssignmentExpression' && node.left?.type === 'Identifier' && node.right) {
      declarators.push({ id: node.left, init: node.right })
    }
  }
  if (entry?.body) walkOwn(entry.body, note)
  let changed = true
  let rounds = 0
  while (changed && rounds < 6) {
    changed = false
    rounds += 1
    for (const declarator of declarators) {
      if (taints.has(declarator.id.name)) continue
      const taint = expressionTaint(declarator.init, taints, null, taintOptions(collected))
      if (!taint || (!allowArgs && taint.tag === 'args')) continue
      taints.set(declarator.id.name, taint)
      changed = true
    }
  }
  const returns = []
  if (entry?.expressionBody) returns.push(entry.expressionBody)
  else if (entry?.body) {
    walkOwn(entry.body, (node) => {
      if (node.type === 'ReturnStatement') returns.push(node.argument ?? null)
    })
  }
  let proven = null
  let conflict = false
  for (const expr of returns) {
    if (!expr) continue
    const taint = expressionTaint(expr, taints, null, taintOptions(collected))
    if (!taint || (!allowArgs && taint.tag === 'args')) continue
    if (!proven) proven = taint.crossReturn ? taint : { tag: taint.tag, source: taint.source }
    else if (proven.tag !== taint.tag) conflict = true
  }
  return { taint: conflict ? null : proven, touches }
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
function expressionTaint(node, taints, toolArgName = 'args', options = null) {
  const target = unwrapExpression(node)
  if (!target) return null
  const allowBareEnv = options?.allowBareEnv !== false
  const again = (child, nextOptions = options) => expressionTaint(child, taints, toolArgName, nextOptions)
  if (target.type === 'ChainExpression') return again(target.expression)
  if (target.type === 'Identifier') return taints.get(target.name) ?? null
  if (target.type === 'MemberExpression') {
    if (isSecretEnvRead(target)) return { tag: 'env', source: calleeName(target) ?? 'process.env' }
    if (allowBareEnv && !target.computed && calleeName(target) === 'process.env') {
      return { tag: 'env', source: 'process.env' }
    }
    const objectName = target.object?.type === 'Identifier' ? target.object.name : null
    if (toolArgName && objectName && objectName === toolArgName) {
      return { tag: 'args', source: calleeName(target) ?? toolArgName }
    }
    if (target.object?.type === 'Identifier' && taints.has(target.object.name)) return taints.get(target.object.name)
    // process.env.NODE_ENV must not inherit a full-env dump from its object.
    return again(target.object, { ...(options ?? {}), allowBareEnv: false })
  }
  if (target.type === 'CallExpression') {
    if (options?.promiseValues?.has(target)) return options.promiseValues.get(target)
    if (options?.callReturns?.has(target)) {
      const info = options.callReturns.get(target)
      if (info?.taint) return { ...info.taint, crossReturn: info }
      if (info?.unresolved) return { tag: 'unresolved-return', source: info.label ?? 'return', crossReturn: info }
    }
    const raw = calleeName(target.callee)
    if (raw === 'Promise.resolve' && target.arguments?.[0]) return again(target.arguments[0])
    const read = valueProducingReadTag(target, options?.collected)
    if (read) return read
    const tagged = sourceCallTag(target)
    if (tagged?.tag === 'decode') return tagged
    return null
  }
  if (target.type === 'NewExpression') return null
  if (target.type === 'ArrayExpression') {
    for (const element of target.elements ?? []) {
      const taint = again(element)
      if (taint) return taint
    }
    return null
  }
  if (target.type === 'ObjectExpression') {
    for (const prop of target.properties ?? []) {
      if (prop?.type === 'SpreadElement') {
        const taint = again(prop.argument)
        if (taint) return taint
      } else if (prop && prop.type === 'Property') {
        const taint = again(prop.value)
        if (taint) return taint
      }
    }
    return null
  }
  if (target.type === 'TemplateLiteral') {
    for (const expression of target.expressions ?? []) {
      const taint = again(expression)
      if (taint) return taint
    }
    return null
  }
  if (target.type === 'BinaryExpression' || target.type === 'LogicalExpression') {
    return again(target.left) ?? again(target.right)
  }
  if (target.type === 'ConditionalExpression') {
    return again(target.consequent) ?? again(target.alternate)
  }
  if (target.type === 'SequenceExpression') {
    for (let i = (target.expressions ?? []).length - 1; i >= 0; i -= 1) {
      const taint = again(target.expressions[i])
      if (taint) return taint
    }
    return null
  }
  if (target.type === 'AssignmentExpression') return again(target.right)
  if (target.type === 'AwaitExpression' || target.type === 'YieldExpression'
    || target.type === 'UnaryExpression' || target.type === 'UpdateExpression') {
    return again(target.argument)
  }
  if (target.type === 'SpreadElement') return again(target.argument)
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

function collectTaintedLocals(ast, collected = null) {
  const taints = new Map()
  const options = taintOptions(collected)
  let changed = true
  let rounds = 0
  while (changed && rounds < 6) {
    changed = false
    rounds += 1
    walk(ast, (node) => {
      if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier' && node.init) {
        if (taints.has(node.id.name)) return
        const taint = expressionTaint(node.init, taints, 'args', options)
        if (taint) {
          taints.set(node.id.name, taint)
          changed = true
        }
      }
      if (node.type === 'AssignmentExpression' && node.left?.type === 'Identifier') {
        if (taints.has(node.left.name)) return
        const taint = expressionTaint(node.right, taints, 'args', options)
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
  const promiseValues = new Map()
  const flowTaint = (node, map = taints) => expressionTaint(node, map, ctx.toolArgName ?? 'args', taintOptions(ctx.collected, {
    promiseValues,
    callReturns: options.callReturns,
  }))

  let changed = true
  let rounds = 0
  while (changed && rounds < 6) {
    changed = false
    rounds += 1
    for (const declarator of declarators) {
      if (declarator.id?.type === 'Identifier' && declarator.init) {
        if (taints.has(declarator.id.name)) continue
        const taint = flowTaint(declarator.init)
        if (taint) {
          taints.set(declarator.id.name, taint)
          changed = true
        }
      } else if (declarator.id?.type === 'ObjectPattern' && declarator.init) {
        const init = unwrapExpression(declarator.init)
        if (calleeName(init) === 'process.env') {
          for (const prop of declarator.id.properties ?? []) {
            const key = prop.computed ? staticStringOf(prop.key) : (prop.key?.name ?? staticStringOf(prop.key))
            const value = prop.value
            const name = value?.type === 'AssignmentPattern' ? value.left?.name : value?.name
            if (!key || !name || taints.has(name) || !SECRET_ENV.test(key)) continue
            taints.set(name, { tag: 'env', source: `process.env.${key}` })
            changed = true
          }
          continue
        }
        const taint = flowTaint(declarator.init)
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
      const taint = flowTaint(assignment.right)
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

  // Direct `.then` on a value-producing read/decode/env/args expression.
  // The fulfillment parameter is seeded; unknown receivers are not.
  if (depth < 3) {
    for (const call of calls.filter(isThenCall).reverse()) {
      const callee = unwrapExpression(call.callee)
      const receiver = callee?.type === 'MemberExpression' ? callee.object : null
      const receiverTaint = flowTaint(receiver)
      if (!receiverTaint || receiverTaint.tag === 'unresolved-return') continue
      const fulfillment = call.arguments?.[0]
      const value = unwrapExpression(fulfillment)
      const bound = value?.type === 'Identifier' ? callbackLookup.get(value.name) : null
      if (bound) {
        callbacks.push({ paramIndex: bound.paramIndex, argIndex: 0, taint: receiverTaint, label: 'then(...)' })
        continue
      }
      const cbEntry = callbackEntryFor(fulfillment)
      const seededNames = fulfillmentNames(cbEntry?.paramNodes?.[0])
      if (!cbEntry || seededNames.length === 0) continue
      const seed = new Map(seededNames.map((name) => [name, receiverTaint]))
      const sub = analyzeFunctionFlow(cbEntry, seed, ctx, {
        depth: depth + 1,
        callbackScope: callbackLookup,
        callReturns: options.callReturns,
      })
      mergeFlow({ hits, callbacks, closureWrites, coverage }, sub, 'then(...)')
      const returned = ownReturnTaint(cbEntry, seed, ctx.collected, { allowArgs: true })
      if (returned.taint) {
        promiseValues.set(call, returned.taint.crossReturn ? returned.taint : { ...returned.taint, crossReturn: receiverTaint.crossReturn })
      }
    }
  }

  for (const call of calls) {
    const raw = calleeName(call.callee)
    const tail = raw ? raw.slice(raw.lastIndexOf('.') + 1) : null

    // A function parameter invoked with tainted data is a callback bridge.
    const callbackBinding = raw ? callbackLookup.get(raw) : null
    if (callbackBinding) {
      for (let index = 0; index < (call.arguments ?? []).length; index += 1) {
        const taint = flowTaint(call.arguments[index])
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
        const inherited = flowTaint(callee.object)
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
          const taint = flowTaint(arg)
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
      .map((arg) => flowTaint(arg))
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
function analyzeCallerReturnScope(entry, ctx, callReturns, seed = new Map(), depth = 0) {
  const hits = []
  const skips = []
  const taints = new Map(seed)
  const declarators = []
  const calls = []
  const body = entry?.body ?? entry
  walkOwn(body, (node) => {
    if (node.type === 'VariableDeclarator') declarators.push(node)
    if (node.type === 'AssignmentExpression' && node.left?.type === 'Identifier' && node.right) {
      declarators.push({ id: node.left, init: node.right })
    }
    if (node.type === 'CallExpression') calls.push(node)
  })
  const optionsFor = (promiseValues) => taintOptions(ctx.collected, { promiseValues, callReturns })
  let changed = true
  let rounds = 0
  while (changed && rounds < 6) {
    changed = false
    rounds += 1
    for (const declarator of declarators) {
      if (declarator.id?.type === 'Identifier' && declarator.init && !taints.has(declarator.id.name)) {
        const taint = expressionTaint(declarator.init, taints, 'args', optionsFor(null))
        if (taint) {
          taints.set(declarator.id.name, taint)
          changed = true
        }
      } else if (declarator.id?.type === 'ObjectPattern' && declarator.init) {
        const taint = expressionTaint(declarator.init, taints, 'args', optionsFor(null))
        if (!taint) continue
        for (const name of fulfillmentNames(declarator.id)) {
          if (!taints.has(name)) {
            taints.set(name, taint)
            changed = true
          }
        }
      }
    }
  }
  const promiseValues = new Map()
  if (depth < 3) {
    for (const call of calls.filter(isThenCall).reverse()) {
      const callee = unwrapExpression(call.callee)
      if (callee?.type !== 'MemberExpression') continue
      const receiverTaint = expressionTaint(callee.object, taints, 'args', optionsFor(promiseValues))
      if (!receiverTaint) continue
      const cbEntry = functionEntryFromNode(call.arguments?.[0])
      const names = fulfillmentNames(cbEntry?.paramNodes?.[0])
      if (!cbEntry || names.length === 0) continue
      const sub = analyzeCallerReturnScope(
        cbEntry,
        ctx,
        callReturns,
        new Map(names.map((name) => [name, receiverTaint])),
        depth + 1,
      )
      hits.push(...sub.hits)
      skips.push(...sub.skips)
      if (sub.returnTaint) promiseValues.set(call, sub.returnTaint)
    }
  }
  for (const call of calls) {
    if (isThenCall(call)) continue
    const sinkRaw = calleeName(call.callee) ?? callTargetName(call.callee)
    if (!sinkRaw) continue
    const sinkName = resolveCrossFileSink(sinkRaw, ctx.collected)
    if (!sinkName) continue
    const sink = SINKS.find((item) => item.names.includes(sinkName))
    if (!sink) continue
    if (sink.module && !bindingConfirmsBuiltin(sinkRaw, ctx.collected)) continue
    const argTaints = (call.arguments ?? [])
      .map((arg) => expressionTaint(arg, taints, 'args', optionsFor(promiseValues)))
      .filter(Boolean)
    const resolved = argTaints.find((taint) => taint.crossReturn && taint.tag !== 'unresolved-return')
    const unresolved = argTaints.find((taint) => taint.tag === 'unresolved-return')
    if (resolved) {
      hits.push({
        sink: { ...sink, callee: sinkName, start: call.start },
        taint: resolved,
        call,
        info: resolved.crossReturn,
      })
    } else if (unresolved?.crossReturn) {
      skips.push({ info: unresolved.crossReturn, call })
    }
  }
  let returnTaint = null
  const returns = []
  if (entry?.expressionBody) returns.push(entry.expressionBody)
  else {
    walkOwn(body, (node) => {
      if (node.type === 'ReturnStatement' && node.argument) returns.push(node.argument)
    })
  }
  for (const expr of returns) {
    const taint = expressionTaint(expr, taints, 'args', optionsFor(promiseValues))
    if (taint?.crossReturn || taint?.tag === 'unresolved-return') returnTaint = taint
  }
  return { hits, skips, returnTaint }
}

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
      const collected = ast ? collectImports(ast) : { imports: new Map(), aliases: new Map(), cpVars: new Set() }
      if (ast) applyAwaitImportBindings(ast, collected)
      sourceByPath.set(node.path, {
        path: node.path,
        content,
        ast,
        index,
        collected,
        taints: ast ? collectTaintedLocals(ast, collected) : new Map(),
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

  const addHit = ({ fromPath, toPath, source, sinkHit, binding, entry, trace, sinkFile, modulePath = null }) => {
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
    const resolvedModulePath = modulePath ?? [fromPath, toPath]
    const dedupeKey = `${resolvedModulePath.join('>')}|${rule.ruleId}|${sinkFile.path}|${sinkLine}|${sinkHit.sink.callee}|${source}`
    if (seenFindings.has(dedupeKey)) return
    seenFindings.add(dedupeKey)
    const chain = {
      source,
      modulePath: resolvedModulePath,
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
      modulePath: resolvedModulePath,
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
        const followed = resolveReexport(sourceByPath, graph, edge.to, invocation.targetPath, { instance: invocation.instance })
        if (followed.status === 'ambiguous') {
          if (invocation.argTaints.size > 0) {
            addSkip({
              reason: 'cross-file-reexport-unresolved',
              path: edge.from,
              member: invocation.targetPath.join('.'),
              start: invocation.start,
            })
          }
          continue
        }
        if (followed.status !== 'found') {
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
        invocations.push({
          ...invocation,
          edge,
          binding,
          from,
          to: followed.file,
          entry: followed.entry,
          exportChain: followed.chain,
        })
      }
    }
  }

  const moduleState = new Map()
  for (let round = 0; round < 3; round += 1) {
    let changed = false
    for (const invocation of invocations) {
      const key = `${invocation.to.path}\0${invocation.edge.from}`
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
        file: invocation.to.path,
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
          toPath: invocation.to.path,
          modulePath: [invocation.edge.from, ...(invocation.exportChain ?? [invocation.to.path])],
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
            toPath: invocation.to.path,
            modulePath: [invocation.edge.from, ...(invocation.exportChain ?? [invocation.to.path])],
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

  const callReturns = new Map()
  const returnProfiles = new Map()
  for (const edge of graph?.edges ?? []) {
    const from = sourceByPath.get(edge.from)
    const to = sourceByPath.get(edge.to)
    if (!from?.ast || !to?.index) continue
    const bindings = bindingsForEdge(from.content, edge, from.ast)
    for (const binding of bindings) {
      for (const invocation of collectInvocationsForBinding(from.ast, binding, from.taints)) {
        if (!Array.isArray(invocation.targetPath) || invocation.targetPath.length === 0) continue
        const followed = resolveReexport(sourceByPath, graph, edge.to, invocation.targetPath, { instance: invocation.instance })
        if (followed.status === 'ambiguous') {
          if (invocation.argTaints.size > 0) {
            addSkip({
              reason: 'cross-file-reexport-unresolved',
              path: edge.from,
              member: invocation.targetPath.join('.'),
              start: invocation.start,
            })
          }
          continue
        }
        if (followed.status !== 'found') continue
        const profileKey = `${followed.file.path}\0${invocation.targetPath.join('.')}\0${invocation.instance ? '1' : '0'}`
        let profile = returnProfiles.get(profileKey)
        if (!profile) {
          profile = ownReturnTaint(followed.entry, new Map(), followed.file.collected)
          returnProfiles.set(profileKey, profile)
        }
        if (!profile.taint && !profile.touches) continue
        callReturns.set(invocation.call, {
          taint: profile.taint,
          unresolved: !profile.taint && profile.touches,
          edge,
          binding,
          entry: followed.entry,
          resolvedFile: followed.file,
          exportChain: followed.chain,
          label: invocation.targetPath.join('.'),
        })
      }
    }
  }
  if (callReturns.size > 0) {
    const files = new Set([...callReturns.values()].map((info) => info.edge.from))
    for (const filePath of files) {
      const file = sourceByPath.get(filePath)
      if (!file?.ast) continue
      const scopes = [{ body: file.ast, expressionBody: null, params: [], paramNodes: [] }]
      walk(file.ast, (node) => {
        if (!FUNCTION_NODE_TYPES.has(node.type) || !node.body) return
        const scope = functionEntryFromNode(node)
        if (scope) scopes.push(scope)
      })
      for (const scope of scopes) {
        const sub = analyzeCallerReturnScope(scope, { collected: file.collected }, callReturns)
        for (const hit of sub.hits) {
          if (!hit.info?.edge) continue
          addHit({
            fromPath: hit.info.edge.from,
            toPath: hit.info.resolvedFile?.path ?? hit.info.edge.to,
            modulePath: [hit.info.edge.from, ...(hit.info.exportChain ?? [hit.info.edge.to])],
            source: hit.taint.source,
            sinkHit: hit,
            binding: hit.info.binding,
            entry: hit.info.entry,
            trace: ['return'],
            sinkFile: file,
          })
        }
        for (const skip of sub.skips) {
          addSkip({
            reason: 'cross-file-return-unresolved',
            path: file.path,
            member: skip.info?.label ?? skip.info?.binding?.local ?? 'return',
            start: skip.call?.start,
          })
        }
      }
    }
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
