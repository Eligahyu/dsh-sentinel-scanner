/**
 * Statically recoverable module specifiers.
 *
 * This helper never evaluates scanned code. It only folds string literals,
 * string concatenation, and templates whose every part is itself a static
 * string. Anything else — identifiers without a proven const, calls, member
 * access, conditionals, numeric coercion — stays unresolved.
 */

import { staticString, walk } from './ast.js'

const PENDING = Symbol('pending')
const MAX_DEPTH = 8
const MAX_SPECIFIER_CHARS = 2000

function skipWs(source, index, end) {
  let i = index
  while (i < end && /\s/.test(source[i])) i += 1
  return i
}

function readEscape(source, index, end) {
  if (source[index] !== '\\' || index + 1 >= end) return null
  const esc = source[index + 1]
  if (esc === '\n') return { value: '', index: index + 2 }
  if (esc === '\r') return { value: '', index: source[index + 2] === '\n' ? index + 3 : index + 2 }
  const simple = {
    n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', v: '\v',
    '\\': '\\', "'": "'", '"': '"', '`': '`', '/': '/',
  }
  if (Object.prototype.hasOwnProperty.call(simple, esc)) return { value: simple[esc], index: index + 2 }
  if (esc === '0' && !/[0-9]/.test(source[index + 2] ?? '')) return { value: '\0', index: index + 2 }
  if (esc === 'x' && /^[0-9a-fA-F]{2}$/.test(source.slice(index + 2, index + 4))) {
    return { value: String.fromCharCode(parseInt(source.slice(index + 2, index + 4), 16)), index: index + 4 }
  }
  if (esc === 'u' && source[index + 2] === '{') {
    const close = source.indexOf('}', index + 3)
    const hex = close < 0 ? '' : source.slice(index + 3, close)
    if (close < 0 || close > end || hex.length === 0 || hex.length > 6 || !/^[0-9a-fA-F]+$/.test(hex)) return null
    const codePoint = parseInt(hex, 16)
    if (codePoint > 0x10FFFF) return null
    return { value: String.fromCodePoint(codePoint), index: close + 1 }
  }
  if (esc === 'u' && /^[0-9a-fA-F]{4}$/.test(source.slice(index + 2, index + 6))) {
    return { value: String.fromCharCode(parseInt(source.slice(index + 2, index + 6), 16)), index: index + 6 }
  }
  return null
}

function readQuoted(source, index, end, quote) {
  let value = ''
  let i = index + 1
  while (i < end) {
    const ch = source[i]
    if (ch === '\\') {
      const decoded = readEscape(source, i, end)
      if (!decoded) return null
      value += decoded.value
      i = decoded.index
      continue
    }
    if (ch === quote) return { value, index: i + 1 }
    if ((ch === '\n' || ch === '\r') && quote !== '`') return null
    value += ch
    i += 1
  }
  return null
}

function parseExpr(source, index, end, depth) {
  if (depth > MAX_DEPTH) return null
  const first = parsePrimary(source, index, end, depth)
  if (!first) return null
  let value = first.value
  let i = first.index
  while (true) {
    const j = skipWs(source, i, end)
    if (j >= end || source[j] !== '+') return { value, index: i }
    const next = parsePrimary(source, j + 1, end, depth)
    if (!next) return null
    value += next.value
    i = next.index
  }
}

function parseTemplate(source, index, end, depth) {
  let value = ''
  let i = index + 1
  while (i < end) {
    const ch = source[i]
    if (ch === '\\') {
      const decoded = readEscape(source, i, end)
      if (!decoded) return null
      value += decoded.value
      i = decoded.index
      continue
    }
    if (ch === '`') return { value, index: i + 1 }
    if (ch === '$' && source[i + 1] === '{') {
      const expr = parseExpr(source, i + 2, end, depth + 1)
      if (!expr) return null
      const close = skipWs(source, expr.index, end)
      if (source[close] !== '}') return null
      value += expr.value
      i = close + 1
      continue
    }
    value += ch
    i += 1
  }
  return null
}

function parsePrimary(source, index, end, depth) {
  const i = skipWs(source, index, end)
  if (i >= end) return null
  const ch = source[i]
  if (ch === "'" || ch === '"') return readQuoted(source, i, end, ch)
  if (ch === '`') return parseTemplate(source, i, end, depth)
  if (ch === '(') {
    const inner = parseExpr(source, i + 1, end, depth + 1)
    if (!inner) return null
    const close = skipWs(source, inner.index, end)
    if (source[close] !== ')') return null
    return { value: inner.value, index: close + 1 }
  }
  return null
}

/** Fold a comment-stripped argument slice. Returns null when it is not a pure static string. */
export function evaluateStaticSpecifier(source, start, end) {
  if (!Number.isInteger(start) || !Number.isInteger(end) || end < start || end - start > MAX_SPECIFIER_CHARS) return null
  const parsed = parseExpr(source, start, end, 0)
  if (!parsed) return null
  if (skipWs(source, parsed.index, end) !== end) return null
  return parsed.value
}

/**
 * Read the first argument of a call whose opening parenthesis is at `openParen`.
 * Templates and strings are opaque, matching the comment stripper.
 */
export function readCallArgument(source, openParen) {
  if (source[openParen] !== '(') return null
  let depth = 1
  let quote = null
  let escaped = false
  let argEnd = null
  const start = openParen + 1
  for (let i = start; i < source.length; i += 1) {
    const ch = source[i]
    if (quote) {
      if (escaped) escaped = false
      else if (ch === '\\') escaped = true
      else if (ch === quote) quote = null
      continue
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      quote = ch
      continue
    }
    if (ch === '(') {
      depth += 1
      continue
    }
    if (ch === ')') {
      depth -= 1
      if (depth === 0) return { start, end: argEnd ?? i, close: i }
      continue
    }
    if (ch === ',' && depth === 1 && argEnd === null) argEnd = i
  }
  return null
}

function patternNames(pattern, out = []) {
  if (!pattern || typeof pattern.type !== 'string') return out
  if (pattern.type === 'Identifier') out.push(pattern.name)
  else if (pattern.type === 'AssignmentPattern' || pattern.type === 'RestElement') patternNames(pattern.argument ?? pattern.left, out)
  else if (pattern.type === 'ObjectPattern') {
    for (const prop of pattern.properties ?? []) {
      if (prop?.type === 'RestElement') patternNames(prop.argument, out)
      else patternNames(prop?.value, out)
    }
  } else if (pattern.type === 'ArrayPattern') {
    for (const element of pattern.elements ?? []) if (element) patternNames(element, out)
  }
  return out
}

function recoverNode(node, lookup) {
  if (!node || typeof node.type !== 'string') return null
  const direct = staticString(node)
  if (direct !== null) return direct
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = recoverNode(node.left, lookup)
    const right = recoverNode(node.right, lookup)
    if (left === PENDING || right === PENDING) return PENDING
    if (typeof left !== 'string' || typeof right !== 'string') return null
    return left + right
  }
  if (node.type === 'TemplateLiteral') {
    if (node.quasis.length !== node.expressions.length + 1) return null
    let value = ''
    for (let i = 0; i < node.quasis.length; i += 1) {
      const cooked = node.quasis[i]?.value?.cooked
      if (typeof cooked !== 'string') return null
      value += cooked
      if (i < node.expressions.length) {
        const expr = recoverNode(node.expressions[i], lookup)
        if (expr === PENDING) return PENDING
        if (typeof expr !== 'string') return null
        value += expr
      }
    }
    return value
  }
  if (node.type === 'Identifier') {
    const value = lookup(node.name)
    if (value === PENDING) return PENDING
    return typeof value === 'string' ? value : null
  }
  if (node.type === 'ParenthesizedExpression') return recoverNode(node.expression, lookup)
  return null
}

/** Recover a specifier expression. `lookup(name)` returns a string or null. */
export function recoverStaticSpecifier(node, lookup = () => null) {
  const value = recoverNode(node, (name) => {
    const resolved = lookup(name)
    return typeof resolved === 'string' ? resolved : null
  })
  return typeof value === 'string' ? value : null
}

/**
 * Map a name to a string only when the file has exactly one `const` binding,
 * that binding is never assigned, shadowed by a parameter, or repeated, and
 * its initializer folds to a string. Ambiguous names stay unresolved.
 */
export function buildConstStringLookup(ast) {
  const declarations = []
  const blocked = new Set()
  walk(ast, (node) => {
    if (node.type === 'VariableDeclaration') {
      for (const decl of node.declarations ?? []) {
        const names = patternNames(decl.id)
        if (node.kind !== 'const' || names.length !== 1 || decl.id?.type !== 'Identifier') {
          for (const name of names) blocked.add(name)
          continue
        }
        declarations.push({ name: names[0], init: decl.init ?? null })
      }
      return
    }
    if (node.type === 'AssignmentExpression' || node.type === 'UpdateExpression') {
      const target = node.type === 'UpdateExpression' ? node.argument : node.left
      if (target?.type !== 'MemberExpression') {
        for (const name of patternNames(target)) blocked.add(name)
      }
      return
    }
    if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') {
      if (node.id?.name) blocked.add(node.id.name)
      for (const param of node.params ?? []) for (const name of patternNames(param)) blocked.add(name)
      return
    }
    if (node.type === 'CatchClause' && node.param) {
      for (const name of patternNames(node.param)) blocked.add(name)
    } else if ((node.type === 'ClassDeclaration' || node.type === 'ClassExpression') && node.id?.name) {
      blocked.add(node.id.name)
    }
  })

  const counts = new Map()
  for (const decl of declarations) counts.set(decl.name, (counts.get(decl.name) ?? 0) + 1)
  const resolvable = new Map()
  for (const decl of declarations) {
    if (blocked.has(decl.name) || counts.get(decl.name) !== 1) continue
    resolvable.set(decl.name, decl.init)
  }

  const resolved = new Map()
  const pending = new Set(resolvable.keys())
  const lookup = (name) => {
    if (resolved.has(name)) return resolved.get(name)
    if (pending.has(name)) return PENDING
    return null
  }
  let progressed = true
  while (progressed) {
    progressed = false
    for (const [name, init] of resolvable) {
      if (resolved.has(name)) continue
      const value = recoverNode(init, (dependency) => (dependency === name ? null : lookup(dependency)))
      if (value === PENDING) continue
      resolved.set(name, typeof value === 'string' ? value : null)
      pending.delete(name)
      progressed = true
    }
  }
  for (const name of pending) resolved.set(name, null)
  return (name) => (typeof resolved.get(name) === 'string' ? resolved.get(name) : null)
}

function childNodes(node) {
  const children = []
  for (const key of Object.keys(node)) {
    if (key === 'type' || key === 'start' || key === 'end' || key === 'loc' || key === 'range') continue
    const child = node[key]
    if (Array.isArray(child)) {
      for (const item of child) if (item && typeof item.type === 'string') children.push(item)
    } else if (child && typeof child.type === 'string') children.push(child)
  }
  return children
}

export function parentMap(ast) {
  const parents = new Map()
  walk(ast, (node) => {
    for (const child of childNodes(node)) parents.set(child, node)
  })
  return parents
}

/** Named bindings from an object pattern. Unreadable computed keys are skipped. */
export function namedBindingsFromObjectPattern(pattern, lookup = () => null) {
  const out = []
  for (const prop of pattern?.properties ?? []) {
    if (!prop || prop.type === 'RestElement' || prop.type !== 'Property' || prop.kind === 'get' || prop.kind === 'set' || prop.method) continue
    let imported = null
    if (!prop.computed && prop.key?.type === 'Identifier') imported = prop.key.name
    else if (prop.key?.type === 'Literal' && typeof prop.key.value === 'string') imported = prop.key.value
    else if (prop.computed) imported = recoverStaticSpecifier(prop.key, lookup)
    let localNode = prop.value
    if (localNode?.type === 'AssignmentPattern') localNode = localNode.left
    if (!imported || !/^[A-Za-z_$][\w$]*$/.test(imported) || localNode?.type !== 'Identifier') continue
    out.push({ imported, local: localNode.name })
  }
  return out
}

/** Direct `require` / `require.resolve`, including `(0, require)` and optional calls. */
export function requireCallKind(callee) {
  const target = callee?.type === 'SequenceExpression' ? callee.expressions?.at(-1) : callee
  if (!target) return null
  if (target.type === 'Identifier' && target.name === 'require') return 'require'
  if (target.type === 'MemberExpression'
    && target.object?.type === 'Identifier'
    && target.object.name === 'require'
    && ((!target.computed && target.property?.name === 'resolve')
      || (target.computed && recoverStaticSpecifier(target.property) === 'resolve'))) {
    return 'resolve'
  }
  return null
}

export function bindingsForImportCall(node, parents, lookup = () => null) {
  let current = node
  let parent = parents.get(current)
  while (parent && (
    (parent.type === 'AwaitExpression' && parent.argument === current)
    || (parent.type === 'ChainExpression' && parent.expression === current)
  )) {
    current = parent
    parent = parents.get(current)
  }
  if (parent?.type !== 'VariableDeclarator' || parent.init !== current || parent.id?.type !== 'ObjectPattern') return []
  return namedBindingsFromObjectPattern(parent.id, lookup)
}
