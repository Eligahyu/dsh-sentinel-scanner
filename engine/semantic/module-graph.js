/**
 * Read-only JavaScript/TypeScript module graph.
 *
 * This module never imports or executes a target module. It resolves static
 * import/export declarations and dynamic import()/require()/require.resolve()
 * calls whose specifiers fold to a static string. External packages are kept
 * as unresolved edges so callers can distinguish a graph gap from a package
 * boundary. Targets that cannot be folded stay warnings and never become edges.
 */

import { createHash } from 'node:crypto'
import { existsSync, readFileSync, statSync } from 'node:fs'
import { dirname, extname, join, relative, resolve } from 'node:path'
import { parseJavaScript, walk, staticString } from './ast.js'
import { resolveInside } from '../path-safety.js'
import {
  bindingsForImportCall,
  buildConstStringLookup,
  evaluateStaticSpecifier,
  parentMap,
  readCallArgument,
  recoverStaticSpecifier,
  requireCallKind,
} from './static-specifier.js'

const SOURCE_EXTENSIONS = ['.js', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts', '.jsx']

/** TypeScript 变体:acorn 无法解析,属能力边界(降级而非完整性失败)。 */
const TS_EXT = /\.(?:tsx?|mts|cts|d\.ts)$/i

/** 测试路径:测试文件引用构建产物/外部脚本是开发态常态,其模块图缺口降级为警告。 */
const TEST_PATH = /(^|[\\/])(?:test|tests|__tests__|spec|e2e)([\\/]|\.)|\.(?:spec|test|e2e)\./i

/** Type declarations and explicit development runners do not participate in runtime reachability. */
const DECLARATION_PATH = /\.d\.(?:ts|mts|cts)$/i
const DEVELOPMENT_RUNNER_MARKERS = ['e2e', 'release', 'bench', 'eval', 'check', 'dev']

function isDevelopmentRunnerPath(relPath) {
  const parts = String(relPath).replace(/\\/g, '/').split('/')
  if (parts.length < 2 || parts.at(-2).toLowerCase() !== 'scripts') return false
  const fileName = parts.at(-1).toLowerCase()
  return DEVELOPMENT_RUNNER_MARKERS.some((marker) => fileName.includes(marker))
}

function relPath(root, abs) {
  return relative(root, abs).replace(/\\/g, '/')
}

function hash(content) {
  return createHash('sha256').update(content).digest('hex')
}

function packageExportTarget(pkg, subpath = '.') {
  const exports = pkg?.exports
  if (typeof exports === 'string') return exports
  if (!exports || typeof exports !== 'object' || Array.isArray(exports)) return null
  const entry = exports[subpath] ?? (subpath === '.' ? exports['.'] : null)
  if (typeof entry === 'string') return entry
  if (entry && typeof entry === 'object') {
    return entry.import ?? entry.require ?? entry.default ?? null
  }
  return null
}

function readPackage(abs) {
  try {
    return JSON.parse(readFileSync(join(abs, 'package.json'), 'utf8'))
  } catch {
    return null
  }
}

function resolveContained(root, candidate) {
  try {
    return resolveInside(root, candidate)
  } catch (error) {
    return { error }
  }
}

/** Resolve a source specifier without executing package code. */
export function resolveModuleSpecifier(root, importer, specifier) {
  if (typeof specifier !== 'string' || specifier.length === 0) return { kind: 'external', specifier }
  if (!specifier.startsWith('.') && !specifier.startsWith('/')) {
    return { kind: 'external', specifier }
  }

  const base = resolve(root, dirname(join(root, importer)), specifier)
  const contained = resolveContained(root, base)
  if (contained?.error) return { kind: 'failure', specifier, reason: 'path-escape', error: contained.error }

  const candidates = []
  const addFileCandidates = (abs) => {
    const ext = extname(abs)
    if (ext) {
      candidates.push(abs)
      // TS 项目标准 ESM 形态:import './x.js' 实际文件是 x.ts(allowImportingTsExtensions/
      // rewriteRelativeImportExtensions 产物)。对 .js/.mjs/.cjs 追加 TS 变体回退。
      if (/^\.(?:js|mjs|cjs)$/i.test(ext)) {
        const base = abs.slice(0, -ext.length)
        for (const tsExt of ['.ts', '.tsx', '.mts', '.cts']) candidates.push(base + tsExt)
      }
    } else for (const e of SOURCE_EXTENSIONS) candidates.push(abs + e)
  }
  addFileCandidates(contained)
  if (existsSync(contained) && statSync(contained).isDirectory()) {
    const pkg = readPackage(contained)
    const target = packageExportTarget(pkg, '.')
    if (typeof target === 'string') {
      const exported = resolveContained(root, resolve(contained, target))
      if (exported?.error) return { kind: 'failure', specifier, reason: 'path-escape', error: exported.error }
      addFileCandidates(exported)
    }
    for (const ext of SOURCE_EXTENSIONS) candidates.push(join(contained, `index${ext}`))
  }

  for (const candidate of candidates) {
    const safe = resolveContained(root, candidate)
    if (safe?.error) return { kind: 'failure', specifier, reason: 'path-escape', error: safe.error }
    if (existsSync(safe) && statSync(safe).isFile()) {
      return { kind: 'internal', specifier, abs: safe }
    }
  }
  return { kind: 'failure', specifier, reason: 'missing-file' }
}

function importSpecifiers(ast) {
  const lookup = buildConstStringLookup(ast)
  const parents = parentMap(ast)
  const out = []
  walk(ast, (node) => {
    if (node.type === 'ImportDeclaration') {
      const specifier = staticString(node.source)
      if (specifier !== null) out.push({ specifier, start: node.source.start, kind: 'static-import' })
    } else if (node.type === 'ExportNamedDeclaration' || node.type === 'ExportAllDeclaration') {
      const specifier = staticString(node.source)
      if (specifier !== null) out.push({ specifier, start: node.source.start, kind: 'static-import' })
    } else if (node.type === 'ImportExpression') {
      const specifier = recoverStaticSpecifier(node.source, lookup)
      out.push({
        specifier,
        start: node.source?.start ?? node.start,
        kind: specifier === null ? 'dynamic-import' : 'static-import',
        fromCall: true,
        bindings: specifier === null ? [] : bindingsForImportCall(node, parents, lookup),
      })
    } else if (node.type === 'CallExpression') {
      const callKind = requireCallKind(node.callee)
      if (!callKind) return
      const arg = node.arguments?.[0]
      const dynamicKind = callKind === 'resolve' ? 'dynamic-require-resolve' : 'dynamic-require'
      const staticKind = callKind === 'resolve' ? 'static-require-resolve' : 'static-require'
      if (!arg) {
        out.push({ specifier: null, start: node.start, kind: dynamicKind, fromCall: true, bindings: [] })
        return
      }
      const specifier = recoverStaticSpecifier(arg, lookup)
      out.push({
        specifier,
        start: arg.start,
        kind: specifier === null ? dynamicKind : staticKind,
        fromCall: true,
        bindings: specifier === null || callKind === 'resolve' ? [] : bindingsForImportCall(node, parents, lookup),
      })
    }
  })
  return out
}

/** Remove comments without changing offsets or quoted import specifiers. */
function withoutComments(content) {
  let out = ''
  let state = 'code'
  let escaped = false
  for (let i = 0; i < content.length; i += 1) {
    const ch = content[i]
    const next = content[i + 1]
    if (state === 'line-comment') {
      if (ch === '\n' || ch === '\r') {
        state = 'code'
        out += ch
      } else out += ' '
      continue
    }
    if (state === 'block-comment') {
      if (ch === '*' && next === '/') {
        out += '  '
        i += 1
        state = 'code'
      } else out += ch === '\n' || ch === '\r' ? ch : ' '
      continue
    }
    if (state === 'single' || state === 'double' || state === 'template') {
      out += ch
      if (escaped) escaped = false
      else if (ch === '\\') escaped = true
      else if ((state === 'single' && ch === "'") || (state === 'double' && ch === '"') || (state === 'template' && ch === '`')) state = 'code'
      continue
    }
    if (ch === '/' && next === '/') {
      out += '  '
      i += 1
      state = 'line-comment'
    } else if (ch === '/' && next === '*') {
      out += '  '
      i += 1
      state = 'block-comment'
    } else {
      out += ch
      if (ch === "'") state = 'single'
      else if (ch === '"') state = 'double'
      else if (ch === '`') state = 'template'
    }
  }
  return out
}

/** Mark lexical code positions so fallback patterns cannot match examples inside strings. */
function codePositions(content) {
  const positions = new Uint8Array(content.length)
  let quote = null
  let escaped = false
  for (let i = 0; i < content.length; i += 1) {
    const ch = content[i]
    if (quote) {
      if (escaped) escaped = false
      else if (ch === '\\') escaped = true
      else if (ch === quote) quote = null
      continue
    }
    if (ch === "'" || ch === '"' || ch === '`') quote = ch
    else positions[i] = 1
  }
  return positions
}

function skipWs(source, index, end = source.length) {
  let i = index
  while (i < end && /\s/.test(source[i])) i += 1
  return i
}

function matchDelim(source, openIndex, openChar, closeChar) {
  if (source[openIndex] !== openChar) return -1
  let depth = 1
  let quote = null
  let escaped = false
  for (let i = openIndex + 1; i < source.length; i += 1) {
    const ch = source[i]
    if (quote) {
      if (escaped) escaped = false
      else if (ch === '\\') escaped = true
      else if (ch === quote) quote = null
      continue
    }
    if (ch === "'" || ch === '"' || ch === '`') quote = ch
    else if (ch === openChar) depth += 1
    else if (ch === closeChar && --depth === 0) return i
  }
  return -1
}

function splitTopLevel(text, separator) {
  const parts = []
  let quote = null
  let escaped = false
  let depth = 0
  let start = 0
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]
    if (quote) {
      if (escaped) escaped = false
      else if (ch === '\\') escaped = true
      else if (ch === quote) quote = null
      continue
    }
    if (ch === "'" || ch === '"' || ch === '`') quote = ch
    else if (ch === '(' || ch === '{' || ch === '[') depth += 1
    else if (ch === ')' || ch === '}' || ch === ']') depth = Math.max(0, depth - 1)
    else if (ch === separator && depth === 0) {
      parts.push(text.slice(start, i))
      start = i + 1
    }
  }
  parts.push(text.slice(start))
  return parts
}

function namedBindingsFromPattern(text) {
  const out = []
  for (const part of splitTopLevel(text, ',')) {
    const trimmed = part.trim()
    if (!trimmed || trimmed.startsWith('...')) continue
    const match = /^([A-Za-z_$][\w$]*)\s*(?::\s*([A-Za-z_$][\w$]*))?(?:\s*=\s*[\s\S]*)?$/.exec(trimmed)
    if (!match) continue
    out.push({ imported: match[1], local: match[2] ?? match[1] })
  }
  return out
}

/** Find `=` that terminates a type annotation, without crossing a statement boundary. */
function findEqualsAfterType(source, index) {
  let quote = null
  let escaped = false
  let depth = 0
  const limit = Math.min(source.length, index + 2000)
  for (let i = index; i < limit; i += 1) {
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
    if (ch === '{' || ch === '(' || ch === '[') {
      depth += 1
      continue
    }
    if (ch === '}' || ch === ')' || ch === ']') {
      depth -= 1
      if (depth < 0) return -1
      continue
    }
    if (depth === 0 && (ch === '\n' || ch === ';')) return -1
    if (depth === 0 && ch === '=') return i
  }
  return -1
}

const INIT_CALL = /^\s*(?:await\s+)?(?:\([^()\n]{0,100},\s*)?((?:require(?:\s*\.\s*resolve)?)|import)(?:\s*\?\.)?\s*(?:\)\s*)?\(/

function destructuredCallBindings(source, code) {
  const byStart = new Map()
  const declRe = /(?:const|let|var)\s*\{/g
  let match
  while ((match = declRe.exec(source)) !== null) {
    if (code[match.index] !== 1) continue
    const brace = match.index + match[0].length - 1
    const patternEnd = matchDelim(source, brace, '{', '}')
    if (patternEnd < 0) continue
    let cursor = skipWs(source, patternEnd + 1)
    if (source[cursor] === ':') {
      const eq = findEqualsAfterType(source, cursor + 1)
      if (eq < 0) continue
      cursor = eq
    }
    if (source[cursor] !== '=') continue
    const init = INIT_CALL.exec(source.slice(cursor + 1, cursor + 501))
    if (!init) continue
    const keywordOffset = init[0].search(/\b(?:require|import)\b/)
    const keywordIndex = cursor + 1 + keywordOffset
    if (keywordOffset < 0 || code[keywordIndex] !== 1) continue
    if (/\bresolve\b/.test(init[1])) continue
    const open = cursor + 1 + init[0].length - 1
    const arg = readCallArgument(source, open)
    if (!arg) continue
    const specifier = evaluateStaticSpecifier(source, arg.start, arg.end)
    if (specifier === null) continue
    const bindings = namedBindingsFromPattern(source.slice(brace + 1, patternEnd))
    if (bindings.length === 0) continue
    byStart.set(arg.start, bindings)
    declRe.lastIndex = arg.close + 1
  }
  return byStart
}

/** TypeScript `import()` type queries are erased and are not runtime edges. */
function isTypePositionImport(source, keywordIndex) {
  const before = source.slice(Math.max(0, keywordIndex - 48), keywordIndex)
  if (/(?:typeof|[:|&])\s*$/.test(before)) return true
  const lineStart = source.lastIndexOf('\n', keywordIndex - 1) + 1
  return /^\s*(?:export\s+)?(?:declare\s+)?(?:type|interface)\b/.test(source.slice(lineStart, keywordIndex))
}

function scanCallSpecifiers(source, code) {
  const bindings = destructuredCallBindings(source, code)
  const found = []
  const callRe = /(?<![\w$.])((?:require(?:\s*\.\s*resolve)?)|import)(?:\s*\?\.)?\s*(?:\)\s*)?\(/g
  let match
  while ((match = callRe.exec(source)) !== null) {
    const keywordOffset = match[0].search(/\b(?:require|import)\b/)
    if (keywordOffset < 0 || code[match.index + keywordOffset] !== 1) continue
    if (match[1] === 'import' && isTypePositionImport(source, match.index + keywordOffset)) continue
    const open = match.index + match[0].length - 1
    const isImport = match[1] === 'import'
    const isResolve = !isImport && /\bresolve\b/.test(match[1])
    const dynamicKind = isImport ? 'dynamic-import' : isResolve ? 'dynamic-require-resolve' : 'dynamic-require'
    const staticKind = isImport ? 'static-import' : isResolve ? 'static-require-resolve' : 'static-require'
    const arg = readCallArgument(source, open)
    if (!arg) {
      callRe.lastIndex = open + 1
      found.push({ specifier: null, start: open + 1, kind: dynamicKind, fromCall: true, bindings: [] })
      continue
    }
    callRe.lastIndex = arg.close + 1
    const specifier = evaluateStaticSpecifier(source, arg.start, arg.end)
    found.push({
      specifier,
      start: arg.start,
      kind: specifier === null ? dynamicKind : staticKind,
      fromCall: true,
      bindings: specifier === null || isResolve ? [] : (bindings.get(arg.start) ?? []),
    })
  }
  return found
}

/** Conservative ESM import/export recovery for TypeScript Acorn cannot parse. */
function fallbackImportSpecifiers(content) {
  const source = withoutComments(content)
  const code = codePositions(source)
  const found = []
  const patterns = [
    { pattern: /(?:^|[;\r\n])\s*import\s*(['"])([^'"\r\n]+)\1/g, keyword: /\bimport\b/, kind: 'static-import', specifierGroup: 2 },
    { pattern: /(?:^|[;\r\n])\s*(?:import|export)\s+(?:type\s+)?[^;]{0,2000}?\bfrom\s*(['"])([^'"\r\n]+)\1/g, keyword: /\b(?:import|export)\b/, kind: 'static-import', specifierGroup: 2 },
  ]
  for (const { pattern, keyword, kind, specifierGroup } of patterns) {
    let match
    while ((match = pattern.exec(source)) !== null) {
      const keywordOffset = match[0].search(keyword)
      if (keywordOffset < 0 || code[match.index + keywordOffset] !== 1) continue
      const specifier = specifierGroup ? match[specifierGroup] : null
      const start = specifier === null
        ? match.index + match[0].length
        : match.index + match[0].lastIndexOf(specifier)
      found.push({ specifier, start, kind })
    }
  }
  found.push(...scanCallSpecifiers(source, code))
  const seen = new Set()
  return found
    .sort((a, b) => a.start - b.start || String(a.kind).localeCompare(String(b.kind)))
    .filter((item) => {
      const key = `${item.start}|${item.specifier}|${item.kind}`
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
}

function nodeFor(root, abs, content, ast) {
  return {
    path: relPath(root, abs),
    bytes: Buffer.byteLength(content),
    sha256: hash(content),
    parser: ast ? 'acorn' : 'unparsed',
    imports: ast ? importSpecifiers(ast).map((x) => x.specifier).filter((value) => value !== null) : [],
  }
}

/** Copy non-recoverable dynamic targets into report coverage without failing the scan. */
export function dynamicModuleCoverageSkips(graph) {
  return (graph?.warnings ?? [])
    .filter((warning) => warning?.reason === 'dynamic-module-specifier')
    .map((warning) => ({
      stage: 'module-graph',
      reason: warning.reason,
      path: warning.path,
      kind: warning.kind,
      ...(Number.isInteger(warning.start) ? { start: warning.start } : {}),
    }))
}

/**
 * Build a bounded module graph from seed files and statically recoverable imports.
 * Dynamic import()/require()/require.resolve() become edges only when the
 * specifier folds to a string. Unrecoverable targets are warnings, not edges.
 * @param {string} root scan root
 * @param {string[]} files relative seed paths
 * @returns {{nodes: object[], edges: object[], unresolved: object[], failures: object[], warnings: object[], complete: boolean}}
 */
export function buildModuleGraph(root, files = []) {
  const rootAbs = resolve(root)
  const nodes = []
  const edges = []
  const unresolved = []
  const failures = []
  const warnings = []
  const queue = [...new Set(files.map((f) => String(f).replace(/\\/g, '/')))]
  const seen = new Set()

  while (queue.length > 0) {
    const rel = queue.shift()
    if (seen.has(rel)) continue
    seen.add(rel)
    // 非 JS/TS 源码(如 .ps1/.py/.json 误入种子)不是模块图职责范围:跳过而非记 failure
    if (!SOURCE_EXTENSIONS.some((ext) => rel.toLowerCase().endsWith(ext))) continue
    const downgradeMissingImport = TEST_PATH.test(rel) || DECLARATION_PATH.test(rel) || isDevelopmentRunnerPath(rel)
    let abs
    try {
      abs = resolveInside(rootAbs, rel)
    } catch (error) {
      failures.push({ path: rel, reason: 'path-escape', detail: error?.message })
      continue
    }
    if (!existsSync(abs) || !statSync(abs).isFile()) {
      failures.push({ path: rel, reason: 'missing-file' })
      continue
    }
    let content
    try {
      content = readFileSync(abs, 'utf8')
    } catch (error) {
      failures.push({ path: rel, reason: 'read-error', detail: error?.code ?? error?.message })
      continue
    }
    const ast = parseJavaScript(content)
    const node = nodeFor(rootAbs, abs, content, ast)
    nodes.push(node)
    let imports
    if (ast) imports = importSpecifiers(ast)
    else {
      // TS/TSX/DTS 是 acorn 的能力边界:节点已带 parser:'unparsed' 降级标记,
      // 不记 failures(与语义引擎"AST 失败走兜底、不判完整性失败"的策略一致)。
      // 只有真正的 JS parse-error 才构成完整性信号。
      if (!TS_EXT.test(rel)) {
        failures.push({ path: rel, reason: 'parse-error' })
        continue
      }
      imports = fallbackImportSpecifiers(content)
      node.imports = imports.map((item) => item.specifier).filter((value) => value !== null)
      warnings.push({ path: rel, reason: 'parser-unparsed', fallback: 'static-module-specifiers', importsRecovered: imports.length })
    }
    for (const item of imports) {
      if (item.specifier === null) {
        warnings.push({ path: rel, reason: 'dynamic-module-specifier', kind: item.kind, start: item.start })
        continue
      }
      const result = resolveModuleSpecifier(rootAbs, rel, item.specifier)
      if (result.kind === 'external') {
        unresolved.push({ from: rel, specifier: item.specifier, external: true, start: item.start })
        continue
      }
      if (result.kind === 'failure') {
        const issue = { path: rel, specifier: item.specifier, reason: result.reason }
        if (downgradeMissingImport && result.reason === 'missing-file') warnings.push(issue)
        else failures.push(issue)
        continue
      }
      const target = relPath(rootAbs, result.abs)
      edges.push({
        from: rel,
        to: target,
        specifier: item.specifier,
        start: item.start,
        kind: item.kind ?? 'static-import',
        ...(item.fromCall ? { bindings: item.bindings ?? [] } : {}),
      })
      if (!seen.has(target)) queue.push(target)
    }
  }

  return {
    nodes,
    edges,
    unresolved,
    failures,
    warnings,
    complete: failures.length === 0,
  }
}
