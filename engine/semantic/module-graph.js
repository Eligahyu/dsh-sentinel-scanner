/**
 * Read-only JavaScript/TypeScript module graph.
 *
 * This module never imports a target module. It parses import declarations and
 * resolves only files contained by the scan root. External packages are kept
 * as unresolved edges so callers can distinguish a graph gap from a package
 * boundary.
 */

import { createHash } from 'node:crypto'
import { existsSync, readFileSync, statSync } from 'node:fs'
import { dirname, extname, join, relative, resolve } from 'node:path'
import { parseJavaScript, walk, staticString, staticStringOf } from './ast.js'
import { resolveInside } from '../path-safety.js'

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
  const out = []
  walk(ast, (node) => {
    if (node.type === 'ImportDeclaration') {
      const specifier = staticString(node.source)
      if (specifier !== null) out.push({ specifier, start: node.source.start, kind: 'static-import' })
    } else if (node.type === 'ExportNamedDeclaration' || node.type === 'ExportAllDeclaration') {
      const specifier = staticString(node.source)
      if (specifier !== null) out.push({ specifier, start: node.source.start, kind: 'static-import' })
    } else if (node.type === 'ImportExpression') {
      const specifier = staticStringOf(node.source)
      out.push({
        specifier,
        start: node.source.start,
        kind: specifier === null ? 'dynamic-import' : 'static-import',
      })
    } else if (node.type === 'CallExpression' && node.arguments.length === 1) {
      const directRequire = node.callee?.type === 'Identifier' && node.callee.name === 'require'
      const requireResolve = node.callee?.type === 'MemberExpression'
        && node.callee.object?.type === 'Identifier'
        && node.callee.object.name === 'require'
        && ((!node.callee.computed && node.callee.property?.name === 'resolve')
          || (node.callee.computed && staticStringOf(node.callee.property) === 'resolve'))
      if (!directRequire && !requireResolve) return
      const specifier = staticStringOf(node.arguments[0])
      out.push({
        specifier,
        start: node.arguments[0].start,
        kind: specifier === null
          ? (requireResolve ? 'dynamic-require-resolve' : 'dynamic-require')
          : (requireResolve ? 'static-require-resolve' : 'static-require'),
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

/** Conservative ESM import/export recovery for TypeScript Acorn cannot parse. */
function fallbackImportSpecifiers(content) {
  const source = withoutComments(content)
  const code = codePositions(source)
  const found = []
  const patterns = [
    { pattern: /(?:^|[;\r\n])\s*import\s*(['"])([^'"\r\n]+)\1/g, keyword: /\bimport\b/, kind: 'static-import' },
    { pattern: /(?:^|[;\r\n])\s*(?:import|export)\s+(?:type\s+)?[^;]{0,2000}?\bfrom\s*(['"])([^'"\r\n]+)\1/g, keyword: /\b(?:import|export)\b/, kind: 'static-import' },
    { pattern: /(?<![\w$.])require\s*\.\s*resolve\s*\(\s*(['"])([^'"\r\n]+)\1\s*\)/g, keyword: /\brequire\b/, kind: 'static-require-resolve' },
    { pattern: /(?<![\w$.])require\s*\(\s*(['"])([^'"\r\n]+)\1\s*\)/g, keyword: /\brequire\b/, kind: 'static-require' },
  ]
  for (const { pattern, keyword, kind } of patterns) {
    let match
    while ((match = pattern.exec(source)) !== null) {
      const keywordOffset = match[0].search(keyword)
      if (keywordOffset < 0 || code[match.index + keywordOffset] !== 1) continue
      const specifier = match[2]
      const start = match.index + match[0].lastIndexOf(specifier)
      found.push({ specifier, start, kind })
    }
  }
  const seen = new Set()
  return found
    .sort((a, b) => a.start - b.start)
    .filter((item) => {
      const key = `${item.start}|${item.specifier}`
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

/**
 * Build a bounded module graph from seed files and their static imports.
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
    nodes.push(nodeFor(rootAbs, abs, content, ast))
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
      edges.push({ from: rel, to: target, specifier: item.specifier, start: item.start, kind: item.kind ?? 'static-import' })
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
