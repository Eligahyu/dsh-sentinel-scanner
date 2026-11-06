/**
 * AST 层:Acorn 解析 JS、oxc-parser 解析 TypeScript/TSX,并提供 import/别名/调用识别。
 *
 * confidence 语义:
 *   - AST 精确识别 → confidence: high
 *   - 正则兜底(解析失败/非 JS 变体)→ confidence: medium
 *
 * 解析器加载策略:
 *   - JS:优先包依赖 acorn;缺失时回退仓库内 vendored 副本
 *     (.github/actions/dsh-sentinel/vendor/,供自包含 GitHub Action 运行时使用)。
 *   - TS/TSX/MTS/CTS:按需加载 oxc-parser(native addon,带 WASI 回退)。
 *     加载或解析失败时返回结构化错误,调用方必须显式降级并报告,绝不猜测边。
 *
 * 红线:只解析文本,绝不执行被扫描代码,也不依赖 TypeScript 编译器做类型检查。
 */

let acornParse = null
try {
  const acorn = await import('acorn')
  acornParse = acorn.parse
} catch {
  try {
    const vendored = await import('../../.github/actions/dsh-sentinel/vendor/acorn.mjs')
    acornParse = vendored.parse
  } catch {
    acornParse = null
  }
}

let oxcParseSync = null
let oxcLoadError = null
try {
  const oxc = await import('oxc-parser')
  oxcParseSync = oxc.parseSync
} catch (error) {
  oxcLoadError = error
}

/** TypeScript 源码扩展名。`.d.ts` 也以 `.ts` 结尾。 */
export const TYPESCRIPT_EXT = /\.(?:tsx?|mts|cts)$/i
/** 可由 AST 语义层处理的 JS/TS 扩展名。 */
export const AST_SOURCE_EXT = /\.(?:[cm]?js|jsx|tsx?|mts|cts)$/i

export function isTypeScriptPath(relPath) {
  return TYPESCRIPT_EXT.test(String(relPath ?? ''))
}

function typescriptLanguage(relPath) {
  const path = String(relPath ?? '').toLowerCase()
  if (/\.d\.(?:ts|mts|cts)$/.test(path)) return 'dts'
  if (path.endsWith('.tsx')) return 'tsx'
  return 'ts'
}

/** 解析 JS(保留 Acorn;先 module,再 script)。 */
export function parseJavaScript(code) {
  if (typeof acornParse !== 'function') return null
  const options = { ecmaVersion: 'latest', sourceType: 'module', allowHashBang: true, allowReturnOutsideFunction: true }
  try {
    return acornParse(code, options)
  } catch {
    try {
      return acornParse(code, { ...options, sourceType: 'script' })
    } catch {
      return null
    }
  }
}

function parseErrorMessage(error) {
  const message = error?.message ?? (typeof error === 'string' ? error : String(error))
  return message.length > 240 ? `${message.slice(0, 239)}…` : message
}

/**
 * 解析 TypeScript/TSX/MTS/CTS。
 * @returns {{ast: object|null, parser: 'oxc', errors: object[], available: boolean}}
 *   errors 非空表示本次解析不可用,调用方必须走静态 recovery 并记录 warning。
 */
export function parseTypeScript(code, relPath = 'input.ts') {
  if (typeof oxcParseSync !== 'function') {
    return {
      ast: null,
      parser: 'oxc',
      available: false,
      errors: [{ message: oxcLoadError ? `oxc-parser unavailable: ${parseErrorMessage(oxcLoadError)}` : 'oxc-parser unavailable' }],
    }
  }
  try {
    const result = oxcParseSync(String(relPath), code, {
      sourceType: 'module',
      lang: typescriptLanguage(relPath),
    })
    const errors = Array.isArray(result?.errors) ? result.errors : []
    const blocking = errors.filter((error) => error?.severity !== 'Warning' && error?.severity !== 'Advice')
    if (blocking.length > 0) {
      return {
        ast: null,
        parser: 'oxc',
        available: true,
        errors: blocking.slice(0, 8).map((error) => ({
          message: parseErrorMessage(error?.message ?? 'TypeScript parse error'),
          ...(Number.isInteger(error?.labels?.[0]?.start) ? { start: error.labels[0].start } : {}),
        })),
      }
    }
    return { ast: result?.program ?? null, parser: 'oxc', available: true, errors: [] }
  } catch (error) {
    return {
      ast: null,
      parser: 'oxc',
      available: true,
      errors: [{ message: parseErrorMessage(error) }],
    }
  }
}

/**
 * 按扩展名选择解析器:JS → Acorn,TS → oxc。
 * 非 JS/TS 源码返回 parser:'unsupported',由调用方决定是否走正则。
 */
export function parseSource(code, relPath) {
  if (isTypeScriptPath(relPath)) return parseTypeScript(code, relPath)
  if (!AST_SOURCE_EXT.test(String(relPath ?? ''))) {
    return { ast: null, parser: 'unsupported', available: false, errors: [] }
  }
  const ast = parseJavaScript(code)
  return {
    ast,
    parser: ast ? 'acorn' : 'unparsed',
    available: typeof acornParse === 'function',
    errors: ast ? [] : [{ message: 'acorn parse error' }],
  }
}

const EXPRESSION_WRAPPERS = new Set([
  'ParenthesizedExpression',
  'TSAsExpression',
  'TSTypeAssertion',
  'TSNonNullExpression',
  'TSSatisfiesExpression',
  'TSInstantiationExpression',
  'TypeCastExpression',
])

/** 去掉 TS 断言/非空/括号包装,便于按值语义匹配 callee 与字符串字面量。 */
export function unwrapExpression(node) {
  let current = node
  while (current && typeof current.type === 'string' && EXPRESSION_WRAPPERS.has(current.type)) {
    current = current.expression
  }
  return current
}

/** 简单 AST 遍历。 */
export function walk(node, visit) {
  if (!node || typeof node.type !== 'string') return
  visit(node)
  for (const key of Object.keys(node)) {
    if (key === 'type' || key === 'start' || key === 'end' || key === 'loc' || key === 'range') continue
    const child = node[key]
    if (Array.isArray(child)) {
      for (const c of child) if (c && typeof c.type === 'string') walk(c, visit)
    } else if (child && typeof child.type === 'string') {
      walk(child, visit)
    }
  }
}

/** 解析静态字符串字面量(含模板无插值 / TS 断言包装)。 */
export function staticString(node) {
  if (!node) return null
  const target = unwrapExpression(node)
  if (!target) return null
  if (target.type === 'Literal' && typeof target.value === 'string') return target.value
  if (target.type === 'TemplateLiteral' && target.expressions.length === 0 && target.quasis.length === 1) {
    return target.quasis[0].value.cooked
  }
  return null
}

/** 解析常量表达式:字符串字面量 / 模板 / 常量 '+' 拼接('ex'+'ec' → 'exec')。 */
export function staticStringOf(node) {
  const target = unwrapExpression(node)
  const direct = staticString(target)
  if (direct !== null) return direct
  if (target?.type === 'BinaryExpression' && target.operator === '+') {
    const left = staticStringOf(target.left)
    const right = staticStringOf(target.right)
    if (left !== null && right !== null) return left + right
  }
  return null
}

/**
 * 解析调用目标名:
 *   - Identifier: 'exec'
 *   - MemberExpression: 'cp.exec' / 'process.env' / 计算属性 'cp['ex'+'ec']' → 'cp.exec'
 * @returns {string|null} 归一化调用名(如 'cp.exec')
 */
export function calleeName(node) {
  const target = unwrapExpression(node)
  if (!target) return null
  if (target.type === 'Identifier') return target.name
  if (target.type === 'MemberExpression') {
    const obj = calleeName(target.object)
    if (obj === null) return null
    if (!target.computed) {
      if (target.property.type === 'Identifier') return `${obj}.${target.property.name}`
      return null
    }
    // 计算属性:字符串字面量或 'ex'+'ec' 拼接
    const prop = staticStringOf(target.property)
    if (prop !== null) return `${obj}.${prop}`
    return null
  }
  return null
}

/** 需要 import 绑定确认的模块(P1-3):child_process 与 node:fs 系。 */
const BINDABLE_MODULES = new Set([
  'child_process', 'node:child_process',
  'fs', 'node:fs', 'fs/promises', 'node:fs/promises',
])

/**
 * type-only import 是编译期擦除的,不构成运行时边,也不能确认 sink 绑定。
 * 空 specifier(`import './x'`)是副作用导入,仍属运行时。
 */
export function importDeclarationHasRuntimeBinding(node) {
  if (!node || node.type !== 'ImportDeclaration') return false
  if (node.importKind === 'type') return false
  if (!Array.isArray(node.specifiers) || node.specifiers.length === 0) return true
  return node.specifiers.some((spec) => spec?.importKind !== 'type')
}

/** export type / export type * / 全部 specifier 均为 type 的 re-export 不建运行时边。 */
export function exportDeclarationHasRuntimeBinding(node) {
  if (!node) return false
  if (node.exportKind === 'type') return false
  if (node.type === 'ExportAllDeclaration') return true
  if (Array.isArray(node.specifiers) && node.specifiers.length > 0) {
    return node.specifiers.some((spec) => spec?.exportKind !== 'type')
  }
  return true
}

/**
 * 收集 import/require 信息:
 * @returns {{ imports: Map<string,string>, aliases: Map<string,string>, cpVars: Set<string> }}
 *   imports: 模块名 → 本地绑定(默认导出/命名)
 *   aliases: 本地名 → 原始名(child_process/fs 解构别名等)
 *   cpVars: 绑定到 child_process/fs 的命名空间变量
 */
export function collectImports(ast) {
  const imports = new Map()
  const aliases = new Map()
  const cpVars = new Set()
  walk(ast, (node) => {
    // ESM import(type-only 不参与运行时绑定)
    if (node.type === 'ImportDeclaration') {
      if (!importDeclarationHasRuntimeBinding(node)) return
      const mod = node.source?.value
      if (typeof mod !== 'string') return
      for (const spec of node.specifiers) {
        if (spec.importKind === 'type') continue
        if (spec.type === 'ImportDefaultSpecifier' || spec.type === 'ImportNamespaceSpecifier') {
          imports.set(spec.local.name, mod)
          if (BINDABLE_MODULES.has(mod)) cpVars.add(spec.local.name)
        } else if (spec.type === 'ImportSpecifier') {
          const orig = staticString(spec.imported) ?? spec.imported?.name
          if (typeof orig !== 'string') continue
          if (BINDABLE_MODULES.has(mod)) aliases.set(spec.local.name, orig)
          imports.set(spec.local.name, `${mod}:${orig}`)
        }
      }
    }
    // TS `import fs = require('node:fs')`(type-only 版本直接跳过)
    if (node.type === 'TSImportEqualsDeclaration' && node.importKind !== 'type') {
      const mod = staticString(node.moduleReference?.expression)
      if (typeof mod === 'string') {
        const local = node.id?.name
        if (local) {
          imports.set(local, mod)
          if (BINDABLE_MODULES.has(mod)) cpVars.add(local)
        }
      }
    }
    // CJS require
    if (node.type === 'VariableDeclarator' && node.init && node.init.type === 'CallExpression') {
      const callee = calleeName(node.init.callee)
      if (callee === 'require') {
        const mod = staticString(node.init.arguments[0])
        if (BINDABLE_MODULES.has(mod)) {
          if (node.id.type === 'Identifier') cpVars.add(node.id.name)
          else if (node.id.type === 'ObjectPattern') {
            for (const prop of node.id.properties) {
              const key = prop.key?.name ?? staticString(prop.key)
              const local = prop.value?.name
              if (key && local) aliases.set(local, key)
            }
          }
        }
      }
    }
  })
  return { imports, aliases, cpVars }
}

/** 收集 child_process 别名:const { exec: run } = require(...) / import { exec as run } / const cp = require(...)。 */
export function collectAliases(content) {
  const aliases = new Map()
  // `[^{}]*` keeps matching linear on untrusted source and cannot wander across
  // unrelated object literals while looking for a later require/import call.
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
      if (!t || /^type\s+/.test(t)) continue // `import { type exec }` 是类型位置
      const mm = /([A-Za-z_$][\w$]*)\s*(?:as\s+([A-Za-z_$][\w$]*))?/.exec(t)
      if (mm) aliases.set(mm[2] ?? mm[1], mm[1])
    }
  }
  const cpVarRe = /(?:const|let|var)\s+(cp|child_process)\s*=\s*require\s*\(\s*['"](?:node:)?child_process['"]\s*\)/g
  while ((m = cpVarRe.exec(content)) !== null) {
    for (const name of ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork']) {
      aliases.set(`${m[1]}.${name}`, name)
    }
  }
  return aliases
}

/**
 * 解析表达式中的标识符引用(用于污点变量跟踪)。
 * @returns {Set<string>} 引用的变量名集合
 */
export function referencedIdentifiers(exprNode) {
  const names = new Set()
  walk(exprNode, (n) => {
    if (n.type === 'Identifier') names.add(n.name)
    if (n.type === 'MemberExpression' && n.object.type === 'Identifier') names.add(n.object.name)
  })
  return names
}
