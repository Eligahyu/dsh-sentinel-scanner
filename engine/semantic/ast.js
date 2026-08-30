/**
 * AST 层(Phase 4):acorn 解析 + import/别名/调用识别(含计算属性)。
 *
 * confidence 语义:
 *   - AST 精确识别 → confidence: high
 *   - 正则兜底(解析失败/非 JS 变体)→ confidence: medium
 *
 * acorn 加载:优先包依赖;缺失时回退仓库内 vendored 副本
 * (.github/actions/dsh-sentinel/vendor/,供自包含 GitHub Action 运行时使用)。
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

/** 解析 JS/TS(TS 语法用宽松模式兜底:先按最新 ECMAScript 解析)。 */
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

/** 解析静态字符串字面量(含模板无插值)。 */
export function staticString(node) {
  if (!node) return null
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0 && node.quasis.length === 1) {
    return node.quasis[0].value.cooked
  }
  return null
}

/** 解析常量表达式:字符串字面量 / 模板 / 常量 '+' 拼接('ex'+'ec' → 'exec')。 */
export function staticStringOf(node) {
  const direct = staticString(node)
  if (direct !== null) return direct
  if (node?.type === 'BinaryExpression' && node.operator === '+') {
    const left = staticStringOf(node.left)
    const right = staticStringOf(node.right)
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
  if (!node) return null
  if (node.type === 'Identifier') return node.name
  if (node.type === 'MemberExpression') {
    const obj = calleeName(node.object)
    if (obj === null) return null
    if (!node.computed) {
      if (node.property.type === 'Identifier') return `${obj}.${node.property.name}`
      return null
    }
    // 计算属性:字符串字面量或 'ex'+'ec' 拼接
    const prop = staticStringOf(node.property)
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
 * 收集 import/require 信息:
 * @returns {{ imports: Map<string,string>, aliases: Map<string,string>, cpVars: Set<string> }}
 *   imports: 模块名 → 本地绑定(默认导出/命名)
 *   aliases: 本地名 → 原始名(child_process/fs 解构别名等)
 */
export function collectImports(ast) {
  const imports = new Map()
  const aliases = new Map()
  const cpVars = new Set()
  walk(ast, (node) => {
    // ESM import
    if (node.type === 'ImportDeclaration') {
      const mod = node.source?.value
      if (typeof mod !== 'string') return
      for (const spec of node.specifiers) {
        if (spec.type === 'ImportDefaultSpecifier' || spec.type === 'ImportNamespaceSpecifier') {
          imports.set(spec.local.name, mod)
        } else if (spec.type === 'ImportSpecifier') {
          const orig = spec.imported.name
          if (BINDABLE_MODULES.has(mod)) aliases.set(spec.local.name, orig)
          imports.set(spec.local.name, `${mod}:${orig}`)
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
