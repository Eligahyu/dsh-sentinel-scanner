/**
 * 配置文件加载:sentinel.config.json(项目级)。
 *
 * 优先级:CLI 参数 > 配置文件 > 内置默认。
 * 安全工具的 ignore/skip 必须进入报告(调用方负责把 ignored 汇总进报告),
 * 绝不允许静默忽略。redactSecrets 永远开启,config 中 false 会被忽略并警告。
 */

import { readFileSync, existsSync } from 'node:fs'
import { join, resolve } from 'node:path'

export const CONFIG_FILENAME = 'sentinel.config.json'

export const DEFAULT_CONFIG = Object.freeze({
  mode: 'source',
  maxFiles: 3000,
  maxBytesPerFile: 512 * 1024,
  hardMaxBytesPerFile: 20 * 1024 * 1024,
  maxFindings: 300,
  maxPlugins: 12,
  trustedScopes: ['@deepseek-ai'],
  ignore: [],
  includeBuildArtifacts: false,
  redactSecrets: true,
  redactPaths: false,
  advisories: false,
  failOn: 'high',
  dynamic: false,
  dynamicBackend: 'auto',
  dynamicProfile: 'observe',
  dynamicTimeoutMs: 15000,
})

const MODES = new Set(['source', 'package', 'profile'])
const FAIL_ON = new Set(['critical', 'high', 'medium', 'low'])
const DYNAMIC_BACKENDS = new Set(['auto', 'docker', 'podman'])
const DYNAMIC_PROFILES = new Set(['observe'])
const BOOLEAN_KEYS = ['includeBuildArtifacts', 'redactSecrets', 'redactPaths', 'advisories', 'dynamic']
const POSITIVE_INT_KEYS = ['maxFiles', 'maxBytesPerFile', 'hardMaxBytesPerFile', 'maxFindings', 'maxPlugins']

function isPositiveInt(value) {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1
}

function isStringList(value) {
  return Array.isArray(value) && value.every((item) => typeof item === 'string' && item.trim().length > 0)
}

/**
 * Validate a parsed config object. Unknown keys are not copied onto the
 * effective config; they are returned as warnings so typos stay visible
 * without becoming executable settings.
 * @param {object} raw
 * @param {string} source
 * @returns {string[]} warnings
 */
export function validateConfig(raw, source = CONFIG_FILENAME) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error(`sentinel.config.json 无效(${source}): 根必须是 JSON 对象`)
  }
  const errors = []
  const warnings = []
  for (const key of Object.keys(raw)) {
    if (!Object.hasOwn(DEFAULT_CONFIG, key)) warnings.push(`忽略未知字段 ${key}(不会生效)`)
  }
  if (raw.mode !== undefined && !MODES.has(raw.mode)) {
    errors.push(`mode 必须是 source|package|profile (got ${JSON.stringify(raw.mode)})`)
  }
  if (raw.failOn !== undefined && !FAIL_ON.has(raw.failOn)) {
    errors.push(`failOn 必须是 critical|high|medium|low (got ${JSON.stringify(raw.failOn)})`)
  }
  if (raw.dynamicBackend !== undefined && !DYNAMIC_BACKENDS.has(raw.dynamicBackend)) {
    errors.push(`dynamicBackend 必须是 auto|docker|podman (got ${JSON.stringify(raw.dynamicBackend)})`)
  }
  if (raw.dynamicProfile !== undefined && !DYNAMIC_PROFILES.has(raw.dynamicProfile)) {
    errors.push(`dynamicProfile 必须是 observe (got ${JSON.stringify(raw.dynamicProfile)})`)
  }
  if (raw.dynamicTimeoutMs !== undefined && (typeof raw.dynamicTimeoutMs !== 'number' || !Number.isFinite(raw.dynamicTimeoutMs))) {
    errors.push('dynamicTimeoutMs 必须是有限数字')
  }
  for (const key of BOOLEAN_KEYS) {
    if (raw[key] !== undefined && typeof raw[key] !== 'boolean') {
      errors.push(`${key} 必须是布尔值`)
    }
  }
  for (const key of POSITIVE_INT_KEYS) {
    if (raw[key] !== undefined && !isPositiveInt(raw[key])) {
      errors.push(`${key} 必须是正整数`)
    }
  }
  if (isPositiveInt(raw.maxBytesPerFile) && isPositiveInt(raw.hardMaxBytesPerFile) && raw.hardMaxBytesPerFile < raw.maxBytesPerFile) {
    errors.push('hardMaxBytesPerFile 不能小于 maxBytesPerFile')
  }
  if (raw.ignore !== undefined && !isStringList(raw.ignore)) {
    errors.push('ignore 必须是非空字符串数组')
  }
  if (raw.trustedScopes !== undefined && !isStringList(raw.trustedScopes)) {
    errors.push('trustedScopes 必须是非空字符串数组')
  }
  if (errors.length > 0) {
    throw new Error(`sentinel.config.json 无效(${source}): ${errors.join('; ')}`)
  }
  return warnings
}

/** 从 cwd(或显式路径)加载配置;文件缺失返回默认值。 */
export function loadConfig({ cwd = process.cwd(), configPath = null } = {}) {
  const candidates = configPath
    ? [resolve(cwd, configPath)]
    : [join(cwd, CONFIG_FILENAME)]
  for (const p of candidates) {
    if (!existsSync(p)) continue
    let raw
    try {
      raw = JSON.parse(readFileSync(p, 'utf8'))
    } catch (error) {
      throw new Error(`sentinel.config.json 解析失败(${p}): ${error.message}`)
    }
    const warnings = validateConfig(raw, p)
    const cfg = { ...DEFAULT_CONFIG }
    for (const key of Object.keys(DEFAULT_CONFIG)) {
      if (raw[key] !== undefined) cfg[key] = raw[key]
    }
    return { config: cfg, source: p, warnings }
  }
  return { config: { ...DEFAULT_CONFIG }, source: null, warnings: [] }
}

/** 合并 CLI 覆盖项(undefined 表示未提供)。 */
export function mergeOverrides(config, overrides = {}) {
  const out = { ...config }
  for (const key of Object.keys(overrides)) {
    if (overrides[key] !== undefined && overrides[key] !== null) out[key] = overrides[key]
  }
  return out
}
