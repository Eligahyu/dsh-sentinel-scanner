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

/** 从 cwd(或显式路径)加载配置;文件缺失返回默认值。 */
export function loadConfig({ cwd = process.cwd(), configPath = null } = {}) {
  const candidates = configPath
    ? [resolve(cwd, configPath)]
    : [join(cwd, CONFIG_FILENAME)]
  for (const p of candidates) {
    if (!existsSync(p)) continue
    try {
      const raw = JSON.parse(readFileSync(p, 'utf8'))
      const cfg = { ...DEFAULT_CONFIG }
      for (const key of Object.keys(DEFAULT_CONFIG)) {
        if (raw[key] !== undefined) cfg[key] = raw[key]
      }
      return { config: cfg, source: p }
    } catch (error) {
      throw new Error(`sentinel.config.json 解析失败(${p}): ${error.message}`)
    }
  }
  return { config: { ...DEFAULT_CONFIG }, source: null }
}

/** 合并 CLI 覆盖项(undefined 表示未提供)。 */
export function mergeOverrides(config, overrides = {}) {
  const out = { ...config }
  for (const key of Object.keys(overrides)) {
    if (overrides[key] !== undefined && overrides[key] !== null) out[key] = overrides[key]
  }
  return out
}
