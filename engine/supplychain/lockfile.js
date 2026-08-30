/**
 * 依赖 / Lockfile 识别与统计(§23)。
 * 支持:package-lock.json / npm-shrinkwrap.json / pnpm-lock.yaml / yarn.lock / bun.lock / bun.lockb
 * 只做静态解析,绝不安装。
 */

import { readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { buildDependencyGraph } from './dependency-graph.js'

export const LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'bun.lockb']

/** 目录内存在的 lockfile 名(按优先级),没有返回 null。 */
export function detectLockfile(dir) {
  for (const name of LOCKFILES) {
    try {
      if (statSync(join(dir, name)).isFile()) return name
    } catch {
      // try next
    }
  }
  return null
}

/**
 * 统计 lockfile 中的直接/传递依赖数量。
 * package-lock/shrinkwrap:精确(依赖 lockfile packages 图);
 * pnpm v9:精确(来自规范化 importers/packages/snapshots 图)。
 * yarn/bun:条目级估算(文档注明为估算值)。
 * @returns {{directDependencies: number, transitiveDependencies: number, dependencyCountComplete?: boolean, dependencyCountReason?: string}}
 */
export function countDependencies(dir, lockfileName) {
  const read = () => readFileSync(join(dir, lockfileName), 'utf8')
  try {
    if (lockfileName === 'package-lock.json' || lockfileName === 'npm-shrinkwrap.json') {
      const doc = JSON.parse(read())
      const packages = doc.packages ?? {}
      const root = packages[''] ?? {}
      const direct =
        Object.keys(root.dependencies ?? {}).length +
        Object.keys(root.devDependencies ?? {}).length +
        Object.keys(root.optionalDependencies ?? {}).length +
        Object.keys(root.peerDependencies ?? {}).length
      const total = Object.keys(packages).filter((k) => k !== '').length
      return { directDependencies: direct, transitiveDependencies: Math.max(0, total - direct) }
    }
    if (lockfileName === 'yarn.lock') {
      const text = read()
      const entries = (text.match(/^[^\s#][^:]*:$/gm) ?? []).length
      return { directDependencies: 0, transitiveDependencies: entries }
    }
    if (lockfileName === 'pnpm-lock.yaml') {
      const graph = buildDependencyGraph(dir, { lockfileName })
      if (graph.complete !== true) {
        return {
          directDependencies: 0,
          transitiveDependencies: 0,
          dependencyCountComplete: false,
          dependencyCountReason: graph.failures?.[0]?.reason ?? 'incomplete-graph',
        }
      }
      const directDependencies = graph.root?.directDependencies ?? 0
      const directInstances = (graph.nodes ?? []).filter((node) => node.direct === true).length
      return {
        directDependencies,
        transitiveDependencies: Math.max(0, (graph.nodes ?? []).length - directInstances),
        dependencyCountComplete: true,
      }
    }
    if (lockfileName === 'bun.lock') {
      const text = read()
      const entries = (text.match(/^[^\s#"][^:]*\{/gm) ?? []).length
      return { directDependencies: 0, transitiveDependencies: entries }
    }
  } catch {
    // unreadable / unparseable — 返回 0,不抛错(仅识别不阻塞)
  }
  // bun.lockb(二进制):只识别,统计为 0
  return { directDependencies: 0, transitiveDependencies: 0 }
}
