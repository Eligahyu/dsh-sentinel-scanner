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
 * pnpm v9 / yarn / bun:精确来自规范化依赖图;图失败时显式返回零计数和原因,
 * 绝不以缩进/正则估算冒充精确值。
 * @returns {{directDependencies: number, transitiveDependencies: number, dependencyCountComplete?: boolean, dependencyCountReason?: string}}
 */
export function countDependencies(dir, lockfileName) {
  try {
    if (lockfileName === 'package-lock.json' || lockfileName === 'npm-shrinkwrap.json') {
      const doc = JSON.parse(readFileSync(join(dir, lockfileName), 'utf8'))
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
    if (lockfileName === 'pnpm-lock.yaml' || lockfileName === 'yarn.lock'
      || lockfileName === 'bun.lock' || lockfileName === 'bun.lockb') {
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
  } catch {
    // 不可读 / 不可解析:返回显式不完整,不抛错、不伪造计数。
    return {
      directDependencies: 0,
      transitiveDependencies: 0,
      dependencyCountComplete: false,
      dependencyCountReason: 'read-or-parse-error',
    }
  }
  return {
    directDependencies: 0,
    transitiveDependencies: 0,
    dependencyCountComplete: false,
    dependencyCountReason: 'unsupported-lockfile',
  }
}
