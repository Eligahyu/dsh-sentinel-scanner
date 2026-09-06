/**
 * 路径 containment:manifest(patch / main / exports / bin / 入口名)中的任何路径
 * 都视为不可信输入,禁止解析到扫描根目录之外(如 ../../Users/xxx/.ssh/id_rsa)。
 *
 * 三层校验:
 *   1. lexical containment — normalize/resolve 后的前缀校验
 *   2. platform-aware case  — 仅 Windows 大小写不敏感(win32);POSIX 严格区分
 *   3. real containment    — realpath 解析(目标存在时),配合 path.relative 判定;
 *                            目标不存在时退回词法校验
 *   4. symlink policy      — manifest 派生路径的中间段出现符号链接一律拒绝
 *                            (patch/main/exports/plugin entry 不允许穿越 symlink)
 */

import { resolve, normalize, sep, relative, join, isAbsolute } from 'node:path'
import { realpathSync, lstatSync } from 'node:fs'

/** 仅 Windows 大小写不敏感;macOS 卷格式不定,不强行假定,交给 realpath。 */
export const CASE_INSENSITIVE = process.platform === 'win32'

/** 候选路径逃逸出扫描根目录时抛出。 */
export class PathEscapeError extends Error {
  constructor(candidate) {
    super(`path escapes scan root: ${candidate}`)
    this.name = 'PathEscapeError'
    this.candidate = candidate
  }
}

/** 候选绝对路径是否位于 root(含 root 本身)之内(词法,平台大小写规则)。 */
export function isInsideRoot(root, candidate) {
  const r = normalize(resolve(root))
  const c = normalize(resolve(candidate))
  const a = CASE_INSENSITIVE ? r.toLowerCase() : r
  const b = CASE_INSENSITIVE ? c.toLowerCase() : c
  return b === a || b.startsWith(a + sep)
}

/**
 * 仅作词法 containment，不对 candidate 调用 realpath。
 *
 * 适用于先 lstat、再以描述符验证的遍历：对不可信子项调用 realpath 会在
 * 链接替换窗口中跟随攻击者的目标。调用方仍须负责打开后的 inode 校验。
 */
export function resolveLexicallyInside(root, candidate) {
  const rootPath = normalize(resolve(root))
  const candidatePath = normalize(resolve(rootPath, candidate))
  if (!isInsideRoot(rootPath, candidatePath)) throw new PathEscapeError(candidate)
  return candidatePath
}

/**
 * filesystem-real containment:双方 realpath 后,用 path.relative 判定。
 * 目标不存在/无权限时退回词法校验(不因缺 realpath 而拒绝合法路径)。
 */
export function isInsideRootReal(root, candidate) {
  let rootReal
  try {
    rootReal = realpathSync(root)
  } catch {
    return isInsideRoot(root, candidate)
  }
  let candidateReal
  try {
    candidateReal = realpathSync(candidate)
  } catch {
    return isInsideRoot(root, candidate)
  }
  const rel = relative(rootReal, candidateReal)
  return rel === '' || (!rel.startsWith('..' + sep) && rel !== '..' && !isAbsolute(rel))
}

/**
 * manifest 派生路径逐级 symlink 检查:从 root 到 candidate 的每一级中间段
 * 若存在符号链接(junction 在 Windows 上由 realpath 层兜底),一律拒绝。
 * 简单、安全、可解释:manifest-derived paths may not traverse symlink。
 */
function hasSymlinkSegment(root, abs) {
  const relPart = relative(root, abs)
  if (relPart === '' || relPart === '..' || relPart.startsWith('..' + sep)) return false
  let cur = root
  for (const seg of relPart.split(sep)) {
    if (seg === '' || seg === '.') continue
    cur = join(cur, seg)
    let st = null
    try {
      st = lstatSync(cur)
    } catch {
      break // 中间路径不存在,后面也不再存在
    }
    if (st.isSymbolicLink()) return true
  }
  return false
}

/**
 * 把 candidate 解析为 root 内的绝对路径;若逃逸(词法/realpath)或穿越
 * symlink 则抛 PathEscapeError。candidate 可以是相对或绝对路径,均按绝对校验。
 * mustExist:true 时目标不存在同样抛 PathEscapeError(调用方据此跳过读取)。
 */
export function resolveInside(root, candidate, { mustExist = false } = {}) {
  const abs = resolve(root, candidate)
  if (!isInsideRoot(root, abs)) throw new PathEscapeError(candidate)
  if (!isInsideRootReal(root, abs)) throw new PathEscapeError(candidate)
  if (hasSymlinkSegment(root, abs)) throw new PathEscapeError(candidate)
  if (mustExist) {
    try {
      lstatSync(abs)
    } catch {
      throw new PathEscapeError(candidate)
    }
  }
  return abs
}
