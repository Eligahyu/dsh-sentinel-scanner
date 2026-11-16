/**
 * tarball 获取 + 隔离解包 + 完整性校验。
 * 红线:解包后不运行 npm install,不执行任何生命周期脚本(preinstall/install/postinstall/prepare)。
 * 解包使用自包含安全解析(engine/package/tar.js):防 traversal / symlink / tar bomb。
 */

import { createHash } from 'node:crypto'
import { readFileSync, rmSync, mkdirSync, readdirSync, renameSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { extractTarballSafe, TarSafetyError } from './tar.js'
import { boundedHttpRequest } from '../supplychain/http-client.js'

/** sha512 base64 integrity(npm 格式)与文件内容比对。 */
export function verifyIntegrity(filePath, integrity) {
  if (!integrity) return { ok: false, reason: 'no-integrity-field' }
  const m = /^sha512-([A-Za-z0-9+/=]+)$/.exec(integrity)
  if (!m) return { ok: false, reason: 'unsupported-integrity-format' }
  const expected = m[1]
  const actual = createHash('sha512').update(readFileSync(filePath)).digest('base64')
  return { ok: actual === expected, actual, expected }
}

/** 文件 sha256 十六进制(报告用)。 */
export function fileSha256(filePath) {
  return createHash('sha256').update(readFileSync(filePath)).digest('hex')
}

/** tarball 下载体上限(§9.4:超大/恶意 tarball 绝不整包落盘)。 */
export const TARBALL_MAX_BYTES = 512 * 1024 * 1024

/** Whole-transfer deadline, including redirects. Matches the previous curl --max-time 120. */
export const TARBALL_TIMEOUT_MS = 120_000

/** Process-scoped temporary artifact name to prevent concurrent test/process interference. */
export function temporaryArtifactName(kind, suffix = '') {
  return `sentinel-${kind}-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}${suffix}`
}

/**
 * 下载 tarball 到临时文件并校验 integrity。
 * @param {string} tarballUrl
 * @param {string} integrity
 * @param {object} [opts] - {maxBytes, timeoutMs, strictDns}
 * @returns {Promise<{tarballPath: string, sha256: string, integrityOk: boolean, integrityReason?: string}>}
 */
export async function downloadTarball(tarballUrl, integrity, opts = {}) {
  const maxBytes = opts.maxBytes ?? TARBALL_MAX_BYTES
  const tarballPath = join(tmpdir(), temporaryArtifactName('pkg', '.tgz'))
  // 字节上限在传输中生效;失败/超限/partial 一律删除(§9.4)。
  // 重定向仅在最终响应落盘。strict DNS 时每个跳转目标都重新检查。
  const timeoutMs = opts.timeoutMs ?? TARBALL_TIMEOUT_MS
  const guard = opts.strictDns
    ? async (href) => {
      const { assertPublicDns } = await import('../supplychain/fetch.js')
      await assertPublicDns(href, { strict: true })
    }
    : null
  try {
    await boundedHttpRequest(tarballUrl, {
      method: 'GET',
      maxBytes,
      timeoutMs,
      followRedirects: true,
      destination: tarballPath,
      guard,
    })
  } catch (error) {
    rmSync(tarballPath, { force: true })
    if (String(error?.message ?? '').startsWith('SSRF guard:')) throw error
    const reason = error?.code ?? 'failed'
    throw new Error(`tarball 下载失败:${tarballUrl} (${reason})`)
  }
  const integrityResult = verifyIntegrity(tarballPath, integrity)
  return {
    tarballPath,
    sha256: fileSha256(tarballPath),
    integrityOk: integrityResult.ok,
    integrityReason: integrityResult.reason,
  }
}

/**
 * 把 tarball 解包到隔离目录(quarantine)。绝不执行包内任何脚本。
 * 资源所有权(P0-3):downloadTarball() 创建 tarball,extractTarball() 接管其生命周期——
 * 成功 cleanup / TarSafetyError / 任意解包异常,都由本函数删除 tarball 与 quarantine。
 * cleanup 幂等(重复调用安全)。
 * @returns {Promise<{dir: string, cleanup: () => void, entries: number, unpackedBytes: number}>}
 */
export async function extractTarball(tarballPath) {
  const base = join(tmpdir(), temporaryArtifactName('quarantine'))
  const extractDir = join(base, 'x')
  mkdirSync(extractDir, { recursive: true })
  let stats
  try {
    stats = extractTarballSafe(tarballPath, extractDir)
  } catch (error) {
    // 任意解包失败(TarSafetyError / FS error / invalid gzip):quarantine + tgz 都删
    rmSync(base, { recursive: true, force: true })
    rmSync(tarballPath, { force: true })
    throw error
  }
  // npm tarball 内容在 package/ 下;若缺则用整个解包目录。
  const pkgDir = join(extractDir, 'package')
  let dir
  try {
    dir = readdirSync(extractDir).length === 1 && readdirSync(extractDir)[0] === 'package'
      ? pkgDir
      : extractDir
  } catch {
    dir = extractDir
  }
  let cleaned = false
  const cleanup = () => {
    if (cleaned) return
    cleaned = true
    rmSync(base, { recursive: true, force: true })
    rmSync(tarballPath, { force: true })
  }
  return { dir, cleanup, entries: stats.entries, unpackedBytes: stats.unpackedBytes }
}

/** 把已解包的 package/ 内容平铺到目标目录(与 npm pack 布局一致)。 */
export function flattenPackage(srcDir, destDir) {
  mkdirSync(destDir, { recursive: true })
  for (const entry of readdirSync(srcDir)) {
    renameSync(join(srcDir, entry), join(destDir, entry))
  }
}

export { TarSafetyError }
