/**
 * npm 包元数据获取(安装前审计的第一步)。
 * 只读取 package metadata(名称/版本/tarball/integrity),不上传任何源码。
 */

import { boundedHttpRequest } from '../supplychain/http-client.js'

/** registry 地址:每次调用读取(可被测试/镜像覆盖,不受模块缓存影响)。 */
export function npmRegistry() {
  return process.env.SENTINEL_NPM_REGISTRY ?? 'https://registry.npmjs.org'
}

/** 解析 'name' 或 'name@version' 规格。 */
export function parsePackageSpec(spec) {
  const s = spec.trim()
  const at = s.lastIndexOf('@')
  if (at <= 0) return { name: s, version: null }
  return { name: s.slice(0, at), version: s.slice(at + 1) }
}

/** metadata 响应体上限(§9.2:先限流再读取,绝不整读超限响应)。 */
export const METADATA_MAX_BYTES = 5 * 1024 * 1024

/** Metadata request deadline. Matches the previous curl --max-time 30. */
export const METADATA_TIMEOUT_MS = 30_000

/**
 * Fetch URL text with a hard byte cap and deadline.
 * Redirects are not followed (registry metadata is read from the requested URL).
 * Transport failures return null so the caller can report a registry error.
 */
async function fetchText(url, { maxBytes = METADATA_MAX_BYTES, timeoutMs = METADATA_TIMEOUT_MS } = {}) {
  try {
    const result = await boundedHttpRequest(url, {
      method: 'GET',
      headers: { accept: 'application/json' },
      maxBytes,
      timeoutMs,
      followRedirects: false,
    })
    return result.body ? result.body.toString('utf8') : ''
  } catch {
    return null
  }
}

/**
 * 获取 npm 包元数据(仅 metadata,不下载 tarball)。
 * @param {string} spec - 'name' 或 'name@version'
 * @param {object} [opts] - {maxBytes, timeoutMs}
 * @returns {Promise<{name, version, dist: {tarball, integrity, shasum}, dependencies, scripts}>}
 */
export async function acquireNpmPackage(spec, opts = {}) {
  const { name, version } = parsePackageSpec(spec)
  if (!name) throw new Error(`invalid package spec: ${spec}`)
  const url = version
    ? `${npmRegistry()}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`
    : `${npmRegistry()}/${encodeURIComponent(name)}/latest`
  const text = await fetchText(url, {
    maxBytes: opts.maxBytes ?? METADATA_MAX_BYTES,
    timeoutMs: opts.timeoutMs ?? METADATA_TIMEOUT_MS,
  })
  if (text === null || !text.trim().startsWith('{')) {
    throw new Error(`无法获取 npm 元数据:${name}@${version ?? 'latest'}(注册表不可达或包不存在)`)
  }
  let doc
  try {
    doc = JSON.parse(text)
  } catch {
    throw new Error(`npm 元数据解析失败:${name}@${version ?? 'latest'}`)
  }
  if (!doc.dist?.tarball) throw new Error(`npm 元数据缺少 tarball:${name}@${doc.version ?? version}`)
  // provenance(attestations)仅读元数据,不上传任何源码。
  let attestations = []
  try {
    if (Array.isArray(doc.attestations?.entries)) {
      attestations = doc.attestations.entries.map((e) => ({
        type: e.attestation?.type ?? '',
        issuer: e.attestation?.predicateType ?? '',
        digest: e.attestation?.subject?.[0]?.digest?.sha256 ?? '',
        sourceRepository: e.attestation?.predicate?.invocation?.configSource?.uri ?? '',
        sourceCommit: e.attestation?.predicate?.invocation?.configSource?.digest?.sha1 ?? '',
        workflow: e.attestation?.predicate?.buildDefinition?.buildType ?? '',
      }))
    } else if (doc.attestations) {
      attestations = [{ type: 'present' }]
    }
  } catch {
    attestations = []
  }
  return {
    name: doc.name ?? name,
    version: doc.version,
    dist: {
      tarball: doc.dist.tarball,
      integrity: doc.dist.integrity ?? '',
      shasum: doc.dist.shasum ?? '',
    },
    dependencies: doc.dependencies ?? {},
    scripts: doc.scripts ?? {},
    attestations,
  }
}
