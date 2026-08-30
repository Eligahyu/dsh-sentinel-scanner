/**
 * v2 供应链安全测试:tar 安全解包(traversal/symlink/bomb)、integrity、
 * lockfile 统计、二进制 metadata 审计、path containment 强化(realpath/symlink/大小写)。
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, symlinkSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { gzipSync } from 'node:zlib'
import { createHash } from 'node:crypto'
import { extractTarballSafe, safeJoin, TarSafetyError } from '../engine/package/tar.js'
import { verifyIntegrity, fileSha256 } from '../engine/package/tarball.js'
import { detectLockfile, countDependencies } from '../engine/supplychain/lockfile.js'
import { isInsideRoot, resolveInside, PathEscapeError, CASE_INSENSITIVE } from '../engine/path-safety.js'
import { printableStrings } from '../engine/binary/strings.js'
import { shannonEntropy } from '../engine/binary/entropy.js'
import { classifyBinary, auditBinarySample } from '../engine/binary/inspect.js'
import { scan } from '../engine/index.js'

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'fixtures')

// ─────────────────────────── tar 构造 helper(仅测试用) ───────────────────────────

function tarHeader(name, size, typeflag = '0', linkname = '') {
  const buf = Buffer.alloc(512)
  const nameBuf = Buffer.from(name, 'utf8')
  nameBuf.copy(buf, 0, 0, Math.min(100, nameBuf.length))
  buf.write('0000644\0', 100, 8, 'utf8')
  buf.write('0000000\0', 108, 8, 'utf8')
  buf.write('0000000\0', 116, 8, 'utf8')
  buf.write(size.toString(8).padStart(11, '0') + '\0', 124, 12, 'utf8')
  buf.write('00000000000\0', 136, 12, 'utf8')
  buf.fill(0x20, 148, 156)
  buf.write(typeflag, 156, 1, 'utf8')
  if (linkname) buf.write(linkname, 157, Math.min(100, linkname.length), 'utf8')
  buf.write('ustar\0', 257, 6, 'utf8')
  buf.write('00', 263, 2, 'utf8')
  let sum = 0
  for (let i = 0; i < 512; i += 1) sum += buf[i]
  buf.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'utf8')
  return buf
}

function makeTar(files) {
  const chunks = []
  for (const f of files) {
    const content = typeof f.content === 'string' ? Buffer.from(f.content, 'utf8') : (f.content ?? Buffer.alloc(0))
    const type = f.type ?? '0'
    const size = (type === '0' || type === 'L' || type === 'x') ? content.length : 0
    chunks.push(tarHeader(f.name, size, type, f.linkname ?? ''))
    if (size > 0) chunks.push(content)
    const pad = (512 - (size % 512)) % 512
    if (pad) chunks.push(Buffer.alloc(pad))
  }
  chunks.push(Buffer.alloc(1024))
  return Buffer.concat(chunks)
}

function writeGzipTar(dir, files) {
  const p = join(dir, 'evil.tgz')
  writeFileSync(p, gzipSync(makeTar(files)))
  return p
}

// ─────────────────────────── tar 安全解包 ───────────────────────────

test('正常 tarball 解包成功且内容正确', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-tar-ok-'))
  try {
    const dest = join(tmp, 'x')
    mkdirSync(dest, { recursive: true })
    const tar = writeGzipTar(tmp, [
      { name: 'package/', type: '5' },
      { name: 'package/index.js', content: "export const name = 'a'\n" },
      { name: 'package/package.json', content: '{"name":"a"}' },
    ])
    const { entries, unpackedBytes, files } = extractTarballSafe(tar, dest)
    assert.equal(entries, 3)
    assert.equal(files.length, 2)
    assert.ok(files.includes('package/index.js'))
    assert.equal(readFileSync(join(dest, 'package', 'index.js'), 'utf8'), "export const name = 'a'\n")
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

test('tar traversal:../../evil 被阻止', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-tar-trav-'))
  try {
    const dest = join(tmp, 'x')
    mkdirSync(dest, { recursive: true })
    const tar = writeGzipTar(tmp, [{ name: '../../evil.txt', content: 'pwned' }])
    assert.throws(() => extractTarballSafe(tar, dest), (e) => e instanceof TarSafetyError && e.code === 'path-traversal')
    assert.ok(!existsSync(join(tmp, 'evil.txt')), '不得写出解包目录')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

test('tar 绝对路径与盘符路径被阻止', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-tar-abs-'))
  try {
    const dest = join(tmp, 'x')
    mkdirSync(dest, { recursive: true })
    const tar1 = writeGzipTar(tmp, [{ name: '/etc/evil', content: 'x' }])
    assert.throws(() => extractTarballSafe(tar1, dest), (e) => e.code === 'absolute-path')
    const tar2 = writeGzipTar(tmp, [{ name: 'C:\\evil', content: 'x' }])
    assert.throws(() => extractTarballSafe(tar2, dest), (e) => e.code === 'drive-path')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

test('tar symlink/hardlink 条目被拒绝(symlink escape 防护)', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-tar-link-'))
  try {
    const dest = join(tmp, 'x')
    mkdirSync(dest, { recursive: true })
    const sym = writeGzipTar(tmp, [{ name: 'package/link', type: '2', linkname: '../../../../etc/passwd' }])
    assert.throws(() => extractTarballSafe(sym, dest), (e) => e instanceof TarSafetyError && e.code === 'link-entry')
    const hard = writeGzipTar(tmp, [{ name: 'package/hard', type: '1', linkname: 'package/index.js' }])
    assert.throws(() => extractTarballSafe(hard, dest), (e) => e.code === 'link-entry')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

test('tar bomb:条目数 / 单文件大小 / 解压总量超限', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-tar-bomb-'))
  try {
    const dest = join(tmp, 'x')
    mkdirSync(dest, { recursive: true })
    const many = writeGzipTar(tmp, [
      { name: 'a1', content: 'x' }, { name: 'a2', content: 'x' }, { name: 'a3', content: 'x' },
    ])
    assert.throws(() => extractTarballSafe(many, dest, { maxEntries: 2 }), (e) => e.code === 'too-many-entries')
    const huge = writeGzipTar(tmp, [{ name: 'big.bin', content: Buffer.alloc(2048, 7) }])
    assert.throws(() => extractTarballSafe(huge, dest, { maxSingleFileBytes: 1024 }), (e) => e.code === 'single-file-too-large')
    const bomb = writeGzipTar(tmp, [{ name: 'b1', content: Buffer.alloc(2048, 7) }])
    assert.throws(() => extractTarballSafe(bomb, dest, { maxUnpackedBytes: 1024 }), (e) => e.code === 'tar-bomb')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

test('safeJoin:路径长度 / 嵌套深度超限', () => {
  const dest = 'C:/q'
  assert.throws(() => safeJoin(dest, 'a'.repeat(1100)), (e) => e.code === 'path-too-long')
  assert.throws(() => safeJoin(dest, Array(40).fill('d').join('/') + '/f'), (e) => e.code === 'nesting-too-deep')
})

// ─────────────────────────── integrity ───────────────────────────

test('verifyIntegrity:sha512 base64 正确 / 错误 / 缺字段', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-int-'))
  try {
    const p = join(tmp, 'f.bin')
    writeFileSync(p, 'hello world')
    const good = 'sha512-' + createHash('sha512').update('hello world').digest('base64')
    assert.equal(verifyIntegrity(p, good).ok, true)
    assert.equal(verifyIntegrity(p, 'sha512-' + createHash('sha512').update('evil').digest('base64')).ok, false)
    assert.equal(verifyIntegrity(p, null).ok, false)
    assert.equal(verifyIntegrity(p, 'sha256-abc').ok, false, '不支持的格式')
    assert.match(fileSha256(p), /^[0-9a-f]{64}$/)
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ─────────────────────────── lockfile ───────────────────────────

test('lockfile 检测与依赖统计(package-lock.json)', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-lock-'))
  try {
    writeFileSync(join(tmp, 'package-lock.json'), JSON.stringify({
      name: 'app', version: '1.0.0',
      packages: {
        '': { dependencies: { a: '1.0.0', b: '2.0.0' }, devDependencies: { c: '3.0.0' } },
        'node_modules/a': { version: '1.0.0' },
        'node_modules/b': { version: '2.0.0', dependencies: { t: '1.0.0' } },
        'node_modules/t': { version: '1.0.0' },
        'node_modules/c': { version: '3.0.0' },
      },
    }))
    assert.equal(detectLockfile(tmp), 'package-lock.json')
    const counts = countDependencies(tmp, 'package-lock.json')
    assert.equal(counts.directDependencies, 3)
    assert.equal(counts.transitiveDependencies, 1)
    rmSync(join(tmp, 'package-lock.json'))
    writeFileSync(join(tmp, 'yarn.lock'), 'a@1:\n  version "1.0.0"\nb@2:\n  version "2.0.0"\n')
    assert.equal(detectLockfile(tmp), 'yarn.lock')
    assert.equal(countDependencies(tmp, 'yarn.lock').transitiveDependencies, 2)
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

test('pnpm v9 dependency counts use normalized direct and transitive graph nodes', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-pnpm-count-'))
  try {
    writeFileSync(join(tmp, 'package.json'), JSON.stringify({
      name: 'pnpm-app',
      version: '1.0.0',
      dependencies: { alpha: '^1.0.0' },
    }))
    writeFileSync(join(tmp, 'pnpm-lock.yaml'), [
      "lockfileVersion: '9.0'",
      'importers:',
      '  .:',
      '    dependencies:',
      '      alpha:',
      '        specifier: ^1.0.0',
      '        version: 1.2.0',
      'packages:',
      '  alpha@1.2.0: {}',
      '  beta@2.0.0: {}',
      'snapshots:',
      '  alpha@1.2.0:',
      '    dependencies:',
      '      beta: 2.0.0',
      '  beta@2.0.0: {}',
    ].join('\n'))

    assert.deepEqual(countDependencies(tmp, 'pnpm-lock.yaml'), {
      directDependencies: 1,
      transitiveDependencies: 1,
      dependencyCountComplete: true,
    })
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

test('pnpm aliases count each root declaration while retaining one installed node', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-pnpm-alias-count-'))
  try {
    writeFileSync(join(tmp, 'package.json'), JSON.stringify({ name: 'alias-app', version: '1.0.0' }))
    writeFileSync(join(tmp, 'pnpm-lock.yaml'), [
      "lockfileVersion: '9.0'",
      'importers:',
      '  .:',
      '    dependencies:',
      '      compat:',
      '        specifier: npm:real-package@^1.0.0',
      '        version: npm:real-package@1.2.0',
      '      real-package:',
      '        specifier: ^1.0.0',
      '        version: 1.2.0',
      'packages:',
      '  real-package@1.2.0: {}',
      'snapshots:',
      '  real-package@1.2.0: {}',
    ].join('\n'))

    assert.deepEqual(countDependencies(tmp, 'pnpm-lock.yaml'), {
      directDependencies: 2,
      transitiveDependencies: 0,
      dependencyCountComplete: true,
    })
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

test('pnpm dependency count failure stays conservative and explicit', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-pnpm-count-bad-'))
  try {
    writeFileSync(join(tmp, 'pnpm-lock.yaml'), "lockfileVersion: '9.0'\nimporters: [\n")

    assert.deepEqual(countDependencies(tmp, 'pnpm-lock.yaml'), {
      directDependencies: 0,
      transitiveDependencies: 0,
      dependencyCountComplete: false,
      dependencyCountReason: 'parse-error',
    })
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ─────────────────────────── 二进制审计 ───────────────────────────

test('binary strings / entropy / magic 单元', () => {
  assert.deepEqual(printableStrings(Buffer.from('ab\u0000cd\u0000hello world'), { minLen: 2 }), ['ab', 'cd', 'hello world'])
  assert.equal(shannonEntropy(Buffer.alloc(1024, 0)), 0)
  assert.ok(shannonEntropy(Buffer.from('random data random data random data random data')) > 0)
  assert.equal(classifyBinary(Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01])).kind, 'wasm')
  assert.equal(classifyBinary(Buffer.from('MZ...')).kind, 'pe')
  const audit = auditBinarySample(Buffer.from('MZ' + 'x'.repeat(200) + 'curl https://webhook.site/abc'))
  assert.equal(audit.kind, 'pe')
  assert.ok(audit.highSignals.includes('exfil-endpoint'), 'webhook.site 命中高危信号')
})

test('二进制 metadata 审计集成:SEN-BIN-001/002/003 与 SEN-WASM-001', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-bin-'))
  try {
    // PE + 外传端点字符串
    const pe = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(128), Buffer.from('C:\\Windows\\System32\\cmd.exe curl https://webhook.site/abc')])
    writeFileSync(join(tmp, 'tool.exe'), pe)
    // 高熵 .so
    const rnd = Buffer.alloc(4096)
    for (let i = 0; i < 4096; i += 1) rnd[i] = (i * 31 + 7) % 256
    writeFileSync(join(tmp, 'packed.so'), rnd)
    // wasm
    writeFileSync(join(tmp, 'mod.wasm'), Buffer.concat([Buffer.from([0x00, 0x61, 0x73, 0x6d]), Buffer.alloc(64, 1)]))
    // 普通图片仍然跳过
    writeFileSync(join(tmp, 'pic.png'), Buffer.alloc(64, 1))

    const report = await scan(tmp)
    const ids = new Set(report.findings.map((f) => f.id))
    assert.ok(ids.has('SEN-BIN-001'), 'native binary present')
    assert.ok(ids.has('SEN-BIN-002'), 'suspicious strings')
    assert.ok(ids.has('SEN-BIN-003'), 'high entropy')
    assert.ok(ids.has('SEN-WASM-001'), 'wasm module')
    const bin2 = report.findings.find((f) => f.id === 'SEN-BIN-002')
    assert.equal(bin2.severity, 'high', 'exfil 端点字符串 → high(不因 binary 降级)')
    assert.equal(report.scanCoverage.binaryFiles, 3, '3 个可执行二进制被审计')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ─────────────────────────── path containment 强化 ───────────────────────────

test('path containment:../escape、绝对路径、大小写、前缀相似', () => {
  const parent = join(tmpdir(), 'sentinel-path-supplychain')
  const root = join(parent, 'pkg')
  assert.equal(isInsideRoot(root, join(root, 'lib', 'x.js')), true)
  assert.equal(isInsideRoot(root, root), true)
  assert.equal(isInsideRoot(root, join(parent, 'other')), false)
  assert.equal(isInsideRoot(root, join(parent, 'pkgx', 'evil.js')), false, '前缀相似但不是子目录')
  assert.equal(isInsideRoot(root, join(root, '..', 'escape')), false)
  assert.equal(isInsideRoot(root, join(root, '..', '..', 'escape')), false)
  assert.equal(isInsideRoot(root, join(tmpdir(), 'sentinel-path-evil')), false)
  // Windows 大小写:仅 win32 不敏感
  if (CASE_INSENSITIVE) {
    assert.equal(isInsideRoot('C:/Proj/Pkg', 'c:/proj/pkg/lib/x.js'), true, 'win32 大小写不敏感')
  } else {
    assert.equal(isInsideRoot('/Proj/Pkg', '/proj/pkg/lib/x.js'), false, 'POSIX 大小写敏感')
  }
  assert.throws(() => resolveInside(root, '../../etc/passwd'), PathEscapeError)
  assert.throws(() => resolveInside(root, join(tmpdir(), 'sentinel-path-evil')), PathEscapeError)
  assert.equal(resolveInside(root, './lib/x.js'), join(root, 'lib', 'x.js'))
})

test('junction/symlink escape 被 realpath containment 阻止', (t) => {
  const tmp = mkdtempSync(join(tmpdir(), 'v2-link-'))
  try {
    mkdirSync(join(tmp, 'root', 'plugin'), { recursive: true })
    mkdirSync(join(tmp, 'outside'), { recursive: true })
    writeFileSync(join(tmp, 'outside', 'evil.js'), 'x')
    try {
      symlinkSync(join(tmp, 'outside'), join(tmp, 'root', 'plugin', 'link'), 'junction')
    } catch {
      t.skip('当前环境无法创建 junction/symlink')
      return
    }
    // 词法上在 root 内,但 realpath 逃逸 → 必须拒绝
    assert.throws(
      () => resolveInside(join(tmp, 'root', 'plugin'), join(tmp, 'root', 'plugin', 'link', 'evil.js')),
      PathEscapeError,
      'symlink escape 必须被阻止',
    )
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})
