import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { boundedHttpRequest, BoundedHttpError } from '../engine/supplychain/http-client.js'

async function listen(handler) {
  const server = createServer(handler)
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const { port } = server.address()
  return {
    base: `http://127.0.0.1:${port}`,
    close: async () => {
      server.closeAllConnections?.()
      await new Promise((resolve) => server.close(() => resolve()))
    },
  }
}

function read(rel) {
  return readFileSync(new URL(`../${rel}`, import.meta.url), 'utf8')
}

test('registry, tarball, and OSV clients do not spawn curl', () => {
  for (const rel of ['engine/package/acquire.js', 'engine/package/tarball.js', 'engine/supplychain/osv.js', 'engine/supplychain/http-client.js']) {
    const source = read(rel)
    assert.doesNotMatch(source, /curl\.exe/)
    assert.doesNotMatch(source, /child_process|spawnSync|execFile|spawn\(/)
  }
})

test('bounded HTTP rejects non-http protocols before any transfer', async () => {
  await assert.rejects(
    () => boundedHttpRequest('file:///etc/passwd', { maxBytes: 64, timeoutMs: 1000 }),
    (error) => error instanceof BoundedHttpError && error.code === 'unsupported-protocol',
  )
})

test('bounded HTTP returns a body, streams to disk, and enforces the byte cap', async () => {
  const payload = Buffer.from('hello-sentinel')
  const server = await listen((req, res) => {
    if (req.url === '/exact') {
      res.end(payload)
      return
    }
    if (req.url === '/declared') {
      res.writeHead(200, { 'content-length': String(1024 * 1024) })
      res.end('nope')
      return
    }
    res.write('x'.repeat(80))
    res.end('y'.repeat(80))
  })
  const root = mkdtempSync(join(tmpdir(), 'sentinel-http-'))
  const dest = join(root, 'body.bin')
  try {
    const inline = await boundedHttpRequest(`${server.base}/exact`, { maxBytes: payload.length, timeoutMs: 2000 })
    assert.equal(inline.status, 200)
    assert.deepEqual(inline.body, payload)

    const streamed = await boundedHttpRequest(`${server.base}/exact`, {
      maxBytes: payload.length,
      timeoutMs: 2000,
      destination: dest,
    })
    assert.equal(streamed.body, null)
    assert.equal(streamed.bytes, payload.length)
    assert.deepEqual(readFileSync(dest), payload)

    await assert.rejects(
      () => boundedHttpRequest(`${server.base}/stream`, { maxBytes: 40, timeoutMs: 2000, destination: join(root, 'partial.bin') }),
      (error) => error instanceof BoundedHttpError && error.code === 'max-bytes',
    )
    assert.equal(existsSync(join(root, 'partial.bin')), false, 'over-cap stream deletes the partial file')

    await assert.rejects(
      () => boundedHttpRequest(`${server.base}/declared`, { maxBytes: 32, timeoutMs: 2000, destination: join(root, 'declared.bin') }),
      (error) => error instanceof BoundedHttpError && error.code === 'max-bytes',
    )
    assert.equal(existsSync(join(root, 'declared.bin')), false)
  } finally {
    await server.close()
    rmSync(root, { recursive: true, force: true })
  }
})

test('bounded HTTP times out a stalled response and follows only safe redirects', async () => {
  let secretHits = 0
  const server = await listen((req, res) => {
    if (req.url === '/stall') return
    if (req.url === '/loop') {
      res.writeHead(302, { location: '/loop' })
      res.end()
      return
    }
    if (req.url === '/to-file') {
      res.writeHead(302, { location: 'file:///etc/passwd' })
      res.end()
      return
    }
    if (req.url === '/next') {
      res.writeHead(302, { location: '/final' })
      res.end()
      return
    }
    if (req.url === '/secret') {
      secretHits += 1
      res.end('secret')
      return
    }
    if (req.url === '/guarded') {
      res.writeHead(302, { location: '/secret' })
      res.end()
      return
    }
    res.end('final')
  })
  try {
    const started = Date.now()
    await assert.rejects(
      () => boundedHttpRequest(`${server.base}/stall`, { maxBytes: 100, timeoutMs: 300 }),
      (error) => error instanceof BoundedHttpError && error.code === 'timeout',
    )
    assert.ok(Date.now() - started < 2000, 'absolute deadline should not wait on a blackholed socket')

    const followed = await boundedHttpRequest(`${server.base}/next`, {
      maxBytes: 100,
      timeoutMs: 2000,
      followRedirects: true,
    })
    assert.equal(followed.body.toString('utf8'), 'final')

    const notFollowed = await boundedHttpRequest(`${server.base}/next`, { maxBytes: 100, timeoutMs: 2000 })
    assert.equal(notFollowed.status, 302)
    assert.notEqual(notFollowed.body.toString('utf8'), 'final')

    await assert.rejects(
      () => boundedHttpRequest(`${server.base}/loop`, { maxBytes: 100, timeoutMs: 2000, followRedirects: true, maxRedirects: 3 }),
      (error) => error instanceof BoundedHttpError && error.code === 'redirects',
    )
    await assert.rejects(
      () => boundedHttpRequest(`${server.base}/to-file`, { maxBytes: 100, timeoutMs: 2000, followRedirects: true }),
      (error) => error instanceof BoundedHttpError && error.code === 'unsupported-protocol',
    )
    await assert.rejects(
      () => boundedHttpRequest(`${server.base}/guarded`, {
        maxBytes: 100,
        timeoutMs: 2000,
        followRedirects: true,
        guard: (href) => {
          if (href.endsWith('/secret')) throw new Error('SSRF guard: private address target')
        },
      }),
      /SSRF guard/,
    )
    assert.equal(secretHits, 0, 'a rejected redirect must not be fetched')
  } finally {
    await server.close()
  }
})

test('acquireNpmPackage reads local registry metadata and ignores redirects', async () => {
  const { acquireNpmPackage } = await import('../engine/package/acquire.js')
  const server = await listen((req, res) => {
    if (req.url === '/left-pad/1.0.0') {
      res.setHeader('content-type', 'application/json')
      res.end(JSON.stringify({
        name: 'left-pad',
        version: '1.0.0',
        dist: { tarball: 'http://registry.example/left-pad.tgz', integrity: 'sha512-abc', shasum: 'abc' },
        dependencies: {},
        scripts: {},
      }))
      return
    }
    res.writeHead(302, { location: '/left-pad/1.0.0' })
    res.end('redirected')
  })
  const previous = process.env.SENTINEL_NPM_REGISTRY
  process.env.SENTINEL_NPM_REGISTRY = server.base
  try {
    const meta = await acquireNpmPackage('left-pad@1.0.0', { timeoutMs: 2000 })
    assert.equal(meta.name, 'left-pad')
    assert.equal(meta.version, '1.0.0')
    assert.equal(meta.dist.tarball, 'http://registry.example/left-pad.tgz')
    assert.equal(meta.dist.integrity, 'sha512-abc')

    process.env.SENTINEL_NPM_REGISTRY = `${server.base}/missing`
    await assert.rejects(() => acquireNpmPackage('left-pad@1.0.0', { timeoutMs: 2000 }), /无法获取 npm 元数据/)
  } finally {
    if (previous === undefined) delete process.env.SENTINEL_NPM_REGISTRY
    else process.env.SENTINEL_NPM_REGISTRY = previous
    await server.close()
  }
})

test('downloadTarball verifies integrity and deletes an over-cap download', async () => {
  const { downloadTarball } = await import('../engine/package/tarball.js')
  const body = Buffer.from('not-a-real-tarball')
  const integrity = `sha512-${createHash('sha512').update(body).digest('base64')}`
  const server = await listen((req, res) => {
    if (req.url === '/ok.tgz') {
      res.end(body)
      return
    }
    if (req.url === '/cdn.tgz') {
      res.writeHead(302, { location: '/ok.tgz' })
      res.end()
      return
    }
    res.write('x'.repeat(200))
    res.end()
  })
  try {
    const ok = await downloadTarball(`${server.base}/cdn.tgz`, integrity, { timeoutMs: 2000, maxBytes: 1024 })
    try {
      assert.equal(ok.integrityOk, true)
      assert.equal(readFileSync(ok.tarballPath).equals(body), true)
    } finally {
      rmSync(ok.tarballPath, { force: true })
    }

    await assert.rejects(
      () => downloadTarball(`${server.base}/big.tgz`, integrity, { timeoutMs: 2000, maxBytes: 32 }),
      /下载失败/,
    )
  } finally {
    await server.close()
  }
})

test('queryOsv posts only name and version and degrades on failure', async () => {
  const { queryOsv } = await import('../engine/supplychain/osv.js')
  let seen = null
  const server = await listen((req, res) => {
    const chunks = []
    req.on('data', (chunk) => chunks.push(chunk))
    req.on('end', () => {
      seen = {
        method: req.method,
        body: JSON.parse(Buffer.concat(chunks).toString('utf8')),
      }
      if (req.url === '/boom') {
        res.writeHead(500)
        res.end('nope')
        return
      }
      res.setHeader('content-type', 'application/json')
      res.end(JSON.stringify({
        vulns: [{ id: 'GHSA-test', summary: 'example', severity: [{ score: '7.5' }], modified: '2026-01-01T00:00:00Z' }],
      }))
    })
  })
  try {
    const ok = await queryOsv('left-pad', '1.0.0', { endpoint: `${server.base}/v1/query`, timeoutMs: 2000 })
    assert.equal(ok.status, 'ok')
    assert.equal(ok.vulnerabilities[0].id, 'GHSA-test')
    assert.equal(ok.vulnerabilities[0].severity, 'CVSS 7.5')
    assert.equal(seen.method, 'POST')
    assert.deepEqual(Object.keys(seen.body).sort(), ['package', 'version'])
    assert.deepEqual(seen.body.package, { name: 'left-pad', ecosystem: 'npm' })
    assert.equal(seen.body.version, '1.0.0')

    const failed = await queryOsv('left-pad', '1.0.0', { endpoint: `${server.base}/boom`, timeoutMs: 2000 })
    assert.equal(failed.status, 'unavailable')
    assert.deepEqual(failed.vulnerabilities, [])

    const offline = await queryOsv('left-pad', '1.0.0', { endpoint: 'http://127.0.0.1:9/query', timeoutMs: 500 })
    assert.equal(offline.status, 'unavailable')
  } finally {
    await server.close()
  }
})
