/**
 * Bounded HTTP(S) client for registry metadata, tarball downloads, and OSV.
 *
 * Linux, macOS, and Windows share this path. It does not spawn a shell or
 * curl, does not honor HTTP(S)_PROXY (direct connection, same as curl
 * --noproxy *), and leaves TLS verification on. Every transfer has one
 * deadline and a hard byte cap. Redirects are opt-in and are followed as GET.
 */

import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { createWriteStream, rmSync } from 'node:fs'

export class BoundedHttpError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   */
  constructor(code, message) {
    super(message)
    this.name = 'BoundedHttpError'
    this.code = code
  }
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308])
const HOP_HEADER_BLOCKLIST = new Set(['host', 'connection', 'content-length', 'transfer-encoding'])

/** @param {string} value */
function assertHttpUrl(value) {
  let url
  try {
    url = new URL(value)
  } catch {
    throw new BoundedHttpError('invalid-url', 'invalid URL')
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new BoundedHttpError('unsupported-protocol', `unsupported URL protocol ${url.protocol}`)
  }
  if (!url.hostname) throw new BoundedHttpError('invalid-url', 'invalid URL')
  return url
}

/** @param {string | null | undefined} path */
function unlinkQuiet(path) {
  if (!path) return
  try {
    rmSync(path, { force: true })
  } catch {
    // The caller removes the same path again; a race here is not fatal.
  }
}

/**
 * @param {URL} url
 * @param {object} opts
 */
function requestOnce(url, { method, headers, body, maxBytes, timeoutMs, destination, followRedirects }) {
  return new Promise((resolve, reject) => {
    let settled = false
    let fileStream = null
    let opened = false
    /** @type {Error | null} */
    let failure = null

    const finishReject = (error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      const wrapped = error instanceof BoundedHttpError
        ? error
        : new BoundedHttpError(error?.code || 'network', error?.message || 'request failed')
      const cleanup = () => {
        if (opened) unlinkQuiet(destination)
        reject(wrapped)
      }
      if (fileStream) {
        fileStream.destroy()
        if (fileStream.closed) cleanup()
        else fileStream.once('close', cleanup)
      } else {
        cleanup()
      }
    }

    const finishResolve = (value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve(value)
    }

    const transport = url.protocol === 'https:' ? httpsRequest : httpRequest
    const req = transport(url, { method, headers }, (res) => {
      const status = res.statusCode ?? 0
      const locationHeader = res.headers.location
      const location = Array.isArray(locationHeader) ? locationHeader[0] : locationHeader
      if (followRedirects && REDIRECT_STATUSES.has(status) && typeof location === 'string' && location.length > 0) {
        res.resume()
        finishResolve({ kind: 'redirect', status, location })
        return
      }

      const declared = Number(res.headers['content-length'])
      if (Number.isFinite(declared) && declared > maxBytes) {
        failure = new BoundedHttpError('max-bytes', `response exceeded ${maxBytes} bytes`)
        res.resume()
        req.destroy()
        finishReject(failure)
        return
      }

      let received = 0
      /** @type {Buffer[]} */
      const chunks = []

      if (destination) {
        fileStream = createWriteStream(destination)
        opened = true
        fileStream.on('error', (error) => finishReject(failure ?? error))
        fileStream.on('drain', () => {
          if (!settled) res.resume()
        })
      }

      res.on('data', (chunk) => {
        if (settled) return
        received += chunk.length
        if (received > maxBytes) {
          failure = new BoundedHttpError('max-bytes', `response exceeded ${maxBytes} bytes`)
          res.destroy()
          req.destroy()
          finishReject(failure)
          return
        }
        if (fileStream) {
          if (!fileStream.write(chunk)) res.pause()
        } else {
          chunks.push(chunk)
        }
      })
      res.on('error', (error) => finishReject(failure ?? error))
      res.on('end', () => {
        if (settled) return
        clearTimeout(timer)
        if (fileStream) {
          fileStream.end(() => {
            finishResolve({ kind: 'response', status, bytes: received, body: null })
          })
        } else {
          finishResolve({
            kind: 'response',
            status,
            bytes: received,
            body: Buffer.concat(chunks, received),
          })
        }
      })
    })

    const timer = setTimeout(() => {
      failure = new BoundedHttpError('timeout', 'request timed out')
      req.destroy()
      finishReject(failure)
    }, timeoutMs)
    timer.unref?.()

    req.on('error', (error) => finishReject(failure ?? error))
    if (body != null) req.write(body)
    req.end()
  })
}

/**
 * Perform one bounded HTTP(S) request.
 * `destination` streams the final response body to disk; otherwise the body
 * is returned as a Buffer. A failed transfer deletes a partial destination.
 *
 * @param {string} urlString
 * @param {object} [options]
 * @returns {Promise<{status: number, bytes: number, body: Buffer | null}>}
 */
export async function boundedHttpRequest(urlString, options = {}) {
  const {
    method = 'GET',
    headers = {},
    body = null,
    maxBytes,
    timeoutMs,
    followRedirects = false,
    maxRedirects = 5,
    destination = null,
    guard = null,
  } = options

  if (!Number.isInteger(maxBytes) || maxBytes < 0) {
    throw new BoundedHttpError('invalid-limit', 'maxBytes must be a non-negative integer')
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new BoundedHttpError('invalid-limit', 'timeoutMs must be a positive number')
  }
  if (!Number.isInteger(maxRedirects) || maxRedirects < 0) {
    throw new BoundedHttpError('invalid-limit', 'maxRedirects must be a non-negative integer')
  }

  const deadline = Date.now() + timeoutMs
  let current = urlString
  let redirects = 0
  const seen = new Set()

  while (redirects <= maxRedirects) {
    const url = assertHttpUrl(current)
    if (seen.has(url.href)) throw new BoundedHttpError('redirects', 'redirect loop')
    seen.add(url.href)
    if (typeof guard === 'function') await guard(url.href)

    const timeoutLeft = deadline - Date.now()
    if (timeoutLeft <= 0) throw new BoundedHttpError('timeout', 'request timed out')

    const hop = redirects > 0
    /** @type {Record<string, string>} */
    const hopHeaders = { 'user-agent': 'dsh-sentinel', accept: '*/*' }
    for (const [key, value] of Object.entries(headers)) {
      if (value === undefined || value === null) continue
      const lower = key.toLowerCase()
      if (HOP_HEADER_BLOCKLIST.has(lower)) continue
      hopHeaders[lower] = String(value)
    }
    const payload = hop ? null : body
    if (!hop && payload != null) hopHeaders['content-length'] = String(Buffer.byteLength(payload))

    const result = await requestOnce(url, {
      method: hop ? 'GET' : method,
      headers: hopHeaders,
      body: payload,
      maxBytes,
      timeoutMs: timeoutLeft,
      destination,
      followRedirects,
    })

    if (result.kind !== 'redirect') {
      return { status: result.status, bytes: result.bytes, body: result.body }
    }

    redirects += 1
    if (redirects > maxRedirects) throw new BoundedHttpError('redirects', 'too many redirects')
    let next
    try {
      next = new URL(result.location, url).href
    } catch {
      throw new BoundedHttpError('invalid-url', 'invalid redirect URL')
    }
    current = next
  }

  throw new BoundedHttpError('redirects', 'too many redirects')
}
