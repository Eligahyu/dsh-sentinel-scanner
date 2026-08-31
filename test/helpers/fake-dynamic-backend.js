function delay(milliseconds, signal, ignoreAbort = false) {
  if (!milliseconds) return Promise.resolve()
  return new Promise((resolve, reject) => {
    let settled = false
    let timer = null
    const finish = callback => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      signal?.removeEventListener('abort', abort)
      callback()
    }
    const abort = () => finish(() => reject(new Error('aborted')))
    timer = setTimeout(() => finish(resolve), milliseconds)
    if (!signal || ignoreAbort) return
    if (signal.aborted) abort()
    else signal.addEventListener('abort', abort, { once: true })
  })
}

export class FakeDynamicBackend {
  constructor(fixtures = {}) {
    this.fixtures = fixtures
    this.calls = []
    this.events = []
    this.prepareCalls = []
    this.cleanupCalls = []
  }

  async wait(method, signal = null) {
    this.events.push(`${method}:start`)
    await delay(
      this.fixtures.delays?.[method],
      signal,
      this.fixtures.ignoreAbort?.[method] === true,
    )
    this.events.push(`${method}:settled`)
  }

  async available(signal) {
    this.calls.push({ method: 'available' })
    await this.wait('available', signal)
    if (this.fixtures.availableError) throw this.fixtures.availableError
    return {
      available: this.fixtures.available !== false,
      backend: 'fake',
      code: this.fixtures.availableCode ?? 'fake-unavailable',
    }
  }

  async prepare(runSpec, signal) {
    this.calls.push({ method: 'prepare' })
    this.prepareCalls.push(runSpec)
    await this.wait('prepare', signal)
    if (this.fixtures.prepareError) throw this.fixtures.prepareError
    return Object.freeze({ id: `fake-handle-${this.prepareCalls.length}` })
  }

  async runStage(handle, stageSpec) {
    this.calls.push({ method: 'runStage', stage: stageSpec.name })
    await this.wait('runStage', stageSpec.signal)
    const stageError = this.fixtures.stageErrors?.[stageSpec.name]
    if (stageError) throw stageError
    return this.fixtures.stageEvidence?.[stageSpec.name] ?? {}
  }

  async collect(handle, signal) {
    this.calls.push({ method: 'collect' })
    await this.wait('collect', signal)
    if (this.fixtures.collectError) throw this.fixtures.collectError
    return this.fixtures.evidence ?? {}
  }

  async cleanup(handle, signal) {
    this.calls.push({ method: 'cleanup' })
    this.cleanupCalls.push(handle)
    await this.wait('cleanup', signal)
    if (this.fixtures.cleanupError) throw this.fixtures.cleanupError
    if (Object.hasOwn(this.fixtures, 'cleanupResult')) return this.fixtures.cleanupResult
    return { complete: this.fixtures.cleanupComplete !== false }
  }
}
