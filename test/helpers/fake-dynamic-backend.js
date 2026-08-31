function delay(milliseconds, signal) {
  if (!milliseconds) return Promise.resolve()
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, milliseconds)
    if (!signal) return
    const abort = () => {
      clearTimeout(timer)
      reject(new Error('aborted'))
    }
    if (signal.aborted) abort()
    else signal.addEventListener('abort', abort, { once: true })
  })
}

export class FakeDynamicBackend {
  constructor(fixtures = {}) {
    this.fixtures = fixtures
    this.calls = []
    this.prepareCalls = []
    this.cleanupCalls = []
  }

  async available() {
    this.calls.push({ method: 'available' })
    await delay(this.fixtures.delays?.available)
    if (this.fixtures.availableError) throw this.fixtures.availableError
    return {
      available: this.fixtures.available !== false,
      backend: 'fake',
      code: this.fixtures.availableCode ?? 'fake-unavailable',
    }
  }

  async prepare(runSpec) {
    this.calls.push({ method: 'prepare' })
    this.prepareCalls.push(runSpec)
    await delay(this.fixtures.delays?.prepare)
    if (this.fixtures.prepareError) throw this.fixtures.prepareError
    return Object.freeze({ id: `fake-handle-${this.prepareCalls.length}` })
  }

  async runStage(handle, stageSpec) {
    this.calls.push({ method: 'runStage', stage: stageSpec.name })
    await delay(this.fixtures.delays?.runStage, stageSpec.signal)
    const stageError = this.fixtures.stageErrors?.[stageSpec.name]
    if (stageError) throw stageError
    return this.fixtures.stageEvidence?.[stageSpec.name] ?? {}
  }

  async collect(handle) {
    this.calls.push({ method: 'collect' })
    await delay(this.fixtures.delays?.collect)
    if (this.fixtures.collectError) throw this.fixtures.collectError
    return this.fixtures.evidence ?? {}
  }

  async cleanup(handle) {
    this.calls.push({ method: 'cleanup' })
    this.cleanupCalls.push(handle)
    await delay(this.fixtures.delays?.cleanup)
    if (this.fixtures.cleanupError) throw this.fixtures.cleanupError
    return { complete: this.fixtures.cleanupComplete !== false }
  }
}
