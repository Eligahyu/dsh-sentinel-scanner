const PHASE_A_UNAVAILABLE = Object.freeze({
  available: false,
  backend: null,
  code: 'backend-not-implemented-phase-a',
})

export function resolveDynamicBackend({ backendName, injectedBackend } = {}) {
  if (injectedBackend && typeof injectedBackend === 'object') {
    return Object.freeze({ available: true, backend: injectedBackend })
  }
  return PHASE_A_UNAVAILABLE
}
