import { createHash, randomBytes } from 'node:crypto'

const CANARY_DEFINITIONS = Object.freeze([
  ['apiKey', 'api-key'],
  ['bearerToken', 'bearer-token'],
  ['environmentSecret', 'environment-secret'],
  ['sshFile', 'ssh-file'],
  ['workspaceDocument', 'workspace-document'],
  ['conversation', 'conversation'],
  ['memory', 'memory'],
  ['toolArgument', 'tool-argument'],
])

function digest(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function tokenFor(kind, runId, entropy) {
  const bytes = Buffer.from(entropy(24))
  const token = bytes.toString('base64url')
  return `dsh-canary-${kind}-${runId}-${token}`
}

function valueFor(kind, runId, entropy) {
  const token = tokenFor(kind, runId, entropy)
  switch (kind) {
    case 'api-key':
      return `sk-dsh-${token}`
    case 'bearer-token':
      return `dsh-bearer-${token}`
    case 'environment-secret':
      return `DYNAMIC_SECRET_${token}`
    case 'ssh-file':
      return `-----BEGIN OPENSSH PRIVATE KEY-----\n${token}\n-----END OPENSSH PRIVATE KEY-----`
    case 'workspace-document':
      return `workspace-document:${token}`
    case 'conversation':
      return `conversation:${token}`
    case 'memory':
      return `memory:${token}`
    case 'tool-argument':
      return `tool-argument:${token}`
    default:
      throw new Error('unsupported canary kind')
  }
}

export function createCanarySet({ runId = randomBytes(16).toString('hex'), entropy = randomBytes } = {}) {
  if (typeof runId !== 'string' || runId.length === 0) {
    throw new Error('invalid canary run id')
  }
  if (typeof entropy !== 'function') {
    throw new Error('invalid canary entropy source')
  }

  const values = {}
  const descriptors = []
  for (const [property, kind] of CANARY_DEFINITIONS) {
    const value = valueFor(kind, runId, entropy)
    values[property] = value
    descriptors.push(Object.freeze({ id: kind, kind, digest: digest(value) }))
  }

  return Object.freeze({
    values: Object.freeze(values),
    descriptors: Object.freeze(descriptors),
  })
}
