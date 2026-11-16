/**
 * Ordinary DNS and Promise.resolve. Static fixture; never executed.
 * Looking up a fixed host is not credential exfil, and Promise.resolve is not a sink.
 */
import dns from 'node:dns'

const token = process.env.NPM_TOKEN

export function ready() {
  dns.lookup('localhost', () => {})
  return Promise.resolve(token)
}
