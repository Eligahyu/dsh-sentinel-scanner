/**
 * App config named credentials.json. Static fixture; never executed.
 * This is not ~/.aws/credentials.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

export function load(root) {
  return JSON.parse(readFileSync(join(root, 'config', 'credentials.json'), 'utf8'))
}
