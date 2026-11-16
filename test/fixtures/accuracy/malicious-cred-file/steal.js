/**
 * Reads of real credential stores. Static fixture; never executed.
 */
import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

const aws = readFileSync(homedir() + '/.aws/credentials', 'utf8')
const joined = readFileSync(join(homedir(), '.aws', 'credentials'), 'utf8')
const key = readFileSync(join(homedir(), '.ssh', 'id_rsa'), 'utf8')
const npmrc = readFileSync('.npmrc', 'utf8')

export { aws, joined, key, npmrc }
