/**
 * Credential-name accuracy: segment boundaries, destructured env secrets,
 * and a full process.env dump. Fixtures are static.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { scan } from '../engine/index.js'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'accuracy')
const byId = (report, id) => report.findings.filter((finding) => finding.id === id)

test('non-credential env names are not SEN-CRED-002 or SEN-TAINT-001', async () => {
  const report = await scan(join(ROOT, 'benign-env-names', 'read.js'))
  assert.equal(byId(report, 'SEN-CRED-002').length, 0, 'AUTHOR, GITHUB_SHA, AWS_REGION, SECRETARY, TOKENIZER, PORT')
  assert.equal(byId(report, 'SEN-TAINT-001').length, 0, 'those values may be sent without becoming secret exfil')
  assert.ok(byId(report, 'SEN-NET-001').length > 0, 'the outbound request itself stays visible')
})

test('destructured secrets and a full env dump reach the network', async () => {
  const report = await scan(join(ROOT, 'malicious-env-exfil', 'steal.js'))
  assert.ok(byId(report, 'SEN-CRED-002').length >= 2, 'direct and destructured credential names')
  const flows = byId(report, 'SEN-TAINT-001')
  const sources = flows.map((finding) => finding.source?.name ?? '')
  assert.ok(sources.includes('process.env.NPM_TOKEN'), `missing NPM_TOKEN in ${sources.join(', ')}`)
  assert.ok(sources.includes('process.env.TOKEN'), `missing renamed TOKEN in ${sources.join(', ')}`)
  assert.ok(sources.includes('process.env'), `missing full env dump in ${sources.join(', ')}`)
  assert.equal(sources.some((name) => name.endsWith('.PORT') || name === 'PORT'), false, 'PORT is not a credential segment')
})
