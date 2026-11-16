/**
 * SEN-EXFIL-001 host precision: Discord webhooks stay critical,
 * the normal Discord REST API does not.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { scan } from '../engine/index.js'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'accuracy')
const ids = (report) => new Set(report.findings.map((finding) => finding.id))

test('a Discord REST client is not a suspicious endpoint', async () => {
  const report = await scan(join(ROOT, 'benign-discord-api', 'bot.js'))
  assert.equal(ids(report).has('SEN-EXFIL-001'), false)
  assert.equal(ids(report).has('SEN-NET-001'), true, 'the outbound API call is still visible')
})

test('webhook, telegram bot, ngrok, and oast endpoints stay critical', async () => {
  const report = await scan(join(ROOT, 'malicious-exfil', 'endpoints.js'))
  const hits = report.findings.filter((finding) => finding.id === 'SEN-EXFIL-001')
  const lines = new Set(hits.map((finding) => finding.line))
  assert.equal(lines.has(5), true, 'webhook.site')
  assert.equal(lines.has(6), true, 'discord.com/api/webhooks')
  assert.equal(lines.has(7), true, 'discordapp.com/api/webhooks')
  assert.equal(lines.has(8), true, 'api.telegram.org/bot')
  assert.equal(lines.has(9), true, 'ngrok.io')
  assert.equal(lines.has(10), true, 'oast.me')
  assert.equal(lines.has(11), true, 'interact.sh')
})
