/**
 * Generate docs/example-report.json: scan the evil fixture and the real
 * DeepSeek Harness web-app bundle (when present) for a README demo.
 * Run: node scripts/demo.mjs
 */

import { writeFileSync, existsSync, mkdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { scan } from '../engine/index.js'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

const evil = await scan(join(root, 'test', 'fixtures', 'evil-plugin'))
// Checked-in examples must be shareable and must not expose the release
// maintainer's absolute workspace path.
evil.target.path = '<workspace>/test/fixtures/evil-plugin'

const parts = {
  generatedBy: 'scripts/demo.mjs',
  evilFixtureReport: evil,
}

// Optionally scan a real harness bundle for a "known-good" contrast sample.
const harnessWebApp = process.env.DSH_HARNESS_CHECKOUT
  ? join(process.env.DSH_HARNESS_CHECKOUT, 'packages', 'bundle', 'web-app')
  : join(root, '..', 'deepseek-harness', 'packages', 'bundle', 'web-app')
if (existsSync(harnessWebApp)) {
  const real = await scan(harnessWebApp, { maxFiles: 2000 })
  parts.realWorldSample = {
    target: 'packages/bundle/web-app (DeepSeek Harness 官方 bundle)',
    summary: real.summary,
    findings: real.findings.slice(0, 15),
  }
}

const docsDir = join(root, 'docs')
mkdirSync(docsDir, { recursive: true })
writeFileSync(join(docsDir, 'example-report.json'), JSON.stringify(parts, null, 2) + '\n')
console.log('docs/example-report.json written')
console.log(`evil fixture: verdict=${evil.summary.verdict} score=${evil.summary.score} findings=${evil.summary.totalFindings}`)
if (parts.realWorldSample) {
  const s = parts.realWorldSample.summary
  console.log(`web-app bundle: verdict=${s.verdict} score=${s.score} findings=${s.totalFindings}`)
}
