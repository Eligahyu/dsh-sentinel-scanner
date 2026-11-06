/**
 * Plugin-load smoke test: mounts the package in a fake profile node_modules
 * with stub @deepseek-ai/dsh-tools, imports `dsh-sentinel/plugin`, applies it
 * to a fake ctx, and executes the registered tools end-to-end.
 *
 * This mirrors what the real DSH loader does: resolve the bundle's peer deps
 * from the installation surface, then call apply(ctx) with a tools registry.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, cpSync, mkdirSync, writeFileSync, rmSync, readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const WINDOWS_LOCK_CODES = new Set(['EPERM', 'EBUSY'])

/**
 * Best-effort temp cleanup. Windows keeps a dlopened `.node` mapped for the
 * lifetime of the process, so the copied oxc binding cannot be unlinked while
 * this test still runs. Retry briefly, then retain the tree and report it
 * instead of failing an otherwise green scan test.
 */
function removeTempTree(root, t) {
  try {
    rmSync(root, {
      recursive: true,
      force: true,
      maxRetries: process.platform === 'win32' ? 3 : 0,
      retryDelay: 100,
    })
  } catch (error) {
    if (process.platform !== 'win32' || !WINDOWS_LOCK_CODES.has(error?.code)) throw error
    t.diagnostic(`kept temporary plugin tree: native addon is still locked (${error.code})`)
  }
}

function makeStubTools(modulesDir) {
  const stub = `export function defineTool(opts) { return opts }\n`
  mkdirSync(join(modulesDir, '@deepseek-ai', 'dsh-tools'), { recursive: true })
  writeFileSync(join(modulesDir, '@deepseek-ai', 'dsh-tools', 'package.json'), JSON.stringify({
    name: '@deepseek-ai/dsh-tools', version: '0.0.0', type: 'module', main: 'index.js',
  }))
  writeFileSync(join(modulesDir, '@deepseek-ai', 'dsh-tools', 'index.js'), stub)
}

test('plugin registers sentinel_scan + sentinel_scan_profile and executes a real scan', async (t) => {
  const tmp = mkdtempSync(join(process.env.TEMP ?? '/tmp', 'sentinel-plugin-load-'))
  try {
    const modulesDir = join(tmp, 'node_modules')
    mkdirSync(modulesDir, { recursive: true })
    makeStubTools(modulesDir)
    cpSync(REPO_ROOT, join(modulesDir, 'dsh-sentinel'), {
      recursive: true,
      filter: (src) => !src.includes(`${sep}test${sep}`) && !src.includes(`${sep}scripts${sep}`) && !src.includes(`${sep}docs${sep}`),
    })

    const entry = pathToFileURL(join(modulesDir, 'dsh-sentinel', 'plugin', 'index.js')).href
    const plugin = await import(entry)

    assert.equal(plugin.name, 'sentinel')
    assert.deepEqual(plugin.inject, ['tools'])
    assert.equal(typeof plugin.apply, 'function')

    const registered = []
    const fakeCtx = {
      logger: { info() {} },
      tools: {
        register(def) {
          registered.push(def)
          return () => {}
        },
      },
    }
    plugin.apply(fakeCtx)
    assert.equal(registered.length, 3)
    const names = registered.map((d) => d.name)
    assert.ok(names.includes('sentinel_scan'))
    assert.ok(names.includes('sentinel_scan_profile'))
    assert.ok(names.includes('sentinel_audit_package'))

    // Execute the scan tool against the evil fixture: dangerous + render text.
    const scanTool = registered.find((d) => d.name === 'sentinel_scan')
    const evilDir = join(REPO_ROOT, 'test', 'fixtures', 'evil-plugin')
    const report = await scanTool.execute({ path: evilDir })
    assert.equal(report.summary.verdict, 'dangerous')
    // Render is invoked by the framework as render(args, value).
    const blocks = scanTool.output.render({ path: evilDir }, report)
    assert.ok(blocks[0].text.includes('DANGEROUS'))
    assert.ok(blocks[0].text.includes('SEN-EXFIL-001'))

    // Profile tool against a fake DSH home.
    const profileTool = registered.find((d) => d.name === 'sentinel_scan_profile')
    const fakeHome = join(tmp, 'home')
    const fakeModules = join(fakeHome, 'profiles', 'web', 'node_modules')
    mkdirSync(join(fakeModules, 'third-party-evil', 'plugin'), { recursive: true })
    writeFileSync(join(fakeModules, 'third-party-evil', 'package.json'), JSON.stringify({
      name: 'third-party-evil', version: '0.0.1', dsh: { bundle: { patch: './cordis.patch.yml' } },
    }))
    writeFileSync(join(fakeModules, 'third-party-evil', 'cordis.patch.yml'),
      "- insert:\n    - id: e\n      name: 'third-party-evil/plugin'\n")
    writeFileSync(join(fakeModules, 'third-party-evil', 'plugin', 'index.js'),
      "export const name = 'e'\nexport function apply() { eval(atob('eA==')) }\n")

    const previousHome = process.env.DSH_HOME
    process.env.DSH_HOME = fakeHome
    try {
      const profileReport = await profileTool.execute({ profile: 'web' })
      assert.equal(profileReport.target.kind, 'profile')
      assert.deepEqual(profileReport.profile.pluginsScanned, ['third-party-evil'])
      assert.ok(profileReport.findings.some((f) => f.package === 'third-party-evil' && f.id === 'SEN-EXEC-004'))
    } finally {
      if (previousHome === undefined) delete process.env.DSH_HOME
      else process.env.DSH_HOME = previousHome
    }
  } finally {
    removeTempTree(tmp, t)
  }
})

import { sep } from 'node:path'
