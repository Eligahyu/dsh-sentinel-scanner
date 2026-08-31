#!/usr/bin/env node
/**
 * dsh-sentinel CLI — standalone plugin security scanner.
 *
 * Usage:
 *   dsh-sentinel <path> [--json] [--out <file>] [--max-files <n>]
 *   dsh-sentinel --profile <name> [--json] [--out <file>] [--max-plugins <n>]
 *   dsh-sentinel --rules
 *
 * 配置优先级:CLI 参数 > sentinel.config.json > 内置默认。
 *
 * Exit codes (CI-friendly):
 *   0  verdict safe | review
 *   1  verdict risky | dangerous(或 --fail-on 阈值被超过)
 *   2  usage error / scan failure
 *   3  incomplete scan(--fail-on-incomplete / --strict-exit-codes 时)
 */

import { scan, scanProfile, RULES, VERSION } from '../engine/index.js'
import { SEVERITY_ORDER } from '../engine/rules.js'
import { normalizeDynamicOptions } from '../engine/dynamic/policy.js'
import { relative as pathRelative, isAbsolute as pathIsAbsolute } from 'node:path'

const VERDICT_EMOJI = { safe: '✅', review: '👀', risky: '⚠️', dangerous: '🚨' }
const SEV_LABEL = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'low', info: 'info' }

function color(code, text, enabled) {
  return enabled ? `\u001b[${code}m${text}\u001b[0m` : text
}

function usage(out) {
  out.write(`dsh-sentinel ${VERSION} — 给 DSH 插件拍 X 光 / plugin security & health scanner

Usage:
  dsh-sentinel <path>                 scan a plugin repo/directory (or single file)
  dsh-sentinel --profile <name>       audit third-party plugins in a DSH profile
  dsh-sentinel npm:<package>[@ver]    install-time audit of an npm package (quarantine, no install)
  dsh-sentinel audit-install <pkg>    same as npm:<pkg>
  dsh-sentinel diff <srcDir> <spec>   source-vs-published-package drift diff
  dsh-sentinel --rules                print the rule catalog

Options:
  --json          emit the canonical report as JSON
  --format <fmt>  output format: json | text | sarif | html | cyclonedx | spdx
  --out <file>    write the report to a file, print a summary to stdout
  --baseline <f>  diff against a previous report (by stable fingerprint)
  --fail-on <lvl> exit 1 when any finding ≥ level (critical|high|medium|low); CLI 优先于 config
  --fail-on-incomplete  exit 3 when the scan is incomplete (files/bytes/plugins capped)
  --strict-exit-codes   0=ok 1=threshold 2=runtime/usage 3=incomplete scan
  --max-files <n> cap scanned files (default 3000)
  --max-plugins <n> cap plugins scanned per profile (default 12)
  --max-bytes <n>  max bytes per file before large-file-lite (default 524288)
  --mode <mode>   scan mode: source(默认,跳过 dist/build) | package(扫构建产物) | profile
  --config <path> sentinel.config.json path (auto-detected in cwd)
  --include-builtins  include trusted @deepseek-ai scopes in profile audits
  --redact-paths  anonymize absolute paths in shareable reports (<workspace>/...)
  --advisories    query OSV for known vulnerabilities (default OFF; uploads name+version only)
  --provenance    read npm provenance attestations (default OFF)
  --dynamic       request bounded dynamic analysis (Phase A may be unavailable)
  --dynamic-backend <name>  backend: auto | docker | podman
  --dynamic-profile observe  dynamic analysis profile (Phase A only)
  --dynamic-timeout <ms>     dynamic analysis timeout in milliseconds
  -h, --help      show this help

Exit codes: 0 = safe/review, 1 = risky/dangerous or --fail-on exceeded, 2 = usage error.
`)
}

function formatText(report, out) {
  const s = report.summary
  const tty = Boolean(out.isTTY)
  const emoji = VERDICT_EMOJI[s.verdict] ?? '❓'
  const sevColor = { safe: 32, review: 33, risky: 33, dangerous: 31 }[s.verdict] ?? 0
  const banner = `${emoji} ${color(sevColor, s.verdict.toUpperCase(), tty)} — risk score ${s.score}/100`
  out.write(`\n${banner}\n`)
  out.write('─'.repeat(Math.min(72, banner.length + 12)) + '\n')
  if (s.scanComplete === false) {
    out.write(`${color(31, '⚠ INCOMPLETE SCAN — 扫描不完整,结果仅代表已分析部分', tty)}\n`)
  }
  const dynamic = report.analysisLayers?.dynamic
  if (dynamic?.requested === true) {
    out.write(`dynamic analysis ${dynamic.status}\n`)
    if (dynamic.complete !== true) {
      out.write('dynamic analysis is not a successful deep verdict.\n')
    }
  }
  out.write(`target        ${report.target.kind === 'profile' ? `profile "${report.target.name}"` : report.target.path}\n`)
  const m = report.manifest
  if (m?.name) out.write(`manifest      ${m.name}${m.version ? `@${m.version}` : ''} · isBundle=${m.isBundle}${m.patch ? ` · patch=${m.patch}` : ''}\n`)
  if (report.target.kind === 'profile') {
    out.write(`plugins       ${report.profile.pluginsScanned.join(', ') || '(none)'}\n`)
    if (report.profile.pluginsSkipped.length > 0) {
      out.write(`skipped       ${report.profile.pluginsSkipped.length} plugins:\n`)
      for (const sk of report.profile.pluginsSkipped) {
        const name = typeof sk === 'string' ? sk : sk.name
        const reason = typeof sk === 'string' ? '' : ` (${sk.reason})`
        out.write(`                - ${name}${reason}\n`)
      }
    }
  }
  out.write(`files         ${s.filesAnalyzed}/${s.filesDiscovered} analyzed` +
    ` (${report.scanCoverage?.buildFiles ?? 0} build · ${report.scanCoverage?.largeFiles ?? 0} large-lite · ${report.scanCoverage?.binaryFiles ?? 0} binary · ${report.scanCoverage?.hardSkippedFiles ?? 0} hard-skipped)\n`)
  out.write(`findings      ${s.findingsTotal} total(返回 ${s.findingsReturned}) · ` +
    SEVERITY_ORDER.map((sev) => `${SEV_LABEL[sev]} ${s.bySeverity[sev]}`).join(' · ') + '\n')
  out.write(`context       source ${s.byContext?.source ?? 0} · test ${s.byContext?.test ?? 0} (test 文件命中降一级计分,除非被运行入口可达)\n`)
  out.write(`categories    ` +
    Object.entries(s.byCategory).filter(([, n]) => n > 0).map(([c, n]) => `${c} ${n}`).join(' · ') + '\n')
  if (s.scoreBasedOnAllFindings) out.write(`scoring       score 基于全部 ${s.findingsTotal} 条有效命中(scoreBasedOnAllFindings)\n`)
  out.write(`scan time     ${s.scanMs} ms\n`)

  if (report.findings.length > 0) {
    out.write('\nfindings:\n')
    for (const f of report.findings) {
      const loc = f.package ? `${f.package}:${f.file}:${f.line}` : `${f.file}:${f.line}`
      const sev = SEV_LABEL[f.severity].padEnd(8)
      const sevCode = { critical: 31, high: 33, medium: 33, low: 0, info: 0 }[f.severity] ?? 0
      const tag = `${f.testFile ? ' (test)' : ''}${f.bundleFile ? ' (bundle)' : ''}${f.redacted ? ' (secret redacted)' : ''}${f.suppressedForScore ? ' (suppressed-for-score)' : ''}`
      out.write(`  ${color(sevCode, sev, tty)} ${f.id} ${loc}${tag}\n`)
      out.write(`    ${f.message}\n`)
      if (f.snippet) out.write(`    ${f.snippet.slice(0, 120)}${f.snippet.length > 120 ? '…' : ''}\n`)
    }
    if (report.findings.length < s.findingsTotal) {
      out.write(`  … ${s.findingsTotal - report.findings.length} more findings(总数 ${s.findingsTotal})\n`)
    }
  } else {
    out.write('\n当前启用规则未发现问题;这不等价于插件已被证明安全。\n')
    out.write('No findings detected by enabled rules; this does not prove the plugin is safe.\n')
  }
  out.write('\n')
}

/** 可分享输出中的绝对路径匿名化(<workspace>/...)。 */
function redactReportPaths(report, basePath) {
  const rel = (p) => {
    if (!p || typeof p !== 'string') return p
    const r = pathRelative(basePath, p)
    if (pathIsAbsolute(p) && !r.startsWith('..') && r !== '..') return r
    return p
  }
  report.target.path = `<workspace>/${report.target.path.split(/[\\/]/).filter(Boolean).pop() ?? 'target'}`
  for (const f of report.findings ?? []) {
    f.file = rel(f.file) ?? f.file
  }
  for (const s of report.stats?.largestFiles ?? []) {
    s.file = rel(s.file) ?? s.file
  }
  for (const h of report.hardSkipped ?? []) {
    h.path = rel(h.path) ?? h.path
  }
  return report
}

export async function main(argv, io = { stdout: process.stdout, stderr: process.stderr }) {
  const { stdout, stderr } = io
  const args = [...argv]
  const opts = { json: false, format: 'text', out: null, maxFiles: undefined, maxPlugins: undefined, maxBytes: undefined, configPath: null, includeBuiltins: false, baseline: null, failOn: null, advisories: false, provenance: false, redactPaths: false, failOnIncomplete: false, strictExitCodes: false, dynamic: false, dynamicBackend: undefined, dynamicProfile: undefined, dynamicTimeoutMs: undefined }
  const positional = []
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i]
    switch (a) {
      case '--json': opts.json = true; opts.format = 'json'; break
      case '--advisories': opts.advisories = true; break
      case '--provenance': opts.provenance = true; break
      case '--dynamic': opts.dynamic = true; break
      case '--dynamic-backend': {
        const value = args[i + 1]
        if (value === undefined || value.startsWith('-')) {
          stderr.write('dsh-sentinel: --dynamic-backend requires a value (auto|docker|podman)\n')
          return 2
        }
        opts.dynamicBackend = value
        i += 1
        break
      }
      case '--dynamic-profile': {
        const value = args[i + 1]
        if (value === undefined || value.startsWith('-')) {
          stderr.write('dsh-sentinel: --dynamic-profile requires a value (observe)\n')
          return 2
        }
        opts.dynamicProfile = value
        i += 1
        break
      }
      case '--dynamic-timeout': {
        const value = args[i + 1]
        if (value === undefined || value.startsWith('-')) {
          stderr.write('dsh-sentinel: --dynamic-timeout requires a value in milliseconds\n')
          return 2
        }
        opts.dynamicTimeoutMs = value
        i += 1
        break
      }
      case '--redact-paths': opts.redactPaths = true; break
      case '--fail-on-incomplete': opts.failOnIncomplete = true; break
      case '--strict-exit-codes': opts.strictExitCodes = true; break
      case '--format': {
        const fmt = args[++i]
        if (!['json', 'text', 'sarif', 'html', 'cyclonedx', 'spdx'].includes(fmt)) {
          stderr.write(`dsh-sentinel: --format must be json|text|sarif|html|cyclonedx|spdx (got ${fmt})\n`)
          return 2
        }
        opts.format = fmt
        break
      }
      case '--baseline': opts.baseline = args[++i]; break
      case '--fail-on': {
        const level = args[++i]
        if (!['critical', 'high', 'medium', 'low'].includes(level)) {
          stderr.write(`dsh-sentinel: --fail-on must be critical|high|medium|low (got ${level})\n`)
          return 2
        }
        opts.failOn = level
        break
      }
      case '--out': opts.out = args[++i]; break
      case '--max-files': opts.maxFiles = Number(args[++i]); break
      case '--max-plugins': opts.maxPlugins = Number(args[++i]); break
      case '--max-bytes': opts.maxBytes = Number(args[++i]); break
      case '--config': opts.configPath = args[++i]; break
      case '--include-builtins': opts.includeBuiltins = true; break
      case '--rules': {
        for (const r of RULES) {
          stdout.write(`${r.id} [${r.severity.padEnd(8)}] ${r.category.padEnd(12)} ${r.name} — ${r.message}\n`)
        }
        return 0
      }
      case '--mode': {
        const mode = args[++i]
        if (!['source', 'package', 'profile'].includes(mode)) {
          stderr.write(`dsh-sentinel: --mode must be source|package|profile (got ${mode})\n`)
          return 2
        }
        opts.mode = mode
        break
      }
      case '-h': case '--help': usage(stdout); return 0
      default:
        if (a.startsWith('--profile')) {
          opts.profile = args[++i]
        } else if (a.startsWith('-')) {
          stderr.write(`dsh-sentinel: unknown option ${a}\n`)
          usage(stderr)
          return 2
        } else {
          positional.push(a)
        }
    }
  }

  let effectiveFailOn = null
  const run = (async () => {
    // 配置:默认 ← sentinel.config.json(优先从目标目录检测)← CLI 覆盖(CLI 优先)
    const { loadConfig, mergeOverrides } = await import('../engine/config.js')
    const targetLike = positional[0] && !['audit-install', 'diff'].includes(positional[0]) && !positional[0].startsWith('npm:')
    const { config } = loadConfig({
      configPath: opts.configPath,
      cwd: targetLike && opts.profile === undefined ? positional[0] : process.cwd(),
    })
    if (config.redactSecrets === false) {
      stderr.write('dsh-sentinel: 警告 — config 中 redactSecrets=false 被忽略:secret 脱敏永远开启(不可关闭)\n')
    }
    const effective = mergeOverrides(config, {
      mode: opts.mode,
      maxFiles: opts.maxFiles,
      maxBytesPerFile: opts.maxBytes,
      maxFindings: opts.maxFindings,
      maxPlugins: opts.maxPlugins,
      includeBuiltins: opts.includeBuiltins ? true : undefined,
      failOn: opts.failOn ?? config.failOn,
    })
    const normalizedDynamicOptions = normalizeDynamicOptions({
      dynamic: opts.dynamic || effective.dynamic,
      dynamicBackend: opts.dynamicBackend ?? effective.dynamicBackend,
      dynamicProfile: opts.dynamicProfile ?? effective.dynamicProfile,
      dynamicTimeoutMs: opts.dynamicTimeoutMs ?? effective.dynamicTimeoutMs,
    })
    const dynamicOptions = {
      dynamic: normalizedDynamicOptions.requested,
      dynamicBackend: normalizedDynamicOptions.backendName,
      dynamicProfile: normalizedDynamicOptions.profile,
      dynamicTimeoutMs: normalizedDynamicOptions.timeoutMs,
    }
    effectiveFailOn = effective.failOn ?? null
    // 安装前审计:audit-install <pkg> 或 npm:<pkg>
    const auditSpec = positional[0] === 'audit-install' ? positional[1] : positional[0]?.startsWith('npm:') ? positional[0] : null
    if (auditSpec) {
      const { auditNpmSpec } = await import('../engine/package/audit.js')
      return { __audit: await auditNpmSpec(auditSpec, { maxFiles: effective.maxFiles, maxFindings: effective.maxFindings, advisories: opts.advisories || config.advisories, provenance: opts.provenance }) }
    }
    // 源码 ↔ 发布包 diff
    if (positional[0] === 'diff') {
      const { diffPackageWithSource } = await import('../engine/package/diff.js')
      return { __diff: await diffPackageWithSource(positional[1], positional[2]) }
    }
    if (opts.profile !== undefined) {
      return scanProfile(opts.profile, {
        maxPlugins: effective.maxPlugins,
        maxFiles: effective.maxFiles,
        maxFindings: effective.maxFindings,
        maxBytesPerFile: effective.maxBytesPerFile,
        includeBuiltins: effective.includeBuiltins,
        trustedScopes: config.trustedScopes,
        ...dynamicOptions,
      })
    }
    if (positional.length === 0) {
      usage(stderr)
      return null
    }
    return scan(positional[0], {
      maxFiles: effective.maxFiles,
      maxBytesPerFile: effective.maxBytesPerFile,
      maxFindings: effective.maxFindings,
      mode: effective.mode,
      ignore: config.ignore,
      includeBuildArtifacts: config.includeBuildArtifacts,
      ...dynamicOptions,
    })
  })()

  try {
    let result = await run
    if (result === null) return 2

    // 指纹 + baseline(Phase 7)
    const { attachFingerprints, diffBaseline } = await import('../engine/report/fingerprint.js')
    const output = result.__audit ? result.__audit.report : result
    attachFingerprints(output)
    if (opts.baseline) {
      const { readFileSync } = await import('node:fs')
      let baseline = null
      try {
        baseline = JSON.parse(readFileSync(opts.baseline, 'utf8'))
        attachFingerprints(baseline)
      } catch (error) {
        stderr.write(`dsh-sentinel: baseline 读取失败(${opts.baseline}): ${error.message}\n`)
        return 2
      }
      const diff = diffBaseline(output, baseline)
      output.baseline = diff
      if (opts.format === 'text') {
        stdout.write(`\nbaseline: new ${diff.newFindings} · existing ${diff.existingFindings} · resolved ${diff.resolvedFindings}\n`)
        for (const f of diff.new.slice(0, 10)) {
          stdout.write(`  NEW [${f.severity}] ${f.id} ${f.file}:${f.line} — ${f.message}\n`)
        }
      }
    }

    if (result.__diff) {
      const { diff, findings, package: pkgName, version } = result.__diff
      stdout.write(`\n🔀 SOURCE vs PACKAGE DIFF — ${pkgName}@${version}\n`)
      stdout.write(`  extra files: ${diff.extraFiles.length} · modified: ${diff.modifiedFiles.length} · unexpected binaries: ${diff.unexpectedBinaries.length} · script diff: ${diff.scriptDiff.length}\n`)
      for (const f of findings) {
        stdout.write(`  ⚠ [${f.severity}] ${f.message}\n`)
        if (f.detail) stdout.write(`    ${f.detail}\n`)
      }
      if (opts.format === 'json') {
        stdout.write(JSON.stringify({ diff, findings }, null, 2) + '\n')
      }
      return findings.length > 0 ? 1 : 0
    }

    if (result.__audit) {
      const { report, audit } = result.__audit
      if (opts.format !== 'json') {
        const verdictEmoji = { ALLOW: '✅', REVIEW: '👀', 'BLOCK-RECOMMENDED': '🚫' }[audit.verdict] ?? '❓'
        stdout.write(`\n${verdictEmoji} INSTALL AUDIT: ${audit.verdict} — ${audit.package}@${audit.version}\n`)
        stdout.write(`  tarball sha256: ${audit.tarballSha256}\n`)
        stdout.write(`  integrity: ${audit.integrityOk ? 'OK' : `FAIL (${audit.integrityReason ?? 'unknown'})`}\n`)
        stdout.write(`  dependencies: ${audit.dependencyCount} · install scripts: ${audit.installScripts.join(', ') || 'none'}\n`)
        if (audit.extractionError) stdout.write(`  extraction: BLOCKED (${audit.extractionError})\n`)
      }
      if (opts.format === 'json') {
        // audit 元数据必须与 report 一起输出(Harness Tool 与 CLI 保持一致)
        const payload = { ...report, audit }
        if (opts.redactPaths) redactReportPaths(payload, positional[1] ?? process.cwd())
        stdout.write(JSON.stringify(payload, null, 2) + '\n')
      } else {
        formatText(report, stdout)
      }
      if (opts.out) {
        const { writeFileSync } = await import('node:fs')
        writeFileSync(opts.out, JSON.stringify(opts.format === 'json' ? { ...report, audit } : report, null, 2) + '\n')
      }
      return audit.verdict === 'BLOCK-RECOMMENDED' ? 1 : 0
    }

    // 输出前:可分享报告路径匿名化(--redact-paths)
    if (opts.redactPaths) redactReportPaths(output, positional[0] ?? process.cwd())

    // 输出格式:json / sarif / html / text
    if (opts.format === 'cyclonedx' || opts.format === 'spdx') {
      const graph = output.analysisLayers?.dependencyGraph
      if (!graph || graph.complete === false) {
        stderr.write('dsh-sentinel: SBOM export requires a complete supported dependency graph\n')
        return 2
      }
      const { toCycloneDx, toSpdx } = await import('../engine/supplychain/sbom.js')
      const document = opts.format === 'cyclonedx' ? toCycloneDx(graph, { toolVersion: output.version }) : toSpdx(graph, { toolVersion: output.version })
      const serialized = JSON.stringify(document, null, 2) + '\n'
      if (opts.out) {
        const { writeFileSync } = await import('node:fs')
        writeFileSync(opts.out, serialized)
        stdout.write(`${opts.format} SBOM written to ${opts.out}\n`)
      } else {
        stdout.write(serialized)
      }
    } else if (opts.format === 'html') {
      const { toHtml } = await import('../engine/output/html.js')
      const html = toHtml(output)
      if (opts.out) {
        const { writeFileSync } = await import('node:fs')
        writeFileSync(opts.out, html)
        stdout.write(`HTML report written to ${opts.out}\n`)
      } else {
        stdout.write(html)
      }
    } else if (opts.format === 'sarif') {
      const { toSarif } = await import('../engine/output/sarif.js')
      const sarif = JSON.stringify(toSarif(output, { basePath: positional[0] }), null, 2) + '\n'
      if (opts.out) {
        const { writeFileSync } = await import('node:fs')
        writeFileSync(opts.out, sarif)
        stdout.write(`SARIF written to ${opts.out}\n`)
      } else {
        stdout.write(sarif)
      }
    } else if (opts.out) {
      const { writeFileSync } = await import('node:fs')
      writeFileSync(opts.out, JSON.stringify(output, null, 2) + '\n')
      stdout.write(`report written to ${opts.out}\n`)
      formatText(output, stdout)
    } else if (opts.format === 'json') {
      stdout.write(JSON.stringify(output, null, 2) + '\n')
    } else {
      formatText(output, stdout)
    }

    // 退出码:--fail-on 阈值优先(CLI > config),否则按裁决
    let exitCode = 0
    if (effectiveFailOn) {
      const order = { critical: 0, high: 1, medium: 2, low: 3 }
      const threshold = order[effectiveFailOn]
      const exceeded = output.findings.some((f) => order[f.severity] !== undefined && order[f.severity] <= threshold)
      exitCode = exceeded ? 1 : 0
    } else {
      exitCode = output.summary.verdict === 'risky' || output.summary.verdict === 'dangerous' ? 1 : 0
    }
    const dynamicIncomplete = output.analysisLayers?.dynamic?.requested === true
      && output.analysisLayers.dynamic.complete !== true
    // 不完整扫描或请求的深度扫描未完成:严格模式 → exit 3。
    if ((opts.failOnIncomplete || opts.strictExitCodes)
      && (output.summary.scanComplete === false || dynamicIncomplete)) return 3
    return exitCode
  } catch (error) {
    stderr.write(`dsh-sentinel: ${error?.message ?? String(error)}\n`)
    return 2
  }
}

// Direct execution (works on Windows too — compare via pathToFileURL).
import { pathToFileURL } from 'node:url'
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const code = await main(process.argv.slice(2))
  process.exit(code)
}
