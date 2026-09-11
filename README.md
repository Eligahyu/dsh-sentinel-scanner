<div align="center">

# 🛡️ dsh-sentinel

[![Awesome DSH Plugin](https://awesome-dsh-plugin.com/badge.svg)](https://awesome-dsh-plugin.com)

**Read-only security, supply-chain, and health scanner for DeepSeek Harness plugins**

Heuristic rules, AST/taint analysis, package quarantine, dependency intelligence,
SBOM export, SARIF, and CI policy enforcement—without executing scanned code.

`Node.js ^22.18.0 or >=24.11.0 · Static analysis primary; Phase B dynamic analysis is explicit opt-in and network-denied · MIT`

[English](#english) · [中文](README.zh-CN.md) · [Rules](docs/rules.md) ·
[Architecture](docs/architecture.md) · [Roadmap](docs/roadmap.md)

</div>

---

# English

## What is dsh-sentinel?

**dsh-sentinel** gives DeepSeek Harness (DSH) plugins an X-ray before you trust or
install them. It is a read-only static security scanner for plugin source trees,
published npm packages, DSH profiles, and CI pipelines.

The scanner looks for command execution, dynamic code evaluation, credential
access, data exfiltration, obfuscation, unsafe lifecycle scripts, persistence,
native binaries, manifest escape paths, and package drift. It combines 51
heuristic rules with AST-based taint analysis, bounded module and cross-file
analysis, supply-chain metadata, and explicit scan-coverage reporting.

Every scan produces a structured report with a **0–100 risk score**, a
`safe / review / risky / dangerous` verdict, evidence for each finding, and
actionable remediation guidance. The same engine is available as:

- a DSH Agent Tool plugin: `sentinel_scan`, `sentinel_scan_profile`, and
  `sentinel_audit_package`;
- a standalone CLI: npm package `deepseek-harness-sentinel`, executable
  `dsh-sentinel`;
- a GitHub Action with SARIF upload support;
- a JavaScript API for programmatic integrations.

> **Security disclaimer:** heuristic static analysis is not a proof of safety.
> A finding means “review this evidence,” not “this plugin is malicious.” A clean
> report means that enabled checks found no issue; it does not guarantee safety.

## Why this project exists

DSH plugins may run with the same filesystem, network, credential, and process
permissions as the user or agent that loads them. A small install script, hidden
download-and-execute chain, unsafe tool argument, or escaped manifest path can
therefore become a supply-chain incident.

dsh-sentinel is designed for two audiences:

- **Plugin users:** inspect third-party code before installation or activation.
- **Plugin authors and maintainers:** detect dangerous behavior, packaging drift,
  incomplete scans, and manifest defects before publishing.

## Security model and non-negotiable boundaries

1. **Scanned code is never executed.** The scanner does not `require`, `import`,
   `eval`, or spawn target code.
2. **Pre-install audit does not run `npm install`.** It downloads a tarball,
   verifies integrity, extracts it into quarantine, scans it, and cleans up.
3. **Source code is not uploaded.** Optional OSV lookup is disabled by default
   and sends only package name and version when enabled.
4. **Secrets are always redacted.** Reports retain fingerprints and evidence
   without exposing raw secret values.
5. **Skipped work is visible.** Limits, oversized files, ignored paths, parser
   boundaries, and policy skips are represented in the report.
6. **Automation is not detection.** SARIF, HTML, GitHub Actions, and SBOM formats
   transport or present results; detection capability lives in the engine.
7. **Dynamic analysis is explicit opt-in.** Static analysis remains the default;
   `--dynamic` adds a separate Phase B layer and never changes the static result.
8. **Phase B has no host-execution fallback.** It can run only inside a local,
   scanner-owned, immutable-image Docker or Podman runner. This checkout has no
   compiled/deployed approved image, so production resolution currently reports
   `unavailable` rather than executing a package.

## Capabilities

| Area | What it does |
| --- | --- |
| Heuristic rules | 51 rules across execution, credentials, exfiltration, obfuscation, install scripts, filesystem, network, manifests, Agent Tools, taint, supply chain, binaries, and persistence. |
| Agent Tool analysis | Traces `defineTool` inputs such as `args.*` into shell, filesystem, network, and dynamic-code sinks. Handles aliases, computed properties, optional chaining, variable propagation, and bounded cross-function flows. |
| Module and cross-file analysis | Builds a bounded JS/TS module graph across ESM and statically provable CommonJS `require` / `require.resolve` edges, including constant string concatenation and TypeScript `.js` specifiers that map to `.ts` sources. Cross-file taint follows ESM imports and destructured CommonJS exports; unprovable dynamic module specifiers are reported instead of guessed. TypeScript parser limits are reported as a capability boundary instead of falsely failing every TS scan. |
| Language-aware coverage | JS-family files receive semantic analysis. TypeScript is conservatively degraded where syntax exceeds the parser boundary. Python and PowerShell files are not incorrectly fed into the JS parser and still receive applicable heuristic scanning. |
| DSH manifest validation | Audits `dsh.bundle`, `cordis.patch.yml`, package entry contracts, and lexical/realpath/symlink containment. Escaping paths trigger `SEN-MAN-009`. |
| Scan modes | `source` skips generated build trees by default; `package` includes distributable output such as `dist` and `build`; `profile` discovers and audits installed DSH plugins. |
| Pre-install quarantine | Safely extracts npm tarballs while blocking traversal, absolute paths, drive paths, symlink/hardlink entries, and tar bombs. Verifies sha512 integrity and cleans up all artifacts. |
| Supply-chain analysis | Inspects lifecycle scripts, npm and pnpm v9 normalized lockfile graphs, package metadata, optional OSV advisories, optional provenance, and source-versus-package drift. Unsupported lockfile formats remain explicit warnings. |
| Native artifacts | Audits `.wasm`, `.exe`, `.dll`, `.so`, `.node`, and related files using magic bytes, size, SHA-256, entropy, and printable strings. Binaries are never executed. |
| Professional report layers | Stable report schema v2 with module graph, dependency graph, capability graph, SBOM, provenance, attack chains, coverage, and failure metadata. |
| Output and CI | Text, JSON, SARIF 2.1.0, standalone HTML, CycloneDX, and SPDX output; stable fingerprints, baselines, threshold exits, and incomplete-scan enforcement. |
| Privacy | Automatic secret redaction, optional path anonymization with `--redact-paths`, and no hidden ignore/skip behavior. |
| Dynamic analysis (Phase B) | Explicit opt-in, static-preflight-gated, network-denied Docker/Podman runner with immutable image and staged-input contracts. The current release remains `unavailable` until a scanner-owned image is compiled/deployed. |

### Core analysis versus auxiliary analysis

Scan completeness distinguishes security-critical coverage from optional enrichment:

- failures in core coverage, such as module or cross-file analysis failures, can
  set `scanComplete=false`;
- dependency graph, SBOM, provenance, and capability-graph failures are preserved
  as warnings and degraded output rather than falsely claiming source files were
  not scanned;
- unsupported or complex lockfile formats are reported instead of producing
  guessed dependency data.

## Dynamic Analysis (Phase B)

Static completeness and dynamic completeness are separate signals. The static
scan remains the primary verdict and continues to report `summary.scanComplete`.
When `--dynamic` is requested, a dedicated `analysisLayers.dynamic` record
reports the deep-analysis state instead of changing or hiding static coverage.

Phase B is an explicit opt-in release gate layered after static analysis. It is
not a claim that a finite runtime exercise proves a plugin safe. Static
preflight remains authoritative for the static verdict, while
`analysisLayers.dynamic` reports the independent dynamic state. A scan without
`--dynamic` does not probe Docker or Podman and does not start a runner.

The production resolver accepts only a scanner-owned image compiled/deployed at
an immutable digest and a local Docker or Podman capability probe. If the image
is absent, mutable, remote, or unhealthy, the dynamic layer is `unavailable`
with a fixed reason such as `trusted-image-unavailable`; it does not pull,
build, execute on the host, or silently fall back. The current package ships no
approved image, so normal CLI/API use remains safely unavailable until the
release deployment supplies one.

### Static preflight and status

Static analysis always runs first. Phase B refuses execution when preflight finds
high-risk native executables or native Node modules selected for execution,
container-control or escape signals, artifact limits, unresolved entrypoints,
incomplete core traversal, or an unavailable isolation backend. Refusal is
reportable and never erases static findings.

The dynamic status is one of `not-requested`, `unavailable`, `refused`,
`complete`, or `incomplete`:

| Status | Meaning |
| --- | --- |
| `not-requested` | No `--dynamic` request was made. No engine probe occurs. |
| `unavailable` | The local, immutable Phase B prerequisites are not present; the target was not run. |
| `refused` | Static preflight rejected the target as outside the Phase B threat boundary. |
| `complete` | All allowlisted stages produced bounded evidence and exact cleanup completed. |
| `incomplete` | A stage, evidence parser, timeout, cancellation, resource limit, or cleanup path was uncertain. |

With `--fail-on-incomplete` or `--strict-exit-codes`, requested
`unavailable`/`refused`/`incomplete` dynamic results return exit code `3`.
Without those strict controls, the result remains visible and the static exit
policy is unchanged. `complete` means only that the supplied stages and stimuli
completed; it is not a proof of safety, and no observed traffic means only that
these bounded stages did not trigger traffic.

### Linux prerequisites and Phase B runner boundary

The supported release gate is a protected, administrator-managed Linux
self-hosted runner labeled `self-hosted`, `linux`, and `dsh-sentinel-phase-b`,
with a local Docker or rootless Podman engine and a preloaded scanner-owned image
referenced by a full `sha256` digest. The protected environment is named
`dynamic-analysis-protected`. The image must already be present: Phase B uses
`--pull=never` and performs no image build. Engine selection is the fixed
`docker|podman` allowlist; remote endpoints and contexts are not accepted. Before
either engine command, the gate rejects any non-empty `DOCKER_HOST`,
`DOCKER_CONTEXT`, `CONTAINER_HOST`, `CONTAINER_CONNECTION`, `DOCKER_CONFIG`,
`CONTAINERS_CONF`, `CONTAINERS_STORAGE_CONF`, `PODMAN_CONNECTIONS_CONF`, or
`XDG_CONFIG_HOME`, then unsets those selectors/configuration variables. It uses
only `/usr/bin/docker` or `/usr/bin/podman`, a controlled empty environment and
`/` as the working directory, with Docker bound to
`--host=unix:///var/run/docker.sock` or Podman bound to
`--url=unix:///run/user/<uid>/podman/podman.sock`. An unsafe selector fails
closed before image inspection; the engine socket is never mounted into the
container.

Each allowlisted stage uses a fresh, short-lived runner with the following
fixed properties:

The read-only staging mount is the only package input available to the runner;
the original workspace is never mounted.

- `--network=none`; Phase B has no public or private egress and does not provide
  a gateway or network observation path;
- private PID and IPC namespaces, a read-only root filesystem, a read-only
  staging mount, a non-root UID, dropped capabilities (all Linux capabilities
  are dropped), and
  `no-new-privileges`;
- bounded CPU, memory, PID, temporary-storage, output, and wall-clock budgets;
- no user-provided container flags, no host workspace mount, no engine socket,
  no host namespaces, no host credentials, and no real credentials;
- no package-manager or lifecycle execution: no `preinstall`, `install`,
  `postinstall`, or `prepare`.

The staging lifecycle resolves and contains the scan root, copies only approved
regular files into a scanner-owned temporary snapshot, excludes links/devices,
sockets, VCS metadata, worktrees, and escape paths, mounts that snapshot
read-only, and removes it idempotently. Cleanup is ownership-scoped to the
current run. Any cleanup uncertainty is reported as `incomplete`; a report
must not expose raw engine diagnostics, full request bodies, host absolute paths,
or secret values.

### Phase B versus Phase C

Phase B intentionally stops at network denial. It binds the selected local
Docker/Podman endpoint and fixed harness executable through scanner-owned
arguments; callers cannot replace the endpoint, executable, image, mount, or
namespace policy. Trusted image ownership belongs to the scanner release, while
the staged package remains untrusted input. Gateway routing, DNS/HTTP/TCP/UDP
observation, Node preload probes, canary correlation, and any explicitly
allowlisted replay network belong to Phase C and are not implemented or implied
by a Phase B `complete` result.

The Linux-only CI gate is opt-in and runs only on that protected self-hosted
runner. It skips with an explicit `unavailable` reason when the protected
immutable image digest is absent or the exact image is not locally preloaded.
It has fixed two-minute job and 90-second host-command timeouts and never changes
the default static workflow. See `.github/workflows/dynamic-smoke.yml` for the
release contract.

The four opt-in controls are:

| Option | Phase B behavior |
| --- | --- |
| `--dynamic` | Opt in to Phase B after static preflight; no request means no engine probe. |
| `--dynamic-backend <auto\|docker\|podman>` | Select a local engine; Phase B still requires the immutable scanner-owned image and network denial. |
| `--dynamic-profile observe` | Select the bounded Phase B observation contract; Phase C gateway/probe behavior is not included. |
| `--dynamic-timeout <ms>` | Request a bounded timeout. Default: `15000`; values are clamped to the enforced `1000`–`30000` ms range. |

An unavailable, refused, or incomplete requested deep scan exits with code `3`
only when `--fail-on-incomplete` or `--strict-exit-codes` is set. Without either
strict flag, the deep-layer result remains visible but does not by itself fail
CI. This policy applies independently of static completeness.

### pnpm v9 dependency intelligence

dsh-sentinel supports the pnpm v9 lockfile layout as a read-only, normalized
dependency graph. It parses `importers`, `packages`, and `snapshots` with a
standards-aware YAML parser, preserves peer-suffixed package instances, resolves
`workspace:` / `link:` importer relationships, and keeps npm aliases attached to
the installed package identity. Workspace importer paths are containment-checked;
malformed YAML, path escapes, unresolved references, oversized lockfiles, and
unsupported pnpm lockfile versions are reported as explicit dependency-layer
failures rather than converted into guessed nodes.

The graph separates root direct dependencies from transitive package instances.
The dependency summary uses this normalized graph for pnpm v9, so its direct and
transitive counts are reproducible from the lockfile rather than inferred from
indentation or regular-expression matches. If normalization fails, the summary
returns zero counts with an explicit incomplete reason; it never presents a
partial count as exact.

pnpm's `requiresBuild: true` field is retained as build evidence. It means pnpm
recorded that the package requires a build step in the install plan; it does not
prove that a specific lifecycle script is present, and dsh-sentinel deliberately
does not label it as a known install script. Each such package can include a
shortest root-to-package dependency path in the report. The same evidence is
carried into CycloneDX and SPDX exports, with unique component references for
peer-suffixed instances. SBOM output remains a serialization of observed graph
metadata, not a claim that package code was executed or installed.

The current exact lockfile graph support is pnpm v9. Yarn and Bun lockfiles are
recognized and reported with an explicit unsupported/degraded state; they are
not counted as if their formats were fully normalized.

## Installation and quick start

### Standalone CLI

The npm package is `deepseek-harness-sentinel`; it installs the `dsh-sentinel`
executable.

```sh
# Run without a global install
npx deepseek-harness-sentinel ./path/to/plugin

# Or install it as a project dependency
npm install --save-dev deepseek-harness-sentinel
npx dsh-sentinel ./path/to/plugin
```

Common workflows:

```sh
# Canonical JSON report
npx deepseek-harness-sentinel ./plugin --json --out sentinel.json

# Scan published/build output and create SARIF
npx deepseek-harness-sentinel ./plugin \
  --mode package \
  --format sarif \
  --out sentinel.sarif

# Fail CI on high-or-critical findings or incomplete coverage
npx deepseek-harness-sentinel ./plugin \
  --fail-on high \
  --fail-on-incomplete \
  --strict-exit-codes

# Request the opt-in Phase B layer. Without a deployed scanner-owned image it
# reports unavailable; it never runs the target on the host.
npx deepseek-harness-sentinel ./plugin \
  --dynamic \
  --dynamic-backend auto \
  --dynamic-profile observe \
  --dynamic-timeout 15000

# Audit a package before installation; no lifecycle script is executed
npx deepseek-harness-sentinel audit-install some-plugin@1.2.3

# Compare a source tree with a published npm package
npx deepseek-harness-sentinel diff ./plugin some-plugin@1.2.3

# Print the complete rule catalog
npx deepseek-harness-sentinel --rules
```

### Install as a DSH plugin

```sh
# Local checkout
dsh plugin --profile web add ./dsh-sentinel

# GitHub repository
dsh plugin --profile web add github:Eligahyu/dsh-sentinel-scanner

# npm package
dsh plugin --profile web add deepseek-harness-sentinel

dsh --profile web
```

You can then ask the agent to:

```text
Use sentinel_scan to inspect ~/Downloads/some-plugin.
Use sentinel_scan_profile to audit third-party plugins in my web profile.
Use sentinel_audit_package to inspect some-plugin@1.2.3 before installation.
```

### GitHub Action

```yaml
name: Plugin security scan

on:
  pull_request:
  push:

permissions:
  contents: read
  security-events: write

jobs:
  sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7

      - name: Scan plugin
        uses: Eligahyu/dsh-sentinel-scanner@v0.4
        with:
          path: .
          mode: source
          fail-on: high
          fail-on-incomplete: true

      - name: Upload SARIF
        if: always() && hashFiles('sentinel.sarif') != ''
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: sentinel.sarif
```

The Action installs only its own dependencies under `${{ github.action_path }}`
with lifecycle scripts disabled. It never runs `npm install` or `npm ci` in the
repository being scanned. See the
[GitHub Action integration guide](docs/integration-github-action.md).

## CLI reference

```text
dsh-sentinel <path>                 scan a directory or a single file
dsh-sentinel --profile <name>       audit third-party plugins in a DSH profile
dsh-sentinel npm:<pkg>[@version]    pre-install quarantine audit
dsh-sentinel audit-install <pkg>    same as npm:<pkg>
dsh-sentinel diff <dir> <pkg>       compare source with a published package
dsh-sentinel --rules                print the rule catalog
```

| Option | Purpose |
| --- | --- |
| `--mode source\|package\|profile` | Select source, distributable-package, or profile behavior. |
| `--format text\|json\|sarif\|html\|cyclonedx\|spdx` | Select report format. |
| `--out <file>` | Write the full report to a file and keep a summary on stdout. |
| `--baseline <file>` | Compare against a previous report using stable fingerprints. |
| `--fail-on <severity>` | Exit 1 when a finding reaches `critical`, `high`, `medium`, or `low`. |
| `--fail-on-incomplete` | Exit 3 when coverage is incomplete. |
| `--strict-exit-codes` | Preserve distinct threshold, runtime, and incomplete-scan exits. |
| `--dynamic` | Request the opt-in Phase B layer after static preflight; no request keeps scans static-only. |
| `--dynamic-backend <auto\|docker\|podman>` | Select the local Docker/Podman backend; it still requires a scanner-owned immutable image. |
| `--dynamic-profile observe` | Select the bounded Phase B profile; gateway/probe observation is deferred to Phase C. |
| `--dynamic-timeout <ms>` | Bounded deep-analysis timeout; default `15000`, clamped to `1000`–`30000` ms. |
| `--max-files`, `--max-plugins`, `--max-bytes` | Set bounded resource limits. |
| `--config <file>` | Load `sentinel.config.json`; CLI values override config values. |
| `--redact-paths` | Replace absolute paths with shareable workspace labels. |
| `--advisories` | Query OSV with package name and version only; disabled by default. |
| `--provenance` | Read npm provenance attestations; disabled by default. |

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Scan completed and the configured policy threshold was not exceeded. |
| `1` | Risk or policy threshold exceeded. |
| `2` | Usage or runtime error. |
| `3` | Static scan incomplete, or requested dynamic analysis unavailable/refused/incomplete, only when `--fail-on-incomplete` or `--strict-exit-codes` is enabled. |

## Risk scoring and verdicts

| Severity | Weight | Typical evidence |
| --- | ---: | --- |
| `critical` | 50 | Remote download-and-execute, private credential reads, strong exfiltration evidence, destructive home-directory commands, unsafe tar paths. |
| `high` | 20 | Dynamic evaluation, hard-coded secrets, credential environment access, missing entry contracts, suspicious binary strings. |
| `medium` | 8 | Shell execution requiring review, network access, lifecycle scripts, high-entropy binaries, persistence behavior. |
| `low` | 3 | Suspicious encoding combinations, hard-coded public IPs, package-health metadata issues. |
| `info` | 0 | Informational native binary or WASM presence. |

The score is capped at 100:

```text
0–19   safe
20–49  review
50–79  risky
80–100 dangerous
```

Scoring is separated from report display:

- the score uses **all effective findings**, even when `maxFindings` limits the
  number of entries returned;
- a priority-bounded buffer prevents critical and high findings from being hidden
  by a flood of low-severity matches;
- minified or bundled code is tagged as evidence but is not automatically reduced
  in severity;
- test-directory findings score one level lower unless reachable from a runtime
  entry such as `main`, `exports`, `bin`, or a patch;
- overlapping semantic and generic findings retain evidence while duplicate score
  contribution is suppressed.

## Scan completeness

A low score is meaningful only when scan coverage is understood. Reports expose
`scanComplete`, `incompleteReasons`, discovered/analyzed file counts, large-file
handling, binaries, parser boundaries, ignored paths, and hard skips.

File/plugin limits, files above the hard size ceiling, binary sampling limits, and
core module/cross-file analysis failures can make a scan incomplete. TypeScript
syntax outside the current parser capability is explicitly degraded and recorded;
ordinary `.ts`, `.tsx`, or `.d.ts` presence is not an automatic scan failure.
Dynamic `import()` / `require()` targets that cannot be reduced to a static string
remain visible as `dynamic-module-specifier` warnings and never become invented
module-graph edges.

Static completeness does not imply dynamic completeness, and dynamic state does
not overwrite the static verdict. A requested Phase B scan may therefore be
`unavailable`, `refused`, or `incomplete` while the static report remains
complete; strict CI flags decide whether that separate deep-layer state returns
exit code `3`. `unavailable` is expected when the scanner-owned immutable image
has not been compiled/deployed.

## Pre-install package audit

```text
npm metadata
  -> tarball download
  -> sha512 integrity verification
  -> isolated quarantine directory
  -> safe extraction
  -> package-mode static scan
  -> cleanup on success or failure
  -> ALLOW / REVIEW / BLOCK-RECOMMENDED recommendation
```

The extractor rejects `../` traversal, absolute and drive-letter paths,
symlink/hardlink entries, excessive nesting, oversized entries, excessive total
output, and excessive archive entry counts. It never invokes npm lifecycle scripts.

See the [DSH pre-install integration design](docs/integration-dsh-preinstall.md).

## Reports and integrations

- **JSON:** canonical schema v2 for tools, storage, and custom policies.
- **SARIF 2.1.0:** GitHub Code Scanning with relative locations and stable
  fingerprints.
- **HTML:** portable, single-file human-readable report.
- **CycloneDX / SPDX:** SBOM export backed by normalized dependency data.
- **Baseline:** compare findings by fingerprint to focus on newly introduced risk.
- **Source/package diff:** detect drift between a repository and its published npm
  artifact (`SEN-SUPPLY-003`).

See [example JSON output](docs/example-report.json) and the
[architecture and report contracts](docs/architecture.md).

## How the engine works

```text
target
  -> bounded, mode-aware file collection
  -> per-file heuristic pass
  -> JS/TS AST and taint pass
  -> bounded module graph and cross-file analysis
  -> binary metadata inspection
  -> DSH manifest and path-containment validation
  -> dependency / SBOM / provenance / capability enrichment
  -> all-finding scoring and verdict
  -> redacted JSON / text / SARIF / HTML / SBOM output
```

If explicitly requested, the Phase B dynamic state machine runs after the
static verdict and records only its separate, redacted analysis layer. It uses
only the scanner-owned local container backend when an immutable image is
available; otherwise it stops at `unavailable`. It does not use a host-execution
fallback, public/private egress, a host workspace, an engine socket, or host
namespaces. Gateway/probe observation remains Phase C.

The scanner never follows target symlinks and applies lexical plus realpath
containment to manifest-controlled paths. Medium-sized files receive lightweight
analysis instead of being silently skipped; hard-skipped files retain minimum
metadata and make incomplete coverage visible.

## Benchmark and verification

The repository contains 32 labeled benchmark items across malicious, safe,
evasion, and hardening-edge groups. The current checked-in benchmark records:

| Level | Precision | Recall | F1 |
| --- | ---: | ---: | ---: |
| Rule | 0.953 | 1.000 | 0.976 |
| Finding location (±2 lines) | 0.917 | 1.000 | 0.957 |
| Source-to-sink flow | 1.000 | 1.000 | 1.000 |
| Hardening edge group | 1.000 | 1.000 | 1.000 |

These metrics describe the checked-in corpus, not all real-world plugins. The
The project also maintains a full automated test contract covering the engine,
CLI, plugin loading, module/cross-file analysis, supply-chain layers, dynamic
backend contracts, report contracts, and hardening behavior.

```sh
npm test
npm run benchmark
npm run verify:release
```

## Development

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm test              # automated test suite
npm run benchmark     # rule / finding / flow benchmark
npm run docs:rules    # regenerate docs/rules.md
npm run demo          # regenerate docs/example-report.json
npm run scan:self     # dogfood: scan this repository
npm run verify:release
```

Self-scanning can intentionally find strings such as `eval(` or `rm -rf` inside
the scanner's own rule definitions. This transparent pattern-matching limitation
is another reason findings require contextual review.

## Roadmap and contributing

Completed work includes scan-completeness contracts, three scan modes, safe package
quarantine, AST/taint analysis, stable fingerprints, SARIF, binary inspection,
module/dependency/capability graphs, cross-file analysis, SBOM formats, provenance,
package drift detection, and release verification.

Planned work focuses on broader language-aware semantic analysis, deeper lockfile
normalization, stronger interprocedural reachability, larger public corpora, and
stable integration contracts. See the [full roadmap](docs/roadmap.md).

Dynamic execution remains an explicit release-gated path. Phase B is
network-denied and unavailable until a scanner-owned immutable image is
compiled/deployed; Phase C gateway/probe work and any live-network behavior are
deferred until a separate security review.

Issues and pull requests that add test-backed detections, reduce false positives,
or improve documentation are welcome. Before contributing, read the
[contributing guide](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).
Report scanner vulnerabilities privately under the [security policy](SECURITY.md).

## License

[MIT](LICENSE) © dsh-sentinel contributors
