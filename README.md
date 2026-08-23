<div align="center">

# 🛡️ dsh-sentinel

[![Awesome DSH Plugin](https://awesome-dsh-plugin.com/badge.svg)](https://awesome-dsh-plugin.com)

**Read-only security, supply-chain, and health scanner for DeepSeek Harness plugins**

Heuristic rules, AST/taint analysis, package quarantine, dependency intelligence,
SBOM export, SARIF, and CI policy enforcement—without executing scanned code.

`Node.js ^22.18.0 or >=24.11.0 · Static analysis only · MIT`

[English](#english) · [中文](#中文说明) · [Rules](docs/rules.md) ·
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

## Capabilities

| Area | What it does |
| --- | --- |
| Heuristic rules | 51 rules across execution, credentials, exfiltration, obfuscation, install scripts, filesystem, network, manifests, Agent Tools, taint, supply chain, binaries, and persistence. |
| Agent Tool analysis | Traces `defineTool` inputs such as `args.*` into shell, filesystem, network, and dynamic-code sinks. Handles aliases, computed properties, optional chaining, variable propagation, and bounded cross-function flows. |
| Module and cross-file analysis | Builds a bounded JS/TS module graph, resolves common relative imports—including TypeScript `.js` specifiers that map to `.ts` sources—and supports bounded cross-file taint analysis. TypeScript parser limits are reported as a capability boundary instead of falsely failing every TS scan. |
| Language-aware coverage | JS-family files receive semantic analysis. TypeScript is conservatively degraded where syntax exceeds the parser boundary. Python and PowerShell files are not incorrectly fed into the JS parser and still receive applicable heuristic scanning. |
| DSH manifest validation | Audits `dsh.bundle`, `cordis.patch.yml`, package entry contracts, and lexical/realpath/symlink containment. Escaping paths trigger `SEN-MAN-009`. |
| Scan modes | `source` skips generated build trees by default; `package` includes distributable output such as `dist` and `build`; `profile` discovers and audits installed DSH plugins. |
| Pre-install quarantine | Safely extracts npm tarballs while blocking traversal, absolute paths, drive paths, symlink/hardlink entries, and tar bombs. Verifies sha512 integrity and cleans up all artifacts. |
| Supply-chain analysis | Inspects lifecycle scripts, lockfiles, normalized dependency graphs, package metadata, optional OSV advisories, optional provenance, and source-versus-package drift. |
| Native artifacts | Audits `.wasm`, `.exe`, `.dll`, `.so`, `.node`, and related files using magic bytes, size, SHA-256, entropy, and printable strings. Binaries are never executed. |
| Professional report layers | Stable report schema v2 with module graph, dependency graph, capability graph, SBOM, provenance, attack chains, coverage, and failure metadata. |
| Output and CI | Text, JSON, SARIF 2.1.0, standalone HTML, CycloneDX, and SPDX output; stable fingerprints, baselines, threshold exits, and incomplete-scan enforcement. |
| Privacy | Automatic secret redaction, optional path anonymization with `--redact-paths`, and no hidden ignore/skip behavior. |

### Core analysis versus auxiliary analysis

Scan completeness distinguishes security-critical coverage from optional enrichment:

- failures in core coverage, such as module or cross-file analysis failures, can
  set `scanComplete=false`;
- dependency graph, SBOM, provenance, and capability-graph failures are preserved
  as warnings and degraded output rather than falsely claiming source files were
  not scanned;
- unsupported or complex lockfile formats are reported instead of producing
  guessed dependency data.

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
      - uses: actions/checkout@v4

      - name: Scan plugin
        uses: Eligahyu/dsh-sentinel-scanner@v0.4
        with:
          path: .
          mode: source
          fail-on: high
          fail-on-incomplete: true

      - name: Upload SARIF
        if: always() && hashFiles('sentinel.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
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
| `3` | Scan incomplete when `--fail-on-incomplete` is enabled. |

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
project also maintains 200 automated tests covering the engine, CLI, plugin
loading, module/cross-file analysis, supply-chain layers, report contracts, and
hardening behavior.

```sh
npm test
npm run benchmark
npm run verify:release
```

## Development

```sh
npm install
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

Issues and pull requests that add test-backed detections, reduce false positives,
or improve documentation are welcome.

## License

[MIT](LICENSE) © dsh-sentinel contributors

---

# 中文说明

## dsh-sentinel 是什么？

**dsh-sentinel** 是面向 DeepSeek Harness（DSH）插件的只读安全、供应链与健康扫描器。
它可以在安装或信任第三方插件之前，对插件源码、npm 发布包、DSH profile 和 CI 仓库进行
静态审计，而且**绝不执行被扫描代码**。

扫描器检查命令执行、动态代码、凭据访问、数据外传、混淆、安装脚本、持久化、原生
二进制、manifest 路径逃逸、源码与发布包漂移等风险。引擎结合 51 条启发式规则、AST
污点分析、有界模块图、跨文件分析和供应链元数据，输出：

- 0–100 风险分；
- `safe / review / risky / dangerous` 四级裁决；
- 每条发现的证据、置信度和修复建议；
- 扫描完整性、跳过原因和覆盖范围；
- JSON、SARIF、HTML、CycloneDX 或 SPDX 报告。

项目提供三种使用形态：

- DSH Agent 工具：`sentinel_scan`、`sentinel_scan_profile`、
  `sentinel_audit_package`；
- 独立 CLI：npm 包名 `deepseek-harness-sentinel`，命令名 `dsh-sentinel`；
- 可上传 SARIF 的 GitHub Action，以及可供程序集成的 JavaScript API。

> **免责声明：**启发式静态扫描不等于安全证明。命中表示“需要人工复核”，不代表插件
> 一定恶意；没有命中也不代表插件绝对安全。

## 为什么需要它？

DSH 插件可能拥有加载它的用户或 Agent 所具备的文件、网络、凭据和进程权限。一个很短的
安装脚本、隐藏的下载执行链、未经约束的工具参数，或者逃逸到仓库外部的 manifest 路径，
都可能演变成供应链事故。

- **插件使用者：**在安装、启用第三方插件前先做隔离审计；
- **插件作者和维护者：**在发布前发现高风险行为、打包漂移、扫描不完整和清单缺陷。

## 安全红线

1. **绝不执行被扫描代码：**不会 `require`、`import`、`eval` 或启动目标代码。
2. **安装前审计不运行 npm install：**只下载 tarball、校验、隔离解包、静态扫描和清理。
3. **默认不上传源码：**OSV 查询默认关闭；启用后只提交包名和版本。
4. **Secret 永久脱敏：**报告保留指纹和必要证据，不暴露原始密钥。
5. **跳过行为全部可见：**文件上限、大文件、ignore、解析能力边界和策略跳过都会进入报告。
6. **报告层不是检测引擎：**SARIF、HTML、GitHub Action 和 SBOM 负责交换、展示或自动化，
   真正的检测能力来自 engine。

## 核心能力

| 能力 | 说明 |
| --- | --- |
| 启发式规则 | 51 条规则，覆盖执行、凭据、外传、混淆、安装脚本、文件系统、网络、manifest、Agent Tool、污点、供应链、二进制和持久化。 |
| Agent Tool 语义分析 | 跟踪 `defineTool` 中 `args.*` 到 shell、文件、网络和动态代码 sink，支持别名、计算属性、optional chaining、变量传播和有界跨函数流。 |
| 模块图与跨文件分析 | 构建有界 JS/TS 模块图，支持常见相对导入和 TypeScript 项目的 `.js -> .ts` 回退，并执行有界跨文件污点分析。 |
| 语言能力边界 | JS 系列文件执行语义分析；超出当前 parser 能力的 TypeScript 会降级并记录，不会因 `.ts/.tsx/.d.ts` 的存在就全部判扫描不完整；Python、PowerShell 不会错误送入 JS parser。 |
| DSH 清单检查 | 检查 `dsh.bundle`、`cordis.patch.yml`、入口契约，以及词法、realpath、symlink 三层路径 containment；路径逃逸触发 `SEN-MAN-009`。 |
| 三种扫描模式 | `source` 默认跳过生成目录；`package` 扫描 `dist/build` 等发布产物；`profile` 发现并审计第三方 DSH 插件。 |
| 安装前隔离审计 | 安全解包 tarball，阻止 traversal、绝对路径、盘符、symlink/hardlink 和 tar bomb；校验 sha512，并清理全部临时文件。 |
| 供应链能力 | 生命周期脚本、lockfile、标准化依赖图、包元数据、可选 OSV、可选 provenance、源码与 npm 发布包漂移。 |
| 原生二进制 | 对 `.wasm/.exe/.dll/.so/.node` 等提取 magic、大小、SHA-256、熵和 printable strings；只当数据分析。 |
| 专业报告层 | 稳定 schema v2，包含模块图、依赖图、能力图、SBOM、provenance、攻击链、覆盖率和失败信息。 |
| CI 与输出 | text、JSON、SARIF 2.1.0、单文件 HTML、CycloneDX、SPDX；支持 fingerprint、baseline、风险阈值和 incomplete gate。 |

### 核心层与辅助层

- 核心模块图或跨文件分析真正失败时，可以设置 `scanComplete=false`；
- 依赖图、SBOM、provenance、能力图属于辅助层，失败时保留明确警告并降级输出，不会错误
  声称所有源码都没有扫描；
- 对暂不支持或结构复杂的 lockfile，会明确报告 unsupported/incomplete，不会猜测数据。

## 安装与快速开始

### 独立 CLI

```sh
# 无需全局安装，直接扫描
npx deepseek-harness-sentinel ./path/to/plugin

# 或安装为开发依赖；安装后的命令名是 dsh-sentinel
npm install --save-dev deepseek-harness-sentinel
npx dsh-sentinel ./path/to/plugin
```

常见用法：

```sh
# 输出 JSON
npx deepseek-harness-sentinel ./plugin --json --out sentinel.json

# 扫描发布产物并输出 SARIF
npx deepseek-harness-sentinel ./plugin \
  --mode package \
  --format sarif \
  --out sentinel.sarif

# CI 中遇到 high/critical 或扫描不完整时失败
npx deepseek-harness-sentinel ./plugin \
  --fail-on high \
  --fail-on-incomplete \
  --strict-exit-codes

# 安装前审计，不执行生命周期脚本
npx deepseek-harness-sentinel audit-install some-plugin@1.2.3

# 比较源码与 npm 发布包
npx deepseek-harness-sentinel diff ./plugin some-plugin@1.2.3

# 查看规则目录
npx deepseek-harness-sentinel --rules
```

### 安装为 DSH 插件

```sh
# 本地目录
dsh plugin --profile web add ./dsh-sentinel

# GitHub 仓库
dsh plugin --profile web add github:Eligahyu/dsh-sentinel-scanner

# npm 包
dsh plugin --profile web add deepseek-harness-sentinel

dsh --profile web
```

进入 DSH 后可以直接说：

```text
用 sentinel_scan 检查 ~/Downloads/some-plugin。
用 sentinel_scan_profile 审计 web profile 中的全部第三方插件。
用 sentinel_audit_package 在安装前审计 some-plugin@1.2.3。
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
      - uses: actions/checkout@v4

      - name: Scan plugin
        uses: Eligahyu/dsh-sentinel-scanner@v0.4
        with:
          path: .
          mode: source
          fail-on: high
          fail-on-incomplete: true

      - name: Upload SARIF
        if: always() && hashFiles('sentinel.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: sentinel.sarif
```

Action 只会在 `${{ github.action_path }}` 下安装扫描器自己的依赖，并关闭 lifecycle scripts；
不会在被扫描仓库中执行 `npm install` 或 `npm ci`。详见
[GitHub Action 集成文档](docs/integration-github-action.md)。

## CLI 参数与退出码

| 参数 | 作用 |
| --- | --- |
| `--mode source\|package\|profile` | 选择源码、发布包或 profile 模式。 |
| `--format text\|json\|sarif\|html\|cyclonedx\|spdx` | 选择输出格式。 |
| `--out <file>` | 完整报告写入文件，stdout 保留摘要。 |
| `--baseline <file>` | 使用稳定 fingerprint 对比旧报告。 |
| `--fail-on <severity>` | 命中指定或更高严重度时退出 1。 |
| `--fail-on-incomplete` | 扫描不完整时退出 3。 |
| `--strict-exit-codes` | 区分策略失败、运行错误和扫描不完整。 |
| `--max-files / --max-plugins / --max-bytes` | 设置资源上限。 |
| `--config <file>` | 读取 `sentinel.config.json`，CLI 参数优先。 |
| `--redact-paths` | 匿名化绝对路径，便于分享报告。 |
| `--advisories` | 查询 OSV，仅发送包名和版本，默认关闭。 |
| `--provenance` | 读取 npm provenance attestations，默认关闭。 |

退出码：`0` 表示未超过策略阈值，`1` 表示风险/策略阈值被触发，`2` 表示用法或运行错误，
`3` 表示启用 `--fail-on-incomplete` 后发现扫描不完整。

## 评分与裁决

| 严重度 | 权重 | 常见证据 |
| --- | ---: | --- |
| `critical` | 50 | 下载执行、读取私密凭据、强外传证据、破坏用户目录、tar 路径逃逸。 |
| `high` | 20 | 动态执行、硬编码密钥、环境凭据访问、入口契约缺失、二进制可疑字符串。 |
| `medium` | 8 | 需要复核的 shell、网络、生命周期脚本、高熵二进制和持久化行为。 |
| `low` | 3 | 可疑编码组合、硬编码公网 IP、包健康元数据问题。 |
| `info` | 0 | 原生二进制或 WASM 存在等提示。 |

```text
0–19   safe
20–49  review
50–79  risky
80–100 dangerous
```

- 分数基于**全部有效命中**，`maxFindings` 只限制报告返回条数；
- 优先级缓冲保证 critical/high 不会被大量 low 命中淹没；
- minified/bundle 只作为 evidence，不自动降低严重度；
- 测试目录命中默认降一级计分，但被运行入口可达时不降权；
- 语义规则与泛化规则重叠时保留证据，但抑制重复计分。

## 扫描完整性

报告会给出 `scanComplete`、`incompleteReasons`、发现/分析文件数、大文件策略、二进制、
parser 能力边界、ignore 和 hard skip 信息。

文件或插件超过上限、文件超过 hard size、二进制采样受限、核心模块/跨文件分析失败等可能
让扫描不完整。超出当前 parser 能力的 TypeScript 会显式降级并记录；正常存在
`.ts/.tsx/.d.ts` 文件本身不会自动让扫描失败。

## 安装前隔离审计

```text
npm metadata
  -> 下载 tarball
  -> sha512 integrity 校验
  -> quarantine 隔离目录
  -> 安全解包
  -> package 模式静态扫描
  -> 成功或失败路径统一清理
  -> ALLOW / REVIEW / BLOCK-RECOMMENDED 建议
```

解包器拒绝 `../`、绝对路径、盘符、symlink/hardlink、过深目录、超大条目、超大解包总量和
过多 archive entries，全程不调用 npm lifecycle scripts。详见
[DSH 安装前审计集成设计](docs/integration-dsh-preinstall.md)。

## 报告和集成

- **JSON：**schema v2 标准报告，适合程序消费、存储和自定义策略；
- **SARIF 2.1.0：**相对路径与稳定 fingerprint，可上传 GitHub Code Scanning；
- **HTML：**便携的单文件人工审阅报告；
- **CycloneDX / SPDX：**基于标准化依赖图输出 SBOM；
- **Baseline：**按稳定 fingerprint 识别新增风险；
- **源码/发布包 diff：**发现仓库与 npm artifact 漂移（`SEN-SUPPLY-003`）。

参见[示例 JSON 报告](docs/example-report.json)和[架构与报告契约](docs/architecture.md)。

## 引擎工作流程

```text
目标
  -> 有界、模式感知的文件收集
  -> 逐文件启发式规则
  -> JS/TS AST 与污点分析
  -> 有界模块图和跨文件分析
  -> 原生二进制 metadata 审计
  -> DSH manifest 与路径 containment
  -> 依赖图 / SBOM / provenance / 能力图增强
  -> 基于全部命中的计分和裁决
  -> 脱敏 JSON / text / SARIF / HTML / SBOM 输出
```

扫描器不会跟随目标 symlink；manifest 路径同时执行词法和 realpath containment。中等大小
文件走 large-file-lite；hard-skipped 文件保留最低限度 metadata，并明确影响扫描完整性。

## Benchmark 与验证

仓库包含 32 项带标注语料，覆盖 malicious、safe、evasion 和 hardening edge 四组：

| 层级 | Precision | Recall | F1 |
| --- | ---: | ---: | ---: |
| Rule | 0.953 | 1.000 | 0.976 |
| Finding 位置（±2 行） | 0.917 | 1.000 | 0.957 |
| Source-to-sink flow | 1.000 | 1.000 | 1.000 |
| Hardening edge 分组 | 1.000 | 1.000 | 1.000 |

这些数字只描述仓库内标注语料，不代表所有真实插件。项目目前有 200 项自动化测试，覆盖
引擎、CLI、插件加载、模块/跨文件分析、供应链层、报告契约和发布加固。

```sh
npm test
npm run benchmark
npm run verify:release
```

## 开发、路线图与贡献

```sh
npm install
npm test              # 自动化测试
npm run benchmark     # rule / finding / flow 三级基准
npm run docs:rules    # 重新生成 docs/rules.md
npm run demo          # 重新生成 docs/example-report.json
npm run scan:self     # 扫描器扫描自己
npm run verify:release
```

自扫描可能命中规则定义中的 `eval(`、`rm -rf` 等字面量，这是模式匹配公开、诚实的能力
边界，也说明 finding 必须结合上下文人工判断。

已完成能力包括扫描完整性契约、三种模式、安全 tarball 隔离、AST/taint、稳定 fingerprint、
SARIF、二进制检查、模块/依赖/能力图、跨文件分析、SBOM、provenance、发布包漂移检测与
release verification。后续重点是更广的语言语义、更深入的 lockfile 标准化、跨过程
reachability、更大的公开语料和稳定集成契约。详见[完整路线图](docs/roadmap.md)。

欢迎通过 Issue 或 Pull Request 增加有测试覆盖的规则、降低误报或完善文档。

## License

[MIT](LICENSE) © dsh-sentinel contributors
