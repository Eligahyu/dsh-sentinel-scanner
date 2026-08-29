# Contributing to dsh-sentinel

Thank you for helping improve dsh-sentinel. Security scanners need reproducible reports, conservative fixes, and tests that demonstrate both detection and false-positive behavior.

## Development setup

Use Node.js `^22.18.0` or `>=24.11.0`, then install dependencies without running lifecycle scripts:

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm test
```

Run the release checks before opening a pull request:

```bash
npm run verify:release
npm run benchmark
node bin/sentinel.mjs . --format sarif --out .tmp/self.sarif
```

## Pull requests

- Keep each change focused and explain its security impact.
- Add regression tests before fixing a bug. Include a safe negative case for detection rules whenever practical.
- Do not execute, import, or install code from a scanned fixture.
- Update English documentation first; keep Chinese documentation synchronized when behavior changes.
- Avoid committing secrets, generated packages, local reports, or unredacted real-world samples.
- Confirm that ignored, skipped, truncated, or degraded analysis remains visible in scan coverage.

## Reporting findings

Use the false-positive issue form for detection-quality reports and include a minimal, sanitized reproducer. Do not open a public issue for a vulnerability in dsh-sentinel itself; follow [SECURITY.md](SECURITY.md) and use GitHub Private Vulnerability Reporting.

## 中文说明

请使用受支持的 Node.js 版本，通过 `npm ci --ignore-scripts` 安装依赖，并在提交前运行完整测试、发布校验、基准测试和仓库自扫描。规则修复应同时包含“应命中”和“不得误报”的回归测试。扫描器自身漏洞请按 `SECURITY.md` 私密报告，不要在公开 Issue 中披露。
