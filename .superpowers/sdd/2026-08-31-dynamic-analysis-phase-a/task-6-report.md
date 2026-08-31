# Task 6 Report: Phase A documentation and release-grade verification

**Date:** 2026-08-31

## Scope completed

- Kept `README.md` as the first and detailed English primary document; its language
  selector now links to the secondary `README.zh-CN.md`.
- Documented that Phase A dynamic analysis is experimental and opt-in, with a
  deliberately unavailable production resolver. It never executes plugin code,
  starts a container, invokes Docker/Podman, runs a production backend, or falls
  back to host execution.
- Documented all four controls: `--dynamic`, `--dynamic-backend`,
  `--dynamic-profile`, and `--dynamic-timeout`. The timeout default is 15000 ms
  and the enforced range is 1000–30000 ms.
- Recorded separate static and dynamic completeness, including the fact that
  requested unavailable/refused/incomplete deep analysis returns exit 3 only
  with `--fail-on-incomplete` or `--strict-exit-codes`.
- Added the Phase A state machine, injected fake-backend boundary, immutable
  limits, evidence redaction boundary, cleanup uncertainty behavior, and the
  deferred Phase B Docker/Podman independent-audit gate to architecture and
  security documentation.
- Refreshed `.final-test.txt` and `.final-bench.txt` with current command output.
  The new benchmark output is byte-identical to the existing checked-in evidence,
  so Git has no content diff for `.final-bench.txt`.

## Verification evidence

All npm invocations below used `C:\nvm4w\nodejs\npm.cmd`.

| Check | Result |
| --- | --- |
| Syntax checks for 8 requested dynamic/CLI/API modules | Passed (all `node --check` commands exited 0). |
| Focused dynamic tests | Passed: 69 tests; 0 failed, 0 skipped. |
| Full test suite | Passed: 324 tests; 0 failed, 0 skipped, 0 cancelled, 0 todo; 11.81 s. Fresh output: `.final-test.txt`. |
| Benchmark | Passed and met the recorded gate: rule precision/recall `0.953/1.000`, finding `0.917/1.000`, flow `1.000/1.000`; 32 labeled items. Fresh output: `.final-bench.txt`. |
| `npm run verify:release` | Passed; reran the full suite, benchmark, and package dry-run. |
| `npm pack --dry-run` | Passed; package contains both `README.md` and `README.zh-CN.md` (50 files). |
| `npm audit --offline` | Passed: `found 0 vulnerabilities`. |

## No-execution source check

Ran the required search across `engine/dynamic` and `engine/index.js` for process,
container, shell, and network invocation markers. It returned one match only:

```text
engine/dynamic/policy.js:11:const DYNAMIC_BACKENDS = Object.freeze(['auto', 'docker', 'podman'])
```

This is the inert, validated option enum. Inspection confirmed it declares no
execution path; it does not import or invoke process, network, Docker, or Podman
APIs. No other search hits were present.

## Self-review

- `git diff --check` completed with exit 0 (only repository line-ending warnings).
- Reviewed all newly documented guarantees against the production resolver,
  policy limits, CLI exit gating, and dynamic test contracts.
- Confirmed no unrelated source files were modified.

## Independent-security-review gate

No Sol audit was requested or performed. As directed, Sol capacity is unavailable
and the controller owns the final independent review. The independent security
audit remains an explicit release gate before any Phase B Docker/Podman execution
work. This task does not advance or authorize Phase B execution.

## Commit

This report is included in the `docs: document dynamic analysis phase a` commit.

## Fix round 1: documentation gate correction

**Date:** 2026-08-31

- Removed the legacy embedded Chinese document from `README.md`; the English
  README now ends after its English license and its selector links only to the
  separate secondary `README.zh-CN.md`.
- Updated the English verified automated-test claim from 212 to 324. The
  standalone Chinese README had no stale test-count claim.
- Content search found no remaining `# 中文说明` heading or stale 212 test-count
  claim. The only current count claim is `README.md:449` with 324, matching
  `.final-test.txt` (`ℹ tests 324`).
- Inspected `README.zh-CN.md`: it retains the Phase A opt-in/unavailable
  boundary, no plugin/container/production-backend execution, no host fallback,
  1000–30000 ms timeout bounds, separate completeness, strict exit-3 gating,
  and the Phase B independent-audit gate.
- Searched release-contract tests for README readers. No test reads either
  README; the only result is `package.json` package-file metadata. Per the task
  condition, the full npm test suite was not rerun for this documentation-only
  correction.
- Final `git diff --check` passed. The focused content inspection confirms the
  English selector, no embedded Chinese heading, 324-test claim, Chinese Phase A
  guarantees, and `.final-test.txt` results of 324 tests with 0 failures and 0
  skipped tests.
