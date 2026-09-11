# Task 6 report — documentation, Linux Phase B gate, and release evidence

Date: 2026-09-12
Worktree: `C:/Users/Administrator/Desktop/code/dsh-sentinel/.worktrees/dynamic-analysis-phase-b`
Branch: `codex/dynamic-analysis-phase-b`
Reviewed base: `3b8cb67`

## Delivered

- Added an English-first `README.md` Phase B section covering explicit opt-in,
  static preflight refusal, all dynamic statuses and strict exit behavior,
  Linux Docker/Podman prerequisites, scanner-owned immutable image behavior,
  network-denied runner flags, staging lifecycle, ownership, evidence redaction,
  cleanup uncertainty, limitations, and the Phase C boundary.
- Replaced the Chinese dynamic-analysis page with a secondary Phase B mirror and
  an explicit link back to the English primary document.
- Added Phase B threat-boundary, trust-ownership, package-export, staging,
  endpoint/executable-binding, evidence-redaction, and residual Phase C sections
  to `SECURITY.md` and `docs/architecture.md`.
- Added `.github/workflows/dynamic-smoke.yml`: Linux-only, manual opt-in,
  protected immutable image digest, clean `unavailable` skip when absent, no
  image pull/build, `--network=none`, private PID/IPC, read-only root, non-root,
  dropped capabilities, no-new-privileges, and no host workspace/socket mounts.
- Added hardening contract tests for English-first docs, Phase B opt-in and
  unavailable semantics, no host fallback, no public network, immutable image /
  no-pull, and Linux-only workflow gating.
- Refreshed `.final-test.txt` and `.final-bench.txt` from the current commands.

## TDD evidence

Initial focused RED command:

```text
C:\nvm4w\nodejs\node.exe --test test/hardening.test.js
```

Result before the implementation: 69 tests, 66 passed, 3 failed. The three
failures were the new Phase B documentation contract, security/architecture
contract, and missing dynamic smoke workflow contract.

Focused GREEN result after implementation: 69 tests, 69 passed, 0 failed.

## Verification results

The full suite was run offline so the repository's deliberate npm-registry and
OSV integration tests could not contact public network services. A temporary
local preload made only `curl.exe` probes fail with the same unavailable shape;
`SENTINEL_NPM_REGISTRY` was also pointed at `127.0.0.1:9`. The preload was not
part of the committed tree.

| Command | Result |
| --- | --- |
| `C:\nvm4w\nodejs\npm.cmd test` (offline guard) | exit 0; 407 total, 393 passed, 0 failed, 14 skipped, 0 todo. The skips were 10 Windows-inapplicable Linux descriptor-relative staging tests and 4 registry-dependent tests blocked by the offline guard. |
| `C:\nvm4w\nodejs\npm.cmd run benchmark` | exit 0; rule precision 0.953 / recall 1.000 / F1 0.976; finding precision 0.917 / recall 1.000 / F1 0.957; flow precision 1.000 / recall 1.000 / F1 1.000; hardening edge F1 1.000. |
| `C:\nvm4w\nodejs\npm.cmd run verify:release` (offline guard) | exit 0; included the same 407/393/0/14 test result, benchmark, and package dry-run. |
| `C:\nvm4w\nodejs\npm.cmd pack --dry-run` | exit 0; package `deepseek-harness-sentinel@0.4.4`, 54 files, 159.5 kB package size, 519.7 kB unpacked. |
| `C:\nvm4w\nodejs\npm.cmd audit --offline --ignore-scripts --no-fund` | exit 0; `found 0 vulnerabilities`. |
| `C:\nvm4w\nodejs\node.exe -e ... yaml parse ...` | exit 0; `dynamic-smoke.yml` parsed and contains the Linux `phase-b-smoke` job. |
| `node --check` on CLI, hardening test, resolver, command builder, and policy | exit 0 for all five files. |
| `git diff --check` | exit 0; Git emitted only the repository's LF/CRLF normalization warnings. |
| `node bin\sentinel.mjs test\fixtures\clean-plugin --dynamic --json` | exit 0; no-engine smoke reported `dynamicStatus=unavailable`, `dynamicComplete=False`. |

No Docker or Podman command was invoked locally. No public network was used by
the verification commands; the only network-shaped tests were forced into their
documented offline/unavailable paths.
