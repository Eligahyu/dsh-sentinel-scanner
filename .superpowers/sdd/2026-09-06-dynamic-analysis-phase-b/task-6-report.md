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

## Fix round 1/5 — independent release/security review

The review identified three important workflow issues and two minor issues.
They were verified against the checked-in workflow and documentation before
implementation:

- removed `actions/checkout` and all `uses:` entries so the opt-in gate has no
  pre-gate public checkout egress;
- moved the smoke to the protected administrator-managed self-hosted Linux
  runner labels `self-hosted`, `linux`, `dsh-sentinel-phase-b` and environment
  `dynamic-analysis-protected`, with the digest secret scoped to the enabled job;
- added fixed `timeout-minutes: 2` and a fixed host `timeout ... 90s` around the
  engine run;
- added a local `image inspect` branch that skips with an explicit
  `unavailable` reason when the exact immutable image is not preloaded;
- bounded engine selection to the literal `docker|podman` allowlist with no
  remote endpoint input;
- corrected `SECURITY.md` and `docs/architecture.md` so the package `exports`
  map limits package-specifier imports while implementation files may ship
  internally and are not public import paths;
- replaced the workflow substring test with structural YAML assertions and exact
  runner-argument/forbidden-input assertions.

TDD RED for the review-fix contracts: the old workflow lacked the structural job
gate and the corrected export-map wording. TDD GREEN: the focused hardening suite
passed 69/69 after the fixes.

### Fix-round verification

All commands below were run locally without contacting a Docker/Podman daemon or
public network. The full suite and `verify:release` used the same temporary
offline `curl.exe` guard described above; that guard was removed before staging.

| Command | Result |
| --- | --- |
| `C:\nvm4w\nodejs\node.exe --test test/hardening.test.js` | exit 0; 69 passed, 0 failed. |
| `C:\nvm4w\nodejs\npm.cmd test` (offline guard) | exit 0; 407 total, 393 passed, 0 failed, 14 skipped, 0 todo. |
| `C:\nvm4w\nodejs\npm.cmd run benchmark` | exit 0; rule precision/recall/F1 `0.953/1.000/0.976`, finding `0.917/1.000/0.957`, flow `1.000/1.000/1.000`, hardening-edge F1 `1.000`. |
| `C:\nvm4w\nodejs\npm.cmd run verify:release` (offline guard) | exit 0; same 407/393/0/14 test result, benchmark, and package dry-run. |
| `C:\nvm4w\nodejs\npm.cmd pack --dry-run` | exit 0; 54 files, 159.9 kB package size, 520.6 kB unpacked. |
| `C:\nvm4w\nodejs\npm.cmd audit --offline --ignore-scripts --no-fund` | exit 0; `found 0 vulnerabilities`. |
| `node bin\sentinel.mjs test\fixtures\clean-plugin --dynamic --json` | exit 0; `dynamicStatus=unavailable`, `dynamicComplete=False`. |
| YAML parse of `.github/workflows/dynamic-smoke.yml` | exit 0; protected Linux job present. |
| JavaScript `--check` for CLI, hardening test, resolver, command builder, and policy | exit 0 for all five files. |
| `git diff --check` | exit 0; only Git LF/CRLF normalization warnings. |

## Fix round 2/5 — final release/security review

This round corrected the immutable-image predicate and closed the inherited
engine-selector/configuration boundary before the first engine command. The
workflow now evaluates the exact Bash regex
`[[ "$DYNAMIC_IMAGE_DIGEST" =~ ^[^[:space:]]+@sha256:[[:xdigit:]]{64}$ ]]`,
with positive and negative fixture coverage. It rejects non-empty
`DOCKER_HOST`, `DOCKER_CONTEXT`, `CONTAINER_HOST`, `CONTAINER_CONNECTION`,
`DOCKER_CONFIG`, `CONTAINERS_CONF`, `CONTAINERS_STORAGE_CONF`,
`PODMAN_CONNECTIONS_CONF`, and `XDG_CONFIG_HOME`, clears them, and fails closed
before image inspection. Both inspect and run use only the literal allowlisted
absolute engine paths, explicit local Docker/Podman endpoint flags, `/usr/bin/env
-i` with a minimal controlled environment, and `/` as the working directory.
The contract tests normalize the workflow structure and assert the exact inspect
and bounded run argument vectors, permissions, protected runner/environment,
opt-in/unavailable branches, no-action/no-checkout shape, and prohibited
privilege, mount, credential, namespace, network, pull/build, and remote-input
alternatives.

TDD RED for this round: after the review-contract expansion, the focused suite
reported 70 passed and 1 failed because the negative credential assertion was
too broad and rejected the required controlled `HOME=/nonexistent` setting.
The assertion was narrowed to credential forwarding while retaining the exact
controlled environment contract. Focused GREEN then passed 71/71.

### Fix-round verification

All commands below were run against the current worktree without contacting a
Docker/Podman daemon or public network. Full-suite and release verification
used a temporary Node preload that forced `curl.exe` probes to the unavailable
shape and set `SENTINEL_NPM_REGISTRY` to `127.0.0.1:9`; the preload was deleted
before staging.

| Command | Result |
| --- | --- |
| `C:\nvm4w\nodejs\node.exe --test test/hardening.test.js` | exit 0; 71 total, 71 passed, 0 failed, 0 skipped. |
| `C:\nvm4w\nodejs\npm.cmd test` (offline guard) | exit 0; 409 total, 395 passed, 0 failed, 14 skipped, 0 todo. |
| `C:\nvm4w\nodejs\npm.cmd run benchmark` | exit 0; rule precision/recall/F1 `0.953/1.000/0.976`, finding `0.917/1.000/0.957`, flow `1.000/1.000/1.000`, hardening-edge F1 `1.000`. |
| `C:\nvm4w\nodejs\npm.cmd run verify:release` (offline guard) | exit 0; same 409/395/0/14 test result, benchmark, and package dry-run. |
| `C:\nvm4w\nodejs\npm.cmd pack --dry-run` | exit 0; package `deepseek-harness-sentinel@0.4.4`, 54 files, 160.6 kB package size, 522.6 kB unpacked. |
| `C:\nvm4w\nodejs\npm.cmd audit --offline --ignore-scripts --no-fund` | exit 0; `found 0 vulnerabilities`. |
| `C:\nvm4w\nodejs\node.exe bin\sentinel.mjs test\fixtures\clean-plugin --dynamic --json` | exit 0; no-engine smoke reported `dynamicStatus=unavailable`, `dynamicComplete=false`, reason `trusted-image-unavailable`. |
| YAML parse of `.github/workflows/dynamic-smoke.yml` | exit 0; protected Linux `phase-b-smoke` job present. |
| JavaScript `--check` for CLI, hardening test, resolver, command builder, and policy | exit 0 for all five files. |
| `git diff --check` | exit 0; only Git LF/CRLF normalization warnings. |

No Phase C code or static scanner behavior was changed. Task 3/4 contracts and
the English-first documentation boundary remain intact.

## Fix round 3/5 — final release/security review

This round closed case-variant inherited environment selectors, aligned the
workflow digest check with the runtime `REQUIRED_IMAGE_DIGEST` policy, and added
a bounded image-inspect timeout. The smoke now enumerates exported environment
names with `compgen -e`, canonicalizes each name with Bash uppercase expansion,
rejects non-empty casing variants of all Docker/Podman selector and config
names, and unsets every discovered casing variant before the existing exact
unset list and later `env -i` defense. Lowercase and mixed-case regressions
model the refusal path and assert that no engine command is reached.

The workflow digest predicate is now the Bash-ERE equivalent of the runtime
policy `^[a-z0-9](?:[a-z0-9._/-]{0,254})@sha256:[a-f0-9]{64}$`: the image name
prefix is lowercase, starts with an alphanumeric, is at most 255 characters,
and the digest is exactly 64 lowercase hexadecimal characters. Positive and
negative coverage includes uppercase names, uppercase digests, invalid first
characters, overlong prefixes, wrong digest lengths, and non-hex characters.
Image inspection now runs through trusted `/usr/bin/timeout` with fixed
`--signal=TERM --kill-after=5s 15s` bounds; the existing fixed 90-second run
timeout and two-minute job timeout remain unchanged.

TDD RED for this round: the first focused run after adding the new contracts
reported 68 passed and 3 failed against the old workflow (broad digest rule,
exact-case-only environment sanitization, and missing inspect timeout). After
implementation and correcting two test-shape assumptions to match the runtime
regex terminator and the canonicalized loop form, focused GREEN passed 71/71.

### Fix-round verification

All commands below were run against the current worktree without contacting a
Docker/Podman daemon or public network. Full-suite and release verification
used a temporary Node preload that forced `curl.exe` probes to the unavailable
shape and set `SENTINEL_NPM_REGISTRY` to `127.0.0.1:9`; the preload and scratch
release output were deleted before staging.

| Command | Result |
| --- | --- |
| `C:\nvm4w\nodejs\node.exe --test test\hardening.test.js` | exit 0; 71 total, 71 passed, 0 failed, 0 skipped. |
| `C:\nvm4w\nodejs\npm.cmd test` (offline guard) | exit 0; 409 total, 395 passed, 0 failed, 14 skipped, 0 todo. |
| `C:\nvm4w\nodejs\npm.cmd run benchmark` | exit 0; rule precision/recall/F1 `0.953/1.000/0.976`, finding `0.917/1.000/0.957`, flow `1.000/1.000/1.000`, hardening-edge F1 `1.000`. |
| `C:\nvm4w\nodejs\npm.cmd run verify:release` (offline guard) | exit 0; same 409/395/0/14 test result, benchmark, and package dry-run. |
| `C:\nvm4w\nodejs\npm.cmd pack --dry-run` | exit 0; package `deepseek-harness-sentinel@0.4.4`, 54 files, 160.9 kB package size, 523.5 kB unpacked. |
| `C:\nvm4w\nodejs\npm.cmd audit --offline --ignore-scripts --no-fund` | exit 0; `found 0 vulnerabilities`. |
| `C:\nvm4w\nodejs\node.exe bin\sentinel.mjs test\fixtures\clean-plugin --dynamic --json` | exit 0; no-engine smoke reported `dynamicStatus=unavailable`, `dynamicComplete=false`, reason `trusted-image-unavailable`. |
| YAML parse of `.github/workflows/dynamic-smoke.yml` | exit 0; protected Linux `phase-b-smoke` job present. |
| JavaScript `--check` for CLI, hardening test, resolver, command builder, and policy | exit 0 for all five files. |
| `git diff --check` | exit 0; only Git LF/CRLF normalization warnings. |

No Phase C code or static scanner behavior was changed. Task 3/4 contracts,
protected runner controls, English-first documentation, and the no-public-
network boundary remain intact.
