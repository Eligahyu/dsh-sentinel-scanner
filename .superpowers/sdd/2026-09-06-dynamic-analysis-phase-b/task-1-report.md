# Phase B Task 1 Report

## Status

Implemented the immutable container backend policy and hardened Docker/Podman command contract in the requested worktree:

`C:\Users\Administrator\Desktop\code\dsh-sentinel\.worktrees\dynamic-analysis-phase-b`

No Docker or Podman engine was executed. No shell command was introduced into production code. The command builder returns an argv array only.

## Scope

Changed only the Task 1 files from the brief:

- `engine/dynamic/container-policy.js`
- `engine/dynamic/container-command.js`
- `engine/dynamic/policy.js`
- `test/container-backend.test.js`

## Implementation

- Added frozen Phase B limits for timeout, memory, process count, and output bytes.
- Added frozen Docker/Podman allowlist and frozen digest-only image format.
- Added `normalizeContainerPolicy(input)` with bounded scalar normalization and immutable policy output.
- Re-exported the container policy contract from the existing dynamic policy module without changing the Phase A normalized option shape.
- Added `validateEngineName(value)` for the Docker/Podman allowlist.
- Added `buildEngineArgs(...)` with a fixed `run` action and string-only argv output.
- The generated argv enforces network denial, private PID/IPC namespaces, read-only root, non-root execution, dropped capabilities, no-new-privileges, bounded resources, a run label, and a read-only staged snapshot mount.
- The builder rejects injected flags/arguments, mutable image references, host networking, privileged mode, host PID/IPC, custom mounts, engine socket paths, invalid labels, and unsupported engines/actions.

## TDD evidence

1. Wrote `test/container-backend.test.js` before production implementation.
2. Ran `node --test test/container-backend.test.js` and observed the expected `ERR_MODULE_NOT_FOUND` for the missing policy module.
3. Implemented the minimal policy and argv builder.
4. Added the frozen digest-format assertion; it failed because the RegExp export was not frozen.
5. Froze the digest-format export and reran the focused suite successfully.

## Verification

- `node --test test/container-backend.test.js test/dynamic-analysis.test.js`: **72 passed, 0 failed**.
- `npm.cmd test`: **326 passed, 1 failed**.
  - The sole failure is the pre-existing plugin-load test in a temporary packed install: the temporary package cannot resolve the `yaml` dependency.
  - The failure is outside the changed files and does not invoke Docker/Podman.
- `git diff --check`: passed.

The bare `npm` command resolves first to an empty `C:\Windows\System32\npm` shim in this environment, so the real npm entry point was verified with `npm.cmd test`.

## Risks and follow-up

- The full repository test command remains blocked by the environment's temporary-package `yaml` resolution failure; dependency installation was not changed because it is outside Task 1 scope.
- This task defines the policy and command contract only. It does not add engine capability probing, staging, runner lifecycle, or `execFile` invocation; those belong to later Phase B tasks.
- The command contract intentionally supports only the fixed `run` action. Later backend work must extend it with additional explicitly allowlisted actions rather than accepting arbitrary CLI arguments.

## Commit

Final commit: `feat: define hardened container command contracts` (the report is force-added because the repository ignores `.superpowers/sdd` artifacts).

## Review Round 1

### Findings addressed

1. **Staged snapshot containment and mount injection**
   - Added a branded, frozen `createStagingCapability({ root, snapshot })` capability.
   - Policy normalization now requires either that trusted capability or an explicitly controlled staging root whose snapshot is a canonical descendant.
   - Controlled staging roots use a bounded `dsh-...staging...` name; snapshot directories use bounded `snapshot-*` or `run-*` names.
   - Paths are bounded to 512 characters, require an absolute canonical form, reject `..`, commas, semicolons, equals, pipes, quotes, newlines, NULs, and socket paths, and are checked for root containment before becoming the bind-mount source.
   - The command builder passes only the validated path into one fixed mount argument, so a path cannot add mount fields.

2. **Contradictory network policy**
   - `network` and `networkMode` are compared when both are defined. Mismatched values now fail with the fixed `conflicting-network-policy` code; no nullish-coalescing precedence can hide a host-network intent.

3. **Bounded inputs and fixed errors**
   - Image references are bounded and digest-only; labels remain bounded to the fixed safe label grammar; staged paths have bounded length and characters.
   - Engine and action validation use finite allowlists and fixed error codes. Invalid values are never interpolated with `String(value)`, so hostile custom `toString` methods are not invoked.
   - Policy and command errors now expose fixed `error.code` values without attacker-controlled text.

4. **Regression coverage**
   - Added tests for real-looking `.ssh` and worktree paths, path traversal, comma/semicolon/equals/newline mount injection, socket paths, missing/forged capabilities, conflicting network fields, oversized values, and hostile enum values.

5. **Default test contract**
   - Added `test/container-backend.test.js` to the `package.json` `npm test` script.

### TDD and investigation evidence

- Added the review regression tests before changing production code.
- The first focused run failed at module loading because `createStagingCapability` did not exist.
- After the initial implementation, focused tests exposed the intended setup/contract issues: missing capability in the fixed-limit fixture, old text-based assertions, and `undefined` network fields being treated as explicit values. Those were corrected with fixed-code assertions and defined-value network detection.
- The corrected focused suite passed 9/9.

### Dynamic-suite discrepancy investigation

- Ran `node --test test/dynamic-analysis.test.js` three consecutive times: each run was **67 passed, 0 failed**.
- Ran the combined container and dynamic command: **76 passed, 0 failed** (9 container + 67 dynamic).
- The previously reported 69/72 result was not reproducible in this worktree. The prior 72-test composition was 5 container tests plus 67 dynamic tests; this round adds 4 regression tests, making the current combined total 76. No dynamic test was relaxed and no timeout was increased.

### Full npm test and yaml diagnosis

- Before installing local dependencies, the default contract ran **336 tests: 335 passed, 1 failed**. The only failure was `test/plugin-load.test.js`, where the temporary copied package could not resolve `yaml`.
- Read-only checks showed no `node_modules` in this worktree; `yaml` resolved only through the parent main-worktree installation, while `npm.cmd ls yaml --depth=0` was empty for this worktree.
- Installed only the already-declared dependencies with:

  `npm.cmd install --ignore-scripts --no-audit --no-fund`

  This created ignored local `node_modules` and did not change `package.json` or `package-lock.json`.
- Reran the complete command through the real Windows npm entry point, `npm.cmd test`: **336 passed, 0 failed**. This confirms the earlier yaml failure was an environment/setup issue caused by the missing current-worktree `node_modules`, not a package-contract regression.

### Round 1 verification

- `node --test test/container-backend.test.js`: **9 passed, 0 failed**.
- `node --test test/dynamic-analysis.test.js`: **67 passed, 0 failed**.
- `node --test test/container-backend.test.js test/dynamic-analysis.test.js`: **76 passed, 0 failed**.
- `npm.cmd test`: **336 passed, 0 failed** after installing declared local dependencies.
- `git diff --check`: pending final pre-commit run.

### Round 1 risk

- The capability brand is intentionally private to the policy module; later staging code must use `createStagingCapability` or the explicit controlled-root contract rather than passing raw host paths.
- The full-suite success depends on installing declared dependencies in the worktree; `node_modules` is ignored and was not committed.
