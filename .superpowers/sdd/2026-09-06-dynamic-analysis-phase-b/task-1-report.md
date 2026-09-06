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

## Review Round 2

### Findings addressed

1. **Private capability trust root**
   - Removed the exported/copyable Symbol branding and all controlled-root basename heuristics.
   - Added module-private `TRUSTED_STAGING_CAPABILITIES = new WeakSet()`.
   - `createStagingCapability({ root, snapshot })` validates bounded canonical fields, freezes the capability, registers that exact object in the private WeakSet, and returns it.
   - `isTrustedStagingCapability` accepts only object identity present in that WeakSet. A copied object, including one created with all own property descriptors, is rejected.

2. **No raw staging fallback**
   - `normalizeContainerPolicy` now requires the trusted capability and rejects any raw `stagingRoot` field with `raw-staging-root-not-allowed`.
   - `stagedRoot`, when supplied alongside a capability, is only a consistency check; the normalized mount source always comes from `capability.snapshot`.
   - Lexical root/snapshot checks remain only capability-field consistency checks. Realpath/symlink resolution is intentionally deferred to the Task 2 staging layer; no raw path is treated as safe by this task.

3. **Regression coverage**
   - Added assertions for malicious raw staging roots, symlink-shaped escape paths, complete capability descriptor copying, malformed capability root/snapshot fields, and structural path injection.
   - Added `Object.isFrozen(argv)` plus strict write and property-replacement attempts; both fail and the original argv remains unchanged.

### TDD evidence

- Added the Round 2 regression assertions before changing production code.
- The first focused run failed in exactly the two relevant ways: controlled `stagingRoot` fallback was accepted, and a capability cloned with `Object.getOwnPropertyDescriptors` was accepted.
- The argv freeze assertion already passed because the prior implementation froze the returned array; it remains in the regression contract.
- After the WeakSet-only implementation and raw fallback removal, container tests passed.

### Round 2 verification

- `node --test test/container-backend.test.js`: **9 passed, 0 failed**.
- `node --test test/dynamic-analysis.test.js`: **67 passed, 0 failed**.
- `node --test test/container-backend.test.js test/dynamic-analysis.test.js`: **76 passed, 0 failed**.
- `npm.cmd test`: **336 passed, 0 failed**.
- `git diff --check`: to be run immediately before the Round 2 commit.

### Round 2 risk

- The Task 1 capability checks cannot prove filesystem realpath safety; the capability creator validates only bounded canonical strings and lexical containment. Task 2 staging must create the capability only after descriptor-based traversal and symlink/hardlink containment checks.
- The ignored local `node_modules` installation remains an environment prerequisite for the plugin-load smoke test and is not part of the commit.

### Round 2 final tightening: raw `stagedRoot` is not an input contract

The review wording requires the capability to be the only staging input, not merely the source of the final mount after comparing a caller-supplied path. I therefore tightened the contract again:

- `normalizeContainerPolicy` rejects any supplied `stagedRoot` with `raw-staged-root-not-allowed`, even when a valid capability is also present.
- `normalizeContainerPolicy` and `buildEngineArgs` reject raw `stagingRoot`; the command builder no longer forwards either raw path into policy normalization.
- The normalized `stagedRoot` and emitted `--mount` source are derived only from the exact WeakSet-registered capability's `snapshot`.
- Regression coverage now includes raw host paths, symlink-shaped escape paths, comma/semicolon/equals/newline/socket-shaped paths, and a valid capability combined with a raw path. These are rejected before any raw path can be used as a mount source.

TDD evidence for this final tightening:

- Updated the regression assertions first and ran the focused container suite. It failed with the old implementation still accepting a raw `stagedRoot`; the first test edit also exposed a test-local undefined fixture reference, which was corrected before production changes were evaluated.
- Changed policy and command handling only after that failing run. The focused container suite then passed **9/9**.

Final verification for this report revision:

- `node --test test/container-backend.test.js`: **9 passed, 0 failed**.
- `node --test test/dynamic-analysis.test.js`: **67 passed, 0 failed**.
- `node --test test/container-backend.test.js test/dynamic-analysis.test.js`: **76 passed, 0 failed**.
- `npm.cmd test`: **336 passed, 0 failed**.
- `git diff --check`: pending final pre-commit run.

The capability API still does not claim realpath/symlink safety; Task 2 must create capabilities only after filesystem containment verification. No Docker/Podman engine was invoked.

### Final commit verification

- `git diff --check` before commit: passed with no whitespace errors; Git emitted only the existing LF-to-CRLF normalization warnings.
- Commit created and amended in this worktree only: `fix: require private staging capabilities`.
- Post-commit `git diff --check HEAD^ HEAD`: passed with no whitespace errors.
- Post-commit `git status --short --branch`: clean worktree on `codex/dynamic-analysis-phase-b`.
- No merge and no push were performed.

## Review Round 3

### Findings addressed

1. **Factory no longer registers caller-selected paths**
   - `createStagingCapability` is now a zero-argument factory. Any argument, including `{ root, snapshot }`, positional paths, `.ssh`, commas, or other raw path data, is rejected with the fixed `staging-capability-factory-arguments` code.
   - The factory validates the OS temporary directory, creates a unique `dsh-sentinel-staging-*` root, creates a unique `snapshot-*` child directory, freezes the capability, and registers only that exact object in the module-private WeakSet.
   - Task 2 can write a verified snapshot into the owned `capability.snapshot` workspace and use the same capability for policy normalization; there is no public raw-path registration entry point.

2. **Capability identity remains non-forgeable**
   - WeakSet identity remains the only trust decision. Plain objects, copied property descriptors, proxies, and forged fields are rejected.
   - The returned capability is frozen. The command argv remains frozen and rejects both index assignment and property replacement attempts without changing its contents.

3. **Raw path attributes are rejected by presence**
   - `normalizeContainerPolicy` rejects own `stagedRoot` and `stagingRoot` properties even when their values are `undefined`.
   - `buildEngineArgs` applies the same own-property rejection before policy normalization and never forwards raw paths.

4. **Sensitive-path regression coverage**
   - Tests verify that the public factory cannot register `.ssh` or arbitrary caller paths, forged capabilities cannot authorize a mount, and emitted argv contains only the factory-owned snapshot and no `.ssh` path.

### TDD evidence

- Added the zero-argument factory, raw-argument rejection, forged/proxy capability, sensitive-path, and own-undefined property assertions before the production changes.
- The first focused run failed as intended: **8 passed, 1 failed**. The failure was the old factory throwing `invalid-staging-root` for `createStagingCapability()` instead of creating an owned workspace.
- Implemented the factory and own-property checks only after that red run. The focused container suite then passed **9/9**.

### Round 3 verification

- `node --test test/container-backend.test.js`: **9 passed, 0 failed** after the production change.
- `node --test test/dynamic-analysis.test.js`: **67 passed, 0 failed**.
- `npm.cmd test`: **336 passed, 0 failed**.
- `git diff --check`: passed with no whitespace errors; Git emitted only LF-to-CRLF normalization warnings.
- No Docker or Podman engine was run; all command behavior remains runner-injected/test-only.

### Round 3 risk

- The factory now owns the staging directories, but Task 2 remains responsible for writing only verified snapshot content and for realpath/symlink/hardlink containment checks during staging.
- Factory-created temporary workspaces are intentionally represented by the frozen capability paths so Task 2 can use the owned workspace without reintroducing a raw-path registration API.
