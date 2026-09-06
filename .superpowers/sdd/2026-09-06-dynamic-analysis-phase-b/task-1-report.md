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
