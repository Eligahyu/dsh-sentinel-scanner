# Phase B Task 4 Report — Bounded Runner Stages and Cleanup

## Scope

Implemented the bounded Phase B stage protocol on reviewed HEAD `b41b4e9`.
The change remains behind the existing injected-only Phase-A resolver boundary;
Task 5/6 integration was not touched and no Docker/Podman daemon was contacted.

## TDD evidence

### RED

Tests were written before the production implementation and executed with:

```text
node --test test/container-backend.test.js test/dynamic-analysis.test.js
```

Observed result: `127` tests, `112` passed, `5` failed, `10` skipped, `0`
cancelled. The five expected failures were the not-yet-implemented fresh
allowlisted stages, strict stage schema, bounded stage failure normalization and
cleanup retry, and orchestrator stage-shape contract.

### GREEN

After implementation, the focused command was rerun:

```text
node --test test/container-backend.test.js test/dynamic-analysis.test.js
```

Observed result: `129` tests, `119` passed, `0` failed, `10` skipped, `0`
cancelled.

The focused coverage now includes:

- exact immutable `load`/`registration`/`invocation` stage schema and fixed harness argv;
- fresh runner creation per stage with no `exec` or host fallback;
- Docker and Podman endpoint, executable, sanitized environment, cwd, and no-shell binding;
- `--pull=never`, network denial, private PID/IPC, read-only root, nonroot, dropped capabilities, no-new-privileges, bounded tmpfs/resources, and read-only staging;
- bounded output, timeout, cancellation, nonzero exit, malformed evidence, crash/engine failure, and truncation normalization;
- ownership verification, forged/cross-run handle rejection, exact resource-ID cleanup, late completion, repeated/concurrent cleanup, failed cleanup retry, and orphan-cap behavior;
- collection only after all three stages have complete bounded evidence;
- orchestrator quiescence-before-cleanup semantics and incomplete-on-uncertainty status mapping.

## Implementation summary

- `container-backend.js` now validates frozen allowlisted stage objects, creates a
  detached hardened runner for each stage, binds every command to the verified
  local engine endpoint/environment/cwd, verifies the generated ownership label,
  waits for the runner, reads bounded logs, normalizes evidence, and removes the
  exact captured container ID.
- Stage resources are not treated as complete until exact cleanup succeeds;
  failed removal is retained as a bounded owned orphan reservation and retried
  only against that exact resource. Cleanup remains single-flight and
  idempotent.
- `container-command.js` owns the fixed harness entrypoint; callers cannot
  provide commands, entrypoints, mounts, images, environment, or flags through
  the stage protocol.
- `contracts.js` owns the shared fixed stage allowlist, and `orchestrator.js`
  passes the stage name separately from its internal abort signal so the public
  stage object contains no extra fields.

## Full verification

1. Syntax and whitespace checks:

   ```text
   node --check engine/dynamic/container-backend.js
   node --check engine/dynamic/container-command.js
   node --check engine/dynamic/contracts.js
   node --check engine/dynamic/orchestrator.js
   node --check test/container-backend.test.js
   node --check test/dynamic-analysis.test.js
   node --check test/helpers/fake-dynamic-backend.js
   git diff --check
   ```

   All commands exited `0`.

2. Full project contract:

   ```text
   C:\nvm4w\nodejs\npm.cmd test
   ```

   Observed result: `389` tests, `379` passed, `0` failed, `10` skipped,
   `0` cancelled.

3. No-engine host smoke:

   ```text
   C:\nvm4w\nodejs\node.exe --input-type=module -e "import { resolveDynamicBackend } from './engine/dynamic/backend-resolver.js'; const result = resolveDynamicBackend({ backendName: 'auto' }); if (result.code !== 'backend-not-implemented-phase-a' || result.backend !== null) process.exit(1); console.log(JSON.stringify(result));"
   ```

   Output was `{"available":false,"backend":null,"code":"backend-not-implemented-phase-a"}`.
   This smoke uses the existing Phase-A injected-only resolver and does not
   contact Docker or Podman.
