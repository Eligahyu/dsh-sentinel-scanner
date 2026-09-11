# Phase B Task 3 report — hardened container backend capability layer

## Delivered scope

- Added `createContainerBackend(options)`, implementing the Phase A backend surface: `available`, `prepare`, `runStage`, `collect`, and `cleanup`.
- Kept Phase A resolution unchanged: `backend-resolver` exports the factory but continues to resolve only injected backends. Existing fake backend tests remain unchanged and pass.
- Reused the Task 1 factory-owned staging capability and frozen argv builder. The backend accepts no raw source or staging path and relies on `normalizeContainerPolicy` before building its fixed `run` command.
- Preserved Task 2 ownership: no staging traversal or source-path handling was added to this backend.

## Security behavior

- Production execution uses the `execFile`-style runner with frozen argv, `shell: false`, a timeout, and a byte cap. Tests inject the runner and never execute Docker or Podman.
- Capability detection accepts only Docker/Podman local Unix or Windows named-pipe endpoints. It fail-closes on all configured remote-context environment variables, mutable or missing-digest images, failed or timed-out probes, oversized output, malformed JSON, and unknown JSON fields.
- `prepare` requires a deeply frozen, structurally validated run spec and a Task 1 factory capability. The run-spec check is intentionally input-shape validation, not a provenance claim. It uses the Task 1 builder's fixed hardened `run` argv, including private network/PID/IPC, non-root UID, dropped capabilities, no-new-privileges, read-only root, bounded `/tmp`, resource limits, and a read-only staging bind mount.
- Each run receives an independent generated label. A create-result ID is accepted only in its strict identifier form and is then verified by a fixed label inspection query. The returned frozen handle is registered in this backend's private `WeakMap` only after verification.
- `cleanup` accepts only that exact private handle. It invokes the fixed `rm --force <captured-id>` argv; foreign/forged handles return `{ complete: false }`, command errors do not leak diagnostics, successful duplicate cleanup performs no second removal, and caller-tightened execution/output limits remain in force during cleanup.

## TDD evidence

- The inherited partial diff initially had a green focused baseline (101 tests, 0 failures), so it did not demonstrate a RED state.
- Added the minimal regression test for cleanup retaining the limits frozen during `prepare`. It failed as expected: cleanup used the Phase B maximum timeout (`30000`) instead of the caller-tightened value (`17`).
- Stored `policy.limits` with the private resource state and reused it for cleanup. The regression test then passed.
- Added focused coverage for Docker and Podman success, nonzero and timeout probe failures, every remote-context variable, output bounds, unknown JSON, immutable images, unique labels, forged ownership, missing IDs, immutable run specs, non-factory staging objects, private cleanup ownership, cleanup failure, and duplicate cleanup.

## Verification

- `node --test test/container-backend.test.js test/dynamic-analysis.test.js`: 110 tests total; 100 passed, 0 failed, 10 expected skips.
- `npm test`: rerun after all final contract additions; exit code 0.
- `git diff --check`: exit code 0. Git emitted only its normal Windows line-ending conversion notices.

## Remaining risks / intentional limits

- No real Docker or Podman daemon was contacted. This is intentional: tests use the injected runner seam. Production interoperability with a particular local engine version and image remains an environment-level validation item.
- On this Windows host, Task 2's real Linux descriptor-relative traversal tests are expected to skip; `createStagingSnapshot` fails closed where that traversal primitive is unavailable.
- `runStage` and `collect` intentionally return fixed not-implemented errors once given a valid private handle. Task 3 is limited to capability detection, preparation, and ownership/cleanup seams; stage execution and evidence collection remain later work.

## Local commit

- `6001566 feat: add hardened container backend capability layer`

## Fix round 1 — verified review findings

### Security and correctness fixes

- Bound the verified local execution state to the backend lifetime after `available()`. Every probe, create, inspect, rollback, and cleanup command now receives an explicit frozen environment snapshot with `DOCKER_HOST`, `CONTAINER_HOST`, `DOCKER_CONTEXT`, and `CONTAINER_CONNECTION` removed. A later transition of the configured environment to a non-empty remote override invalidates the binding before `prepare` can issue a command; production and injected runner paths use the same sanitized child environment, with no host fallback.
- Added `--pull=never` to the fixed Docker and Podman run argv, in addition to `--network=none`, so a hardened run cannot trigger registry traffic.
- Ownership inspection now accepts bounded extra OCI/image labels while requiring the exact generated `dsh.sentinel.run` value. Label count, per-key size, per-value size, and total size are capped.
- If create returns a strict resource ID but inspect or ownership validation fails, `prepare` performs best-effort private failure-only cleanup using only that exact ID captured from the current create invocation. Invalid or attacker-supplied IDs are never sent to cleanup.
- Clarified the run-spec contract: the backend validates a deeply frozen structural input and does not present that shape check as provenance protection. A regression test proves that a structurally valid frozen copy reaches the backend contract without implying an unforgeable origin.
- Label state is released on every prepare failure, ownership rollback, and successful cleanup, with a bounded active-label ceiling. Private handle checks remain exact `WeakMap` identity checks.

### Regression coverage and TDD evidence

- Added tests for local capability binding followed by a remote environment transition, sanitized/frozen environments on injected and production `execFile` seams, Docker/Podman no-pull argv, bounded extra labels, oversized ownership output, exact rollback cleanup, structural run-spec semantics, and valid/forged `runStage` and `collect` handles.
- The first focused run after adding the regressions was red with 8 failures, including missing no-pull policy, missing environment propagation, unbounded ownership parsing, missing rollback cleanup, and stale call-count expectations. After the minimal implementation, the focused suite was green.

### Verification

- Focused: `node --test test/container-backend.test.js` — 50 tests total; 40 passed, 0 failed, 10 expected skips.
- Full: `C:\nvm4w\nodejs\npm.cmd test` — 377 tests total; 367 passed, 0 failed, 10 expected skips.
- `git diff --check` — clean apart from Git's normal Windows line-ending conversion notices.

## Fix round 2 — endpoint binding, rollback reservations, and cleanup single-flight

### Security and correctness fixes

- Retained the validated local Docker/Podman endpoint from the capability probe in immutable backend state. Every later create, inspect, failed-prepare rollback, and normal cleanup command is now explicitly prefixed with `--host <endpoint>` for Docker or `--url <endpoint>` for Podman, so mutable default context/config state cannot redirect the command after availability succeeds.
- Extended the controlled child environment to remove engine/config selector variables including `DOCKER_HOST`, `CONTAINER_HOST`, `DOCKER_CONTEXT`, `CONTAINER_CONNECTION`, `DOCKER_CONFIG`, `CONTAINERS_CONF`, `CONTAINERS_STORAGE_CONF`, `PODMAN_CONNECTIONS_CONF`, and `XDG_CONFIG_HOME`. The frozen environment snapshot also fixes the `PATH` used by production `execFile` resolution against later caller mutations.
- Changed failed rollback cleanup to return a fixed `{ complete: boolean }` result. When the exact captured resource cannot be removed, a private orphan record retains its resource ID, generated label, bound endpoint/environment, and limits; the label remains reserved and counts toward the configured 256-resource ceiling. Successful exact cleanup releases the reservation.
- Made normal cleanup single-flight with a private promise stored before the first await. Concurrent callers share the same fixed result and issue exactly one `rm`; failed cleanup preserves incomplete semantics and permits a later retry, while successful cleanup alone marks the handle cleaned and releases its label.

### Regression coverage and TDD evidence

- Added Docker and Podman regressions that mutate the simulated default endpoint/config after availability and verify the captured local endpoint remains present on create, inspect, and cleanup argv. The tests also verify config-selector removal and protection against mutable `PATH` redirection.
- Added a rollback-failure stress regression that forces ownership validation failure and `rm` failure repeatedly. It proves exactly 256 create attempts are possible and the 257th attempt is rejected before creating another resource.
- Added a concurrent cleanup regression that gates the first removal and verifies two callers receive identical fixed results while exactly one `rm` is issued.
- The first focused run after adding the new regressions was red with 3 failures: missing endpoint prefixing, missing rollback reservation accounting, and duplicate concurrent cleanup. After implementation and existing argv expectation updates, the focused suite was green.

### Verification

- Focused: `node --test test/container-backend.test.js` — 53 tests total; 43 passed, 0 failed, 10 expected skips.
- Full: `C:\nvm4w\nodejs\npm.cmd test` — 380 tests total; 370 passed, 0 failed, 10 expected skips.
