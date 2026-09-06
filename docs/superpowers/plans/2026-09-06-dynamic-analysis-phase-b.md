# Dynamic Analysis Phase B Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a production-safe Docker/Podman dynamic backend foundation that can detect local isolation capability, stage an untrusted snapshot, construct hardened network-denied runner commands, and clean up only resources owned by the current run.

**Architecture:** Keep the existing backend-neutral orchestrator as the policy owner. Add a container backend adapter whose public methods match `available`, `prepare`, `runStage`, `collect`, and `cleanup`; all engine calls use argument arrays through an injected command runner, never a shell. Phase B enables only a network-denied runner and remains unavailable unless the local engine and immutable trusted image configuration are both present; gateway/probe/network observation remains Phase C.

**Tech Stack:** Node.js ESM, `node:child_process` `execFile`, filesystem staging with `lstat`/`realpath`, existing `node:test` suite, Docker/Podman CLI argument contracts.

**Spec:** `docs/superpowers/specs/2026-08-31-dynamic-egress-sandbox-design.md`

## Global Constraints

- Dynamic analysis is opt-in; scans without `--dynamic` retain existing behavior.
- The backend must never use a shell, host execution fallback, host network, host PID/IPC, engine socket, host credentials, or the real workspace.
- No image pull or build occurs during a scan; runner image references must be immutable digest-pinned values supplied by trusted scanner configuration.
- The Phase B runner has networking denied; public Internet and gateway behavior are Phase C work.
- The staged snapshot excludes symlinks, hardlinks, sockets, devices, VCS metadata, worktrees, and paths outside the scan root.
- Runner limits are fixed security limits; callers may reduce timeout but cannot disable isolation or raise resource caps.
- Backend stdout/stderr and engine errors are untrusted, bounded, redacted, and never copied raw into reports.
- Cleanup is idempotent, ownership-scoped, and required on success, refusal, timeout, cancellation, parser failure, and unexpected exceptions.
- Tests must prove argument injection resistance, no-shell invocation, containment, output bounds, cleanup races, and unavailable behavior when prerequisites are absent.

---

### Task 1: Add immutable container backend policy and command contracts

**Files:**
- Create: `engine/dynamic/container-policy.js`
- Create: `engine/dynamic/container-command.js`
- Modify: `engine/dynamic/policy.js`
- Test: `test/container-backend.test.js`

**Interfaces:**
- `container-policy.js` exports frozen Phase B limits, supported engines, required digest format, and `normalizeContainerPolicy(input) -> normalized policy`.
- `container-command.js` exports `buildEngineArgs({ engine, action, label, image, ... }) -> string[]` and `validateEngineName(value) -> 'docker'|'podman'`.
- The command builder never returns a shell string and rejects user-controlled flags, mutable image tags, host networking, privileged mode, host namespaces, mounts outside the staged snapshot, and engine socket paths.

- [ ] **Step 1: Write failing tests** for digest-only image validation, fixed limits, Docker/Podman argument parity, no-shell output, and rejection of `--privileged`, `--network=host`, `--pid=host`, `-v` engine sockets, mutable tags, and injected label arguments.
- [ ] **Step 2: Run the focused tests** and confirm they fail because the policy and builder do not exist.
- [ ] **Step 3: Implement the minimal frozen policy and argument builder** with explicit allowlists and bounded scalar validation.
- [ ] **Step 4: Run focused tests and the existing dynamic suite**; confirm all pass without invoking an engine.
- [ ] **Step 5: Commit** `feat: define hardened container command contracts`.

### Task 2: Build a sanitized staging snapshot

**Files:**
- Create: `engine/dynamic/staging.js`
- Modify: `engine/path-safety.js`
- Test: `test/container-backend.test.js`

**Interfaces:**
- `createStagingSnapshot(sourceRoot, options) -> { root, manifest, cleanup }`.
- The snapshot copies only regular files under the resolved scan root, rejects or records unsafe entries according to fixed policy, preserves bounded file metadata, and never follows symlinks or hardlinks.
- `cleanup()` is idempotent and deletes only the snapshot directory created for the run.

- [ ] **Step 1: Write failing tests** for symlink escape, hardlink rejection, sockets/devices, `.git` and nested worktree exclusion, root containment, file-count/byte limits, path-length limits, cleanup idempotence, and a valid nested snapshot.
- [ ] **Step 2: Run the focused tests** and confirm the new behaviors fail.
- [ ] **Step 3: Implement descriptor-based traversal** using `lstat`, explicit directory allowlists, bounded copy streams, and a per-run random staging directory outside the source tree.
- [ ] **Step 4: Run focused tests, path-safety tests, and the full suite**; verify no source file is modified and no snapshot remains.
- [ ] **Step 5: Commit** `feat: add sanitized dynamic staging snapshots`.

### Task 3: Implement engine capability detection and owned resource handles

**Files:**
- Create: `engine/dynamic/container-backend.js`
- Modify: `engine/dynamic/backend-resolver.js`
- Test: `test/container-backend.test.js`

**Interfaces:**
- `createContainerBackend(options) -> backend` implementing the orchestrator interface.
- `backend.available() -> { available, backend, code, capabilities }` performs one bounded local capability probe through an injected `execFile`-style runner; it rejects remote contexts and mutable image configuration.
- `prepare(runSpec) -> handle` creates only labeled resources from the current run and returns immutable ownership metadata.
- The backend uses a command-runner seam in tests and `execFile` with `{ shell: false }` in production; it never invokes `cmd.exe`, PowerShell, `sh`, Docker API sockets, or package managers.

- [ ] **Step 1: Write failing tests** for Docker/Podman detection, remote-context refusal, missing digest refusal, bounded probe output, command failure normalization, unique labels, and ownership metadata that cannot be forged by backend output.
- [ ] **Step 2: Run focused tests** and confirm expected failures.
- [ ] **Step 3: Implement capability detection and a prepare path** that creates a network-denied runner with non-root user, dropped capabilities, `no-new-privileges`, read-only root, bounded tmpfs, resource limits, staged read-only mount, and no host namespaces or sockets.
- [ ] **Step 4: Run focused tests and the full suite** without requiring Docker/Podman on the host.
- [ ] **Step 5: Commit** `feat: add hardened container backend capability layer`.

### Task 4: Implement bounded runner stages and cleanup

**Files:**
- Modify: `engine/dynamic/container-backend.js`
- Modify: `engine/dynamic/orchestrator.js`
- Modify: `engine/dynamic/contracts.js`
- Test: `test/container-backend.test.js`
- Test: `test/dynamic-analysis.test.js`

**Interfaces:**
- `runStage(handle, stageSpec) -> bounded stage evidence` executes only the fixed Phase B harness entrypoint inside a fresh network-denied runner; it does not execute an arbitrary host command.
- `collect(handle) -> bounded normalized evidence` reads only owned bounded output channels.
- `cleanup(handle) -> { cleaned: true }` removes only resources whose IDs and labels were captured from the current owned run, and treats uncertain deletion as incomplete.

- [ ] **Step 1: Write failing tests** for fresh runner-per-stage semantics, fixed harness argv, timeout/cancellation, output truncation, crash normalization, cleanup after every failure, late resource creation, repeated cleanup, and cross-run resource refusal.
- [ ] **Step 2: Run focused tests** and confirm the failures are meaningful.
- [ ] **Step 3: Implement the runner stage protocol** with bounded stdin/config, bounded stdout/stderr, abort handling, quiescence, and no public network; extend the orchestrator only where needed to preserve its Phase A invariants.
- [ ] **Step 4: Run focused, dynamic, and full suites** and inspect for unhandled rejections or leaked temporary resources.
- [ ] **Step 5: Commit** `feat: run bounded network-denied container stages`.

### Task 5: Wire Phase B availability without changing safe defaults

**Files:**
- Modify: `engine/dynamic/backend-resolver.js`
- Modify: `engine/config.js`
- Modify: `engine/index.js`
- Modify: `bin/sentinel.mjs`
- Test: `test/dynamic-analysis.test.js`
- Test: `test/professional-contract.test.js`

**Interfaces:**
- Production resolver selects the Phase B backend only for explicit `--dynamic` requests and only when immutable trusted image configuration and a local Docker/Podman capability probe pass.
- `--dynamic-backend auto|docker|podman` remains bounded; unavailable/refused/incomplete remain reportable and strict modes still exit `3`.
- No dynamic request continues to bypass backend detection and container creation entirely.

- [ ] **Step 1: Write failing integration tests** for default static-only behavior, explicit backend selection, missing image/config refusal, unavailable local engine, and strict exit semantics.
- [ ] **Step 2: Run focused tests** and confirm the resolver still returns the Phase A unavailable result.
- [ ] **Step 3: Wire the backend behind the existing injection boundary** without accepting arbitrary backend objects, image refs, host mounts, or engine endpoints from CLI/config.
- [ ] **Step 4: Run full tests, release verification, and a no-engine smoke test**; verify the normal test host remains static-safe.
- [ ] **Step 5: Commit** `feat: enable opt-in phase b backend resolution`.

### Task 6: Documentation, Linux-only integration gate, and release evidence

**Files:**
- Modify: `README.md`
- Modify: `README.zh-CN.md`
- Modify: `SECURITY.md`
- Modify: `docs/architecture.md`
- Create: `.github/workflows/dynamic-smoke.yml`
- Modify: `.final-test.txt`
- Modify: `.final-bench.txt` only if benchmark output changes
- Test: `test/hardening.test.js`

- [ ] **Step 1: Write failing documentation/workflow contract tests** for explicit opt-in, network-denied Phase B semantics, no host fallback, immutable image requirement, and Linux-only smoke gating.
- [ ] **Step 2: Run focused tests** and confirm the current docs/workflow do not cover Phase B.
- [ ] **Step 3: Document operational prerequisites and failure states** in English first, with Chinese as secondary documentation; add a Linux workflow that skips cleanly when trusted images are unavailable and never permits public Internet.
- [ ] **Step 4: Run full test, benchmark, verify:release, pack dry-run, offline audit, and `git diff --check`; refresh evidence files.
- [ ] **Step 5: Commit** `docs: document dynamic analysis phase b gate`.

## Final Review Gate

- Run the complete test contract and confirm the reported test count matches `.final-test.txt`.
- Run argument-construction security review with hostile engine/image/path values.
- Run a no-engine host smoke test and verify the result is `unavailable`, not host execution.
- Run the Linux dynamic smoke workflow only with immutable trusted images and public network disabled.
- Obtain an independent security review before merging Phase B into `master` or enabling it in release automation.
