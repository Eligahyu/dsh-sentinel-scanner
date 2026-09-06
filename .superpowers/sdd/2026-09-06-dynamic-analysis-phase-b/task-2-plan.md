# Sanitized Dynamic Staging Snapshot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Execute this plan inline in the assigned worktree. Do not dispatch subagents.

**Goal:** Create a bounded, descriptor-checked copy of an untrusted source tree in the factory-owned staging capability before it can be mounted into a container.

**Architecture:** `engine/dynamic/staging.js` will obtain its workspace solely through Task 1's `createStagingCapability()`, walk an independently resolved source directory without following links, and copy only descriptor-verified regular files into its snapshot. `engine/path-safety.js` will provide lexical containment for paths that must not be resolved through an untrusted link. A frozen, relative-only manifest will record copied file metadata and bounded exclusions; every failure disposes the capability.

**Tech Stack:** Node.js 22 ESM; `node:fs` synchronous descriptor APIs; `node:test`.

**Spec:** `.superpowers/sdd/2026-09-06-dynamic-analysis-phase-b/task-2-brief.md`

## Global Constraints

- Work only in `C:\Users\Administrator\Desktop\code\dsh-sentinel\.worktrees\dynamic-analysis-phase-b`.
- Never mount or register `sourceRoot`; only the newly created Task 1 capability can be mounted.
- Reject symlinks, hardlinks, sockets, devices, FIFOs, and other non-regular entries; exclude `.git` entries and descendant worktree roots.
- Enforce fixed upper bounds for files, aggregate bytes, each file, and relative path length; caller options can tighten but not raise them.
- Do not place absolute host paths in returned manifests or thrown error messages; cleanup must be idempotent and delegate to `disposeStagingCapability`.

---

### Task 1: Build and verify sanitized staging snapshots

**Files:**
- Create: `engine/dynamic/staging.js`
- Modify: `engine/path-safety.js`
- Modify: `test/container-backend.test.js`
- Create: `.superpowers/sdd/2026-09-06-dynamic-analysis-phase-b/task-2-report.md`

**Interfaces:**
- Consumes: `createStagingCapability(): { root, snapshot }` and `disposeStagingCapability(capability)` from `engine/dynamic/container-policy.js`.
- Produces: `createStagingSnapshot(sourceRoot, options): { capability, root, snapshot, manifest, cleanup }`.

- [ ] **Step 1: Write the failing test matrix.** Import `createStagingSnapshot`, create temporary source fixtures, and assert a valid nested tree is copied with relative-only manifest records. Assert fixed-code rejection plus snapshot rollback for a symlink escape, an actual hardlink, and mocked socket/device entries. Assert `.git` and nested-worktree directories are absent, each four limits rejects, no source writes occur, and calling `cleanup()` twice removes the factory-owned workspace.

- [ ] **Step 2: Run the focused test file before implementation.**

Run: `node --test test/container-backend.test.js`

Expected: FAIL because `engine/dynamic/staging.js` and `createStagingSnapshot` do not yet exist.

- [ ] **Step 3: Add the containment primitive and minimal secure traversal.** Implement lexical child containment in `path-safety.js`. In `staging.js`, open and `fstat` the source root and every candidate file/directory after `lstat`; require identical device/inode identity, `O_NOFOLLOW` where available, a regular file, and `nlink === 1`. Read file descriptors into exclusively-created destination descriptors, stop at precomputed byte budgets, write only under the capability snapshot, set only permission metadata, and map all traversal/copy failures to fixed codes. Dispose the capability on every exception.

- [ ] **Step 4: Re-run focused and integration regression suites.**

Run: `node --test test/container-backend.test.js test/hardening.test.js test/dynamic-analysis.test.js`

Expected: PASS, with no source mutation and no remaining created snapshot after every cleanup path.

- [ ] **Step 5: Run full verification and record it.**

Run: `npm test`, then `git diff --check`.

Expected: PASS and no whitespace errors. Write the exact commands, results, commit, and residual platform risks to the Task 2 report.

- [ ] **Step 6: Commit the code, tests, plan, and report.**

Run: `git add engine/path-safety.js engine/dynamic/staging.js test/container-backend.test.js .superpowers/sdd/2026-09-06-dynamic-analysis-phase-b/task-2-plan.md .superpowers/sdd/2026-09-06-dynamic-analysis-phase-b/task-2-report.md` followed by `git commit -m "feat: add sanitized dynamic staging snapshots"`.

## Self-Review

- Coverage: the one task covers every required unsafe entry, VCS/worktree exclusion, containment and four resource limits, rollback, idempotent Task 1 disposal, focused/dynamic/full verification, report, and commit.
- Placeholders: none; rejection codes and verification commands are explicit.
- Interface consistency: the returned capability is exactly the object Task 1 registers, and `cleanup` delegates only to its Task 1 disposer.
