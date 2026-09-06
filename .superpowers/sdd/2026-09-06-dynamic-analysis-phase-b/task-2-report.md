# Task 2 Report: Sanitized Dynamic Staging Snapshot

## Delivered interface

Added `createStagingSnapshot(sourceRoot, options)` in `engine/dynamic/staging.js`. It returns a frozen object containing:

- `capability`: the exact opaque capability allocated by Task 1;
- `root` and `snapshot`: the capability-owned paths for diagnostics only;
- `manifest`: frozen, relative-only copied-file metadata plus bounded VCS/worktree exclusion counts;
- `cleanup()`: idempotent cleanup which calls Task 1's `disposeStagingCapability(capability)`.

The snapshot creator never accepts a caller-provided staging path and never registers or mounts `sourceRoot`. The container command test proves that only the returned capability produces the mount source.

## Security behavior

- Creates a new factory-owned Task 1 workspace for every run and copies only `lstat`/descriptor-verified regular files.
- Rejects symlinks, hardlinked files (`nlink !== 1`), sockets, devices, FIFOs, and all other special files with fixed public error codes.
- Excludes `.git` entries without traversing them and excludes descendant directories containing a worktree `.git` marker file.
- Applies lexical child containment without calling `realpath` on untrusted children; source and destination roots are separately `lstat`, descriptor, and `realpath` checked. File and directory identity is checked before and after open/read operations, using `O_NOFOLLOW` where Node exposes it.
- Enforces caller-tightenable, never caller-expandable hard caps: 1,024 files, 32 MiB aggregate content, 8 MiB per file, and 240 characters per relative path. Directory entries also have a bounded traversal budget.
- Uses exclusive destination file creation and descriptor-based bounded copying. Only permission bits are preserved; no owner, ACL, special-mode, or arbitrary metadata crosses into the snapshot.
- Maps errors to fixed `StagingSnapshotError` code/messages. Returned manifests contain no source-root absolute path or unbounded entry list. Any creation/traversal/copy failure invokes Task 1 disposal for rollback.

## TDD evidence

1. Added the valid nested-copy, symlink, hardlink, socket/device, VCS/worktree, containment/limit, source-mount isolation, rollback, and idempotent-cleanup tests before creating `engine/dynamic/staging.js`.
2. Ran `node --test test/container-backend.test.js`; it failed as expected with `ERR_MODULE_NOT_FOUND` for the missing staging module.
3. Implemented the path helper and staging traversal, then reran the focused tests.

## Verification

| Command | Result |
| --- | --- |
| `node --test test/container-backend.test.js` | 19 passed, 0 failed |
| `node --test test/container-backend.test.js test/hardening.test.js test/dynamic-analysis.test.js` | 152 passed, 0 failed |
| `npm test` | Exit code 0 |
| `git diff --check` | Exit code 0; no whitespace errors |

## Platform risk

This Windows host denies ordinary test-process symlink creation with `EPERM`; the symlink rejection test therefore simulates only the `lstat` result while still executing the real staging creator, error mapping, and rollback. The hardlink case is exercised with a real filesystem hardlink. A native descriptor-relative `openat` API is not available in cross-platform Node.js; the implementation mitigates replacement races with pre/post `lstat` plus `fstat` identity checks and `O_NOFOLLOW` where supported. A native helper would be required for fully atomic parent-directory traversal against an attacker that can continuously rename source ancestors.

## Commit

`feat: add sanitized dynamic staging snapshots`

## Round 1: descriptor-relative traversal correction

### Blocker resolution

The initial traversal checked a child with `lstat` and then reopened it by source pathname. A concurrent directory replacement could therefore retarget that later pathname lookup outside the originally opened source root. This round removes that path from the trust boundary.

- Snapshot creation now fails before Task 1 capability allocation with the fixed `staging-descriptor-unavailable` error unless it runs on Linux with `O_DIRECTORY`, `O_NOFOLLOW`, and usable `/proc/self/fd` access.
- The Windows behavior is intentionally fail-closed: no snapshot is allocated or copied. The test tracks Task 1's factory call rather than scanning the shared temporary directory.
- On Linux, the source root is opened from `/` as a chain of verified directory descriptors. Each subsequent child directory, metadata lookup, file open, and directory iterator uses `/proc/self/fd/<parent-fd>/<name>`; no untrusted source pathname is reopened after that root descriptor is established.
- Directory reads use `opendirSync(...).readSync()` and increment the traversal budget as each entry is received. File descriptors, directory descriptors, and `fs.Dir` objects are closed on success and error paths.
- VCS matching is ASCII case-insensitive (`.git`, `.GIT`, `.GiT`), manifests are sorted with a locale-independent code-point comparator, and the copied manifest remains relative-only.

### Additional regression coverage

- Windows validates the explicit pre-factory fail-closed contract.
- Linux-only tests cover real symlink and hardlink rejection, case-insensitive VCS/worktree exclusion, controlled source-root pathname replacement after the descriptor is open, incremental limits, idempotent cleanup, and an injected full read I/O failure whose real factory-owned root is verified removed.
- The previous process-wide temporary-directory residue assertion was removed; each failure test captures the owner root created by that individual invocation.

### Round 1 verification

| Command | Result |
| --- | --- |
| `node --test test/container-backend.test.js` | 15 passed, 0 failed, 9 Linux-only tests skipped on Windows |
| `node --test test/container-backend.test.js test/hardening.test.js test/dynamic-analysis.test.js` | 148 passed, 0 failed, 9 Linux-only tests skipped on Windows |
| `npm test` | Exit code 0 on this Windows host |
| `git diff --check` | Exit code 0; no whitespace errors |

This host has no installed WSL distribution, so the Linux-only tests could not be executed locally. They are deliberately not represented as Windows coverage. Linux CI must execute the nine descriptor-relative tests before claiming Linux runtime verification.

## Round 2: traversal-entry budget and capability-gated Linux tests

### TDD evidence

1. Added an independent `maxEntries` hard-cap assertion and a Linux-only integration test that creates five directory entries with caller-supplied `maxEntries: 4`.
2. The new focused test run failed before the implementation change: `STAGING_SNAPSHOT_LIMITS.maxEntries` was `undefined` rather than `4096` (15 passed, 1 failed, 10 skipped).
3. Added the non-expandable 4,096-entry hard cap, preserves a caller-tightened `maxEntries`, and changes over-budget traversal to the fixed `staging-entry-budget-limit` error.

### Regression coverage

- The entry-budget test records the Task 1 factory-owned root for this invocation and verifies rollback after the fixed error. It creates directories rather than files, so it exercises traversal entries rather than file, byte, or path-length limits.
- The test replaces `fs.readdirSync` with a throwing stub for the snapshot attempt. The snapshot still must reach `staging-entry-budget-limit`, which proves the code uses the incremental `opendirSync`/`Dir.readSync()` path and stops before collecting an over-budget directory with whole-directory `readdirSync`.
- Linux staging tests now use a one-time, side-effect-free capability probe: Linux platform, numeric `O_DIRECTORY` and `O_NOFOLLOW`, plus opening, `fstat`-checking, and closing `/proc/self/fd`. If the probe is unavailable, they explicitly skip rather than treating `process.platform` alone as proof of safety.
- Product behavior remains fail-closed whenever the same descriptor conditions are unavailable: no Task 1 capability is allocated and no source file is copied. The existing Windows test continues to verify this condition.
- The existing real Linux symlink, hardlink, descriptor pathname-replacement, VCS/worktree, cleanup, and injected full-I/O rollback tests remain in place.

### Round 2 verification

| Command | Result |
| --- | --- |
| `node --test test/container-backend.test.js` | 16 passed, 0 failed, 10 explicitly capability-gated Linux tests skipped on this Windows host |
| `node --test test/container-backend.test.js test/hardening.test.js test/dynamic-analysis.test.js` | 149 passed, 0 failed, 10 explicitly capability-gated Linux tests skipped |
| `npm test` | Exit code 0 on this Windows host |
| `git diff --check` | Exit code 0; line-ending conversion warnings only, no whitespace errors |

The host still has no installed WSL distribution, so the new real traversal-entry test and the other descriptor tests have not run locally. Linux CI must run the ten capability-gated tests before claiming Linux runtime verification; Windows is covered only for the intentional fail-closed behavior.
