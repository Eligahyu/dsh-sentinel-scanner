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
