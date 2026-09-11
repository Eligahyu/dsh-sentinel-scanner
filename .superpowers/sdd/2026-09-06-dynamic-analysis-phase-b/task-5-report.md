# Task 5 report — wire Phase B availability without changing safe defaults

## RED

Added integration coverage first in `test/dynamic-analysis.test.js` for:

- static scans with no dynamic request;
- missing trusted immutable image;
- explicit Docker and `auto` local-engine selection;
- remote-context refusal;
- static preflight refusal;
- staging disposal on unavailable production resolution;
- hostile CLI/config image, endpoint, command, and adapter inputs; and
- strict exit code `3` for requested incomplete dynamic work.

The first test run stopped at the expected missing-resolver-export boundary. After adding only the resolver test surface, the focused run reached a behavioral RED: `74` tests, `71` passed, `3` failed. The failures were the expected missing production orchestration/staging behavior and the two Phase-A reason-code assertions that Task 5 supersedes.

## GREEN

Implemented the minimal production path:

- ordinary scans return the existing static-only result without resolver, engine, backend, or staging activity;
- production resolution accepts only a branded scanner-owned immutable digest descriptor;
- missing trusted image returns fixed `trusted-image-unavailable` without staging or engine probing;
- Docker, Podman, and `auto` use the existing hardened local-only adapter policy;
- the production adapter verifies the immutable image is available locally with no pull/build path;
- production dynamic runs own a sanitized staging capability and dispose it after unavailable, refused, incomplete, and error results;
- injected fake backends remain on the separate test seam; and
- CLI/config inputs cannot provide image refs, endpoints, executable paths, mounts, commands, or adapter objects.

Focused GREEN verification:

```text
node --check engine/dynamic/backend-resolver.js
node --check engine/dynamic/orchestrator.js
node --check engine/dynamic/container-backend.js
node --check engine/index.js
node --check bin/sentinel.mjs
node --test test/dynamic-analysis.test.js test/professional-contract.test.js
83 tests, 83 passed, 0 failed
```

The Phase B adapter suite also passed:

```text
node --test test/container-backend.test.js
68 tests, 58 passed, 10 skipped by the existing Linux staging capability guard, 0 failed
```

## Full verification

```text
C:\nvm4w\nodejs\npm.cmd test
402 tests, 392 passed, 10 skipped by the existing Linux staging capability guard, 0 failed
```

```text
C:\nvm4w\nodejs\npm.cmd run verify:release
PASS: full test suite, benchmark, and npm pack --dry-run
Benchmark: rule F1 0.976, finding F1 0.957, flow F1 1.000
```

```text
node bin/sentinel.mjs test/fixtures/clean-plugin --dynamic --strict-exit-codes --json
NO_ENGINE_SMOKE_EXIT=3
```

The no-engine smoke reported dynamic status `unavailable` with fixed code `trusted-image-unavailable`; no Docker or Podman process was contacted. `git diff --check` reported no whitespace errors.

## Fix round 1/5 — resolver trust and staging ownership boundaries

### RED

Added regression tests before the fix for the reviewed Important and Minor findings:

- the shipped resolver namespace still exposed `TRUSTED_DYNAMIC_IMAGE`,
  `createTrustedDynamicImage`, and `createTrustedDynamicImageForTests`;
- a forged staging-shaped object was not rejected at resolver selection time; and
- production scan accepted a hostile `dynamicBackendAdapter` option instead of
  proving that production selection ignores it.

The focused RED run was:

```text
node --test test/dynamic-analysis.test.js
74 tests, 72 passed, 2 failed
```

The two failures were the expected public-constructor exposure and forged-staging
selection failures.

### GREEN

The minimal security fix now:

- removes all trusted-image constructors, symbols, descriptor registries, and
  injected runner/staging/environment options from the public backend resolver;
- keeps the approved image registry closed inside the resolver, with no built-in
  asset in this deployment, so production remains fixed-unavailable until a
  scanner-owned exact digest is shipped;
- ignores arbitrary adapter/image options at the production scan boundary while
  retaining fake-backend coverage only through the direct orchestrator test seam;
- validates staging capability ownership through the existing private capability
  registry before any production backend is constructed or probed; and
- preserves preflight refusal, static zero-probe behavior, local-only adapter
  policy, staging cleanup, and strict exit semantics.

Focused GREEN verification:

```text
node --test test/dynamic-analysis.test.js
75 tests, 75 passed, 0 failed

node --test test/dynamic-analysis.test.js test/professional-contract.test.js
84 tests, 84 passed, 0 failed

node --test test/container-backend.test.js
68 tests, 58 passed, 10 skipped by the existing Linux staging capability guard, 0 failed
```

Syntax and whitespace checks passed for the resolver, orchestrator, scanner,
CLI, container adapter, and working-tree diff.

### Full verification

```text
C:\nvm4w\nodejs\npm.cmd test
403 tests, 393 passed, 10 skipped by the existing Linux staging capability guard, 0 failed
```

```text
node bin/sentinel.mjs test/fixtures/clean-plugin --dynamic --strict-exit-codes --json
NO_ENGINE_SMOKE_EXIT=3
dynamicStatus=unavailable
code=trusted-image-unavailable
```

No Docker or Podman daemon was contacted during verification.

## Fix round 2/5 — package export boundary

### RED

Added a package self-reference regression test covering the supported root API,
package metadata, plugin export resolution, and the sensitive engine subpaths.
Before the package change, the wildcard export allowed the first deep import:

```text
node --test --test-name-pattern="package self-reference" test/dynamic-analysis.test.js
1 test, 0 passed, 1 failed
AssertionError: Missing expected rejection: deepseek-harness-sentinel/engine/index
```

The failure demonstrated that a package consumer could still reach the internal
engine tree despite the closed resolver surface.

### GREEN

Replaced the broad `./engine/*` package export with the explicit supported
allowlist already intended by the package:

- `.`, the scanner public API;
- `./plugin`, the plugin entrypoint;
- `./package.json`, package metadata; and
- `./cordis.patch.yml`, the bundle patch asset.

The internal container policy, staging capability factory, container backend,
execution seams, resolver assembly, and orchestrator internals remain available
to repository-relative production and test imports but are no longer package
subpaths. The regression now proves all of these fail with package path export
errors:

- `deepseek-harness-sentinel/engine/index`;
- `deepseek-harness-sentinel/engine/dynamic/container-policy`;
- `deepseek-harness-sentinel/engine/dynamic/container-backend`; and
- `deepseek-harness-sentinel/engine/dynamic/backend-resolver`.

Focused verification:

```text
node --test --test-name-pattern="package self-reference" test/dynamic-analysis.test.js
1 test, 1 passed, 0 failed

node --test test/dynamic-analysis.test.js test/professional-contract.test.js
85 tests, 85 passed, 0 failed
```

`npm pack --dry-run --json` completed successfully and reported the expected
package contents, including `package.json` with the explicit exports map. Syntax
checks and `git diff --check` also passed.

### Full verification

```text
C:\nvm4w\nodejs\npm.cmd test
404 tests, 394 passed, 10 skipped by the existing Linux staging capability guard, 0 failed
```

```text
node bin/sentinel.mjs test/fixtures/clean-plugin --dynamic --strict-exit-codes --json
NO_ENGINE_SMOKE_EXIT=3
dynamicStatus=unavailable
code=trusted-image-unavailable
```

The static default, closed image registry, forged staging rejection, Task 3/4
hardening, and strict exit behavior remain green. No Docker or Podman daemon was
contacted.
