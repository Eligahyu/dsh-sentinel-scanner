# Dynamic Analysis Phase A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the safe, backend-neutral foundation for opt-in dynamic analysis without starting containers or executing untrusted code.

**Architecture:** Add a separate dynamic-analysis report layer, centrally bounded options, deterministic state transitions, per-run synthetic canaries, redacted evidence normalization, and an injected fake backend. The production resolver deliberately reports every real backend as unavailable in Phase A. Static completeness remains independent from dynamic completeness.

**Tech Stack:** Node.js ESM, built-in `node:test`, built-in `crypto`, existing report/config/CLI infrastructure.

**Spec:** `docs/superpowers/specs/2026-08-31-dynamic-egress-sandbox-design.md`

## Global Constraints

- Phase A must never invoke Docker, Podman, a shell, a package manager, plugin code, or any untrusted entrypoint.
- Dynamic analysis remains opt-in. Existing scans without `--dynamic` retain their current verdict and exit behavior.
- `summary.scanComplete` continues to describe the static/core scan only. Requested dynamic analysis is represented separately by `summary.dynamicRequested`, `summary.dynamicComplete`, and `summary.dynamicStatus`.
- No report may contain raw canary values, unbounded backend output, host absolute paths, or backend diagnostics.
- Security limits are immutable upper bounds. User configuration may only select a shorter timeout.
- Backend injection is an internal testing seam and is not loaded from configuration or CLI input.
- Every implementation step follows red-green-refactor and commits only after its focused tests pass.

---

## Task 1: Add the stable dynamic report contract

**Files:**

- Create: `engine/dynamic/contracts.js`
- Modify: `engine/report/schema.js`
- Modify: `engine/report.js`
- Modify: `test/professional-contract.test.js`

- [ ] **Step 1: Write failing contract tests**

Add assertions that every report contains a normalized `analysisLayers.dynamic` object and independent summary fields:

```js
assert.deepEqual(report.analysisLayers.dynamic, {
  status: 'not-requested',
  requested: false,
  complete: false,
  backend: null,
  profile: null,
  stages: [],
  networkAttempts: [],
  dnsQueries: [],
  processes: [],
  fileEvents: [],
  canaryEvents: [],
  policyViolations: [],
  limitations: [],
  failures: [],
  evidenceDigest: null
})
assert.equal(report.summary.dynamicRequested, false)
assert.equal(report.summary.dynamicComplete, false)
assert.equal(report.summary.dynamicStatus, 'not-requested')
assert.equal(report.summary.scanComplete, true)
```

Also test that malformed status, arrays, backend, and digest values normalize to safe defaults rather than leaking arbitrary structures.

- [ ] **Step 2: Run the focused test and confirm failure**

```powershell
node --test --test-name-pattern='dynamic report contract' test/professional-contract.test.js
```

Expected: failure because the dynamic layer is absent.

- [ ] **Step 3: Implement the contract module**

Export the only accepted statuses and the two contract helpers:

```js
export const DYNAMIC_STATUSES = Object.freeze([
  'not-requested',
  'unavailable',
  'refused',
  'complete',
  'incomplete'
])

export function emptyDynamicLayer() {
  return {
    status: 'not-requested', requested: false, complete: false,
    backend: null, profile: null, stages: [], networkAttempts: [],
    dnsQueries: [], processes: [], fileEvents: [], canaryEvents: [],
    policyViolations: [], limitations: [], failures: [], evidenceDigest: null
  }
}

export function normalizeDynamicLayer(value = {}) {
  // Copy only known scalar fields and arrays; return fresh arrays and objects.
}
```

`normalizeDynamicLayer` must enforce these invariants:

- `not-requested` implies `requested=false`, `complete=false`, `backend=null`, and `profile=null`.
- `complete` implies `requested=true` and `complete=true`.
- `unavailable`, `refused`, and `incomplete` imply `requested=true` and `complete=false`.
- unknown fields are discarded.
- list fields accept arrays only and are shallow-cloned.

- [ ] **Step 4: Integrate without changing static completeness**

Add `dynamic` to `LAYER_DEFAULTS`, normalize it with `normalizeDynamicLayer`, and leave it out of `CORE_INCOMPLETE_LAYERS`. In `buildReport`, derive:

```js
const dynamic = analysisLayers.dynamic
const dynamicRequested = dynamic.requested === true
const dynamicComplete = dynamicRequested && dynamic.complete === true
```

Expose these values in `summary`. Extend `assertReportContract` to validate the dynamic invariants while keeping `summary.scanComplete` tied only to core static layers.

- [ ] **Step 5: Run focused tests and commit**

```powershell
node --test --test-name-pattern='professional report|dynamic report contract' test/professional-contract.test.js
git add engine/dynamic/contracts.js engine/report/schema.js engine/report.js test/professional-contract.test.js
git commit -m "feat: define dynamic analysis report contract"
```

---

## Task 2: Normalize policy, configuration, and CLI options

**Files:**

- Create: `engine/dynamic/policy.js`
- Modify: `engine/config.js`
- Modify: `bin/sentinel.mjs`
- Create: `test/dynamic-analysis.test.js`
- Modify: `package.json`

- [ ] **Step 1: Register the dedicated test file**

Add `test/dynamic-analysis.test.js` to the existing explicit `node --test` list in `package.json`.

- [ ] **Step 2: Write failing option-normalization tests**

Cover defaults, accepted values, rejected values, numeric parsing, and hard-limit clamping:

```js
assert.deepEqual(normalizeDynamicOptions({}), {
  requested: false,
  backendName: 'auto',
  profile: 'observe',
  timeoutMs: 15000
})
assert.equal(normalizeDynamicOptions({ dynamic: true, dynamicTimeoutMs: 60000 }).timeoutMs, 30000)
assert.equal(normalizeDynamicOptions({ dynamic: true, dynamicTimeoutMs: 400 }).timeoutMs, 1000)
assert.throws(() => normalizeDynamicOptions({ dynamicBackend: 'remote' }), /dynamic backend/i)
assert.throws(() => normalizeDynamicOptions({ dynamicProfile: 'internet' }), /dynamic profile/i)
```

- [ ] **Step 3: Run the dedicated test and confirm failure**

```powershell
node --test --test-name-pattern='dynamic options' test/dynamic-analysis.test.js
```

- [ ] **Step 4: Implement immutable limits and normalization**

Export:

```js
export const DYNAMIC_HARD_LIMITS = Object.freeze({
  defaultTimeoutMs: 15000,
  minTimeoutMs: 1000,
  maxTimeoutMs: 30000,
  maxEvents: 2000,
  maxTextBytes: 262144,
  maxListItems: 500,
  maxEvidenceDepth: 8
})

export function normalizeDynamicOptions(input = {}) {
  // Return only requested, backendName, profile, and bounded timeoutMs.
}
```

Accept only `auto`, `docker`, or `podman`; Phase A accepts only the `observe` profile. Reject non-finite timeout input and clamp finite input to the immutable interval.

- [ ] **Step 5: Extend known configuration keys**

Add these defaults to `DEFAULT_CONFIG`:

```js
dynamic: false,
dynamicBackend: 'auto',
dynamicProfile: 'observe',
dynamicTimeoutMs: 15000
```

Do not add backend adapter objects, command paths, image references, engine endpoints, or privilege controls to user configuration.

- [ ] **Step 6: Parse the four CLI flags**

Add:

```text
--dynamic
--dynamic-backend auto|docker|podman
--dynamic-profile observe
--dynamic-timeout <milliseconds>
```

Missing values and invalid values must produce the existing usage-error exit path. The CLI must pass only normalized primitive options into `scan`.

- [ ] **Step 7: Test and commit**

```powershell
node --test --test-name-pattern='dynamic options|dynamic CLI' test/dynamic-analysis.test.js
git add engine/dynamic/policy.js engine/config.js bin/sentinel.mjs test/dynamic-analysis.test.js package.json
git commit -m "feat: add bounded dynamic analysis options"
```

---

## Task 3: Create canaries and bounded evidence normalization

**Files:**

- Create: `engine/dynamic/canaries.js`
- Create: `engine/dynamic/evidence.js`
- Modify: `test/dynamic-analysis.test.js`

- [ ] **Step 1: Write failing canary tests**

Use injectable entropy to prove repeatable tests while production uses `randomBytes`:

```js
const canaries = createCanarySet({
  runId: 'run-test',
  entropy: size => Buffer.alloc(size, 0x41)
})
assert.deepEqual(canaries.descriptors.map(item => item.kind), [
  'api-key', 'bearer-token', 'environment-secret', 'ssh-file',
  'workspace-document', 'conversation', 'memory', 'tool-argument'
])
assert.equal(JSON.stringify(canaries.descriptors).includes(canaries.values.apiKey), false)
```

Require every descriptor to contain a stable per-run `id`, `kind`, and SHA-256 `digest`, but never the raw value.

- [ ] **Step 2: Write failing evidence tests**

Test recursive redaction, event caps, text byte caps, accepted event shapes, and digest stability:

```js
const normalized = normalizeDynamicEvidence({
  networkAttempts: [{ destination: 'sink.invalid', body: canaries.values.apiKey }],
  stdout: `prefix ${canaries.values.apiKey} suffix`
}, { canaries, limits: DYNAMIC_HARD_LIMITS })

assert.equal(JSON.stringify(normalized).includes(canaries.values.apiKey), false)
assert.equal(normalized.networkAttempts[0].canaryIds.includes('api-key'), true)
assert.match(normalized.stdout, /\[CANARY:api-key\]/)
assert.match(evidenceDigest(normalized), /^[a-f0-9]{64}$/)
```

Also assert that Windows and POSIX absolute paths become `[HOST_PATH]`, unknown fields are discarded, and truncation adds a structured limitation.

- [ ] **Step 3: Confirm failures**

```powershell
node --test --test-name-pattern='dynamic canary|dynamic evidence' test/dynamic-analysis.test.js
```

- [ ] **Step 4: Implement canary creation**

`createCanarySet` returns two deliberately separate views:

```js
{
  values: Object.freeze({ apiKey, bearerToken, environmentSecret, sshFile,
    workspaceDocument, conversation, memory, toolArgument }),
  descriptors: Object.freeze([{ id: 'api-key', kind: 'api-key', digest }])
}
```

Raw values are internal run inputs only. They must not be accepted from CLI/configuration and must not be attached to errors.

- [ ] **Step 5: Implement allowlisted evidence normalization**

Normalize only these collections: `stages`, `networkAttempts`, `dnsQueries`, `processes`, `fileEvents`, `canaryEvents`, `policyViolations`, `limitations`, and `failures`. Bound depth, text bytes, items per list, and total events using `DYNAMIC_HARD_LIMITS`. Canonically sort object keys before hashing so equivalent evidence has one digest.

- [ ] **Step 6: Test and commit**

```powershell
node --test --test-name-pattern='dynamic canary|dynamic evidence' test/dynamic-analysis.test.js
git add engine/dynamic/canaries.js engine/dynamic/evidence.js test/dynamic-analysis.test.js
git commit -m "feat: add synthetic canaries and evidence redaction"
```

---

## Task 4: Implement the orchestrator state machine and fake backend seam

**Files:**

- Create: `engine/dynamic/orchestrator.js`
- Create: `engine/dynamic/backend-resolver.js`
- Create: `test/helpers/fake-dynamic-backend.js`
- Modify: `test/dynamic-analysis.test.js`

- [ ] **Step 1: Write failing transition and cleanup tests**

Cover every terminal state:

```text
requested=false                         -> not-requested
requested=true, no production backend   -> unavailable
requested=true, preflight denied        -> refused
fake backend succeeds                   -> complete
fake backend stage/collect fails        -> incomplete
fake backend times out                   -> incomplete
fake backend cleanup uncertain          -> incomplete
```

Assert `cleanup` runs exactly once after any successful `prepare`, including stage failure, collection failure, timeout, and cancellation. Assert `prepare` is never called for unavailable or refused runs.

- [ ] **Step 2: Write the fake backend**

The test helper implements the approved interface and records calls:

```js
class FakeDynamicBackend {
  async available() {}
  async prepare(runSpec) {}
  async runStage(handle, stageSpec) {}
  async collect(handle) {}
  async cleanup(handle) {}
}
```

Constructor fixtures select availability, evidence, per-method errors, delay, and cleanup certainty. It must not spawn processes or access the network.

- [ ] **Step 3: Confirm transition tests fail**

```powershell
node --test --test-name-pattern='dynamic orchestrator' test/dynamic-analysis.test.js
```

- [ ] **Step 4: Implement the Phase A resolver**

`resolveDynamicBackend({ backendName, injectedBackend })` returns the injected backend only when supplied by the in-process caller. Without injection it returns a frozen capability result with `available:false` and reason code `backend-not-implemented-phase-a`. It must not inspect environment variables, engine contexts, sockets, executables, or the network.

- [ ] **Step 5: Implement preflight and orchestration**

Export:

```js
export const DYNAMIC_STAGES = Object.freeze(['load', 'registration', 'invocation'])

export function evaluateDynamicPreflight({ scanComplete, entrypoints, blockers = [] }) {}

export async function runDynamicAnalysis({
  target, options, backend = null, preflight, signal = null
}) {}
```

Rules:

- Refuse when static core scanning is incomplete, no entrypoint is resolvable, or an explicit high-risk blocker exists.
- Generate a unique run ID and canary set only after availability and preflight pass.
- Pass a frozen run specification to `prepare`.
- Execute only the fixed stages under the bounded timeout and optional abort signal.
- Normalize all returned evidence before constructing the layer.
- Always clean an acquired handle in `finally`.
- Convert errors to bounded reason codes; never include raw error stacks or backend output.
- A cleanup result other than `{ complete: true }` forces `status:'incomplete'`.

- [ ] **Step 6: Test and commit**

```powershell
node --test --test-name-pattern='dynamic orchestrator' test/dynamic-analysis.test.js
git add engine/dynamic/orchestrator.js engine/dynamic/backend-resolver.js test/helpers/fake-dynamic-backend.js test/dynamic-analysis.test.js
git commit -m "feat: add dynamic analysis state machine"
```

---

## Task 5: Integrate dynamic states into scanning and exit semantics

**Files:**

- Modify: `engine/index.js`
- Modify: `bin/sentinel.mjs`
- Modify: `test/dynamic-analysis.test.js`
- Modify: `test/professional-contract.test.js`

- [ ] **Step 1: Write failing scan integration tests**

Prove these externally visible outcomes:

```js
const staticOnly = await scan(fixture)
assert.equal(staticOnly.analysisLayers.dynamic.status, 'not-requested')
assert.equal(staticOnly.summary.scanComplete, true)

const unavailable = await scan(fixture, { dynamic: true })
assert.equal(unavailable.analysisLayers.dynamic.status, 'unavailable')
assert.equal(unavailable.summary.dynamicRequested, true)
assert.equal(unavailable.summary.dynamicComplete, false)
assert.equal(unavailable.summary.scanComplete, true)
```

Inject the fake backend directly into `scan` and prove a complete run populates normalized evidence while preserving the static verdict. Test a static traversal failure plus `dynamic:true` yields `refused`.

- [ ] **Step 2: Add the orchestrator call after static analysis**

Call `runDynamicAnalysis` only after the static scan has produced findings, core completeness, and resolved runtime entrypoints. Pass the internal test seam as `opts.dynamicBackendAdapter`; never serialize it, merge it from config, or accept it through CLI.

Attach the returned object as `analysisLayers.dynamic`. Do not convert Phase A evidence into findings; dynamic finding families belong to Phase C.

- [ ] **Step 3: Write failing CLI exit tests**

Use the existing CLI subprocess helper to assert:

```text
no --dynamic                                      -> existing exit behavior
--dynamic                                         -> report unavailable, exit 0 by default
--dynamic --fail-on-incomplete                    -> exit 3
--dynamic --strict-exit-codes                     -> exit 3
invalid --dynamic-backend/--dynamic-profile       -> usage exit
```

Default exit zero for unavailable dynamic analysis preserves opt-in reporting usability; strict modes enforce a complete requested deep scan.

- [ ] **Step 4: Implement separate deep-scan exit gating**

Use:

```js
const dynamicIncomplete =
  output.analysisLayers?.dynamic?.requested === true &&
  output.analysisLayers.dynamic.complete !== true

if ((opts.failOnIncomplete || opts.strictExitCodes) &&
    (output.summary.scanComplete === false || dynamicIncomplete)) {
  return 3
}
```

Text output must state the dynamic status and explicitly say that unavailable/refused/incomplete is not a successful deep verdict.

- [ ] **Step 5: Test and commit**

```powershell
node --test --test-name-pattern='dynamic scan|dynamic CLI' test/dynamic-analysis.test.js
node --test --test-name-pattern='professional report' test/professional-contract.test.js
git add engine/index.js bin/sentinel.mjs test/dynamic-analysis.test.js test/professional-contract.test.js
git commit -m "feat: integrate opt-in dynamic analysis states"
```

---

## Task 6: Document Phase A and run release-grade verification

**Files:**

- Modify: `README.md`
- Create: `README.zh-CN.md`
- Modify: `docs/architecture.md`
- Modify: `SECURITY.md`
- Modify: `.final-test.txt`
- Modify: `.final-bench.txt`

- [ ] **Step 1: Update English documentation first**

Document:

- dynamic analysis is experimental, opt-in, and unavailable until Phase B;
- Phase A never executes plugin code or starts a container;
- the four CLI options and bounded timeout;
- static and dynamic completeness are independent;
- unavailable/refused/incomplete deep scans require strict flags to fail CI;
- no host-execution fallback will ever be used.

Keep English README as the primary detailed document and link the Chinese README from its language selector. Synchronize the same security guarantees in Chinese without moving Chinese ahead of English.

- [ ] **Step 2: Update architecture and security boundaries**

Record the Phase A state machine, injected fake backend, redaction boundary, immutable limits, and deliberate production-unavailable resolver. State that Docker/Podman implementation starts only in Phase B after audit.

- [ ] **Step 3: Run syntax and focused checks**

```powershell
node --check engine/dynamic/contracts.js
node --check engine/dynamic/policy.js
node --check engine/dynamic/canaries.js
node --check engine/dynamic/evidence.js
node --check engine/dynamic/backend-resolver.js
node --check engine/dynamic/orchestrator.js
node --check engine/index.js
node --check bin/sentinel.mjs
node --test --test-name-pattern='dynamic' test/dynamic-analysis.test.js test/professional-contract.test.js
```

- [ ] **Step 4: Run the complete verification suite**

```powershell
& 'C:\nvm4w\nodejs\npm.cmd' test 2>&1 | Tee-Object -FilePath .final-test.txt
& 'C:\nvm4w\nodejs\npm.cmd' run benchmark 2>&1 | Tee-Object -FilePath .final-bench.txt
& 'C:\nvm4w\nodejs\npm.cmd' run verify:release
& 'C:\nvm4w\nodejs\npm.cmd' pack --dry-run
& 'C:\nvm4w\nodejs\npm.cmd' audit --offline
```

The full test run must report zero failures and zero skipped tests. Benchmark precision/recall must not regress below the repository's current recorded gate.

- [ ] **Step 5: Prove Phase A cannot execute untrusted code**

Search the new production modules and inspect every hit:

```powershell
rg -n "child_process|execFile|spawn|Docker|Podman|docker|podman|shell\s*:|http:|https:|net:|dgram:" engine/dynamic engine/index.js
```

Expected production behavior: no process or network invocation. Documentation and unavailable reason strings may mention Docker/Podman.

- [ ] **Step 6: Request independent security review**

Assign a Sol audit focused on state invariants, secret leakage, timeout/cleanup behavior, malformed evidence, option smuggling, static/dynamic completeness separation, and proof that no real execution path exists. Address every high or critical issue before integration. If Sol capacity is unavailable, preserve the audit as an explicit release gate and do not advance to Phase B execution.

- [ ] **Step 7: Commit documentation and verification evidence**

```powershell
git add README.md README.zh-CN.md docs/architecture.md SECURITY.md .final-test.txt .final-bench.txt
git commit -m "docs: document dynamic analysis phase a"
git status --short
git log --oneline --decorate -8
```

Expected: clean feature worktree with Phase A commits ready for review and integration.
