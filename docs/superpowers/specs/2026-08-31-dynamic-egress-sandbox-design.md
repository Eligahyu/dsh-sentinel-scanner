# Dynamic Egress Sandbox Design

Date: 2026-08-31
Status: Approved

## 1. Objective

Extend dsh-sentinel from a static plugin scanner into a hybrid security scanner
that can also observe controlled runtime behavior. Dynamic analysis must detect
network egress, data exfiltration, child-process activity, and behavior that is
not statically provable without ever running an untrusted plugin directly on the
host.

The first implementation targets Linux containers through Docker or Podman.
Windows and macOS hosts may use those backends when available; otherwise dynamic
analysis is unavailable and the scanner remains static-only. The scanner must
never silently fall back to host execution.

## 2. Non-goals

- Proving that a plugin is safe because a finite run observed no malicious act.
- Installing dependencies or running package-manager lifecycle scripts.
- Giving an untrusted runner privileged access, host networking, credentials,
  Docker/Podman sockets, or the user's real workspace.
- Executing native binaries that the static preflight classifies as high risk.
- Providing a microVM backend in the first release.
- Allowing arbitrary Internet access during the default dynamic profile.

## 3. Threat model

The scanned package, every bundled dependency, and every artifact in the package
are untrusted. They may attempt to:

- read secrets, memory, conversation data, SSH keys, cloud credentials, or host
  files;
- exfiltrate through HTTP(S), WebSocket, DNS, raw TCP, UDP, TLS, proxies,
  redirects, child-process tools, or encoded destinations;
- access localhost, private networks, link-local services, the Docker API, Unix
  sockets, or cloud metadata services;
- consume excessive CPU, memory, processes, files, output, or network events;
- detect instrumentation, disable JavaScript hooks, launch subprocesses, or use
  native modules to bypass language-level observation;
- leave persistent containers, networks, volumes, or temporary files.

Linux containers reduce exposure but are not equivalent to microVMs. Static
preflight blocks execution when the package contains high-risk native artifacts
or other signals outside the accepted container threat boundary.

## 4. Architecture

Dynamic analysis uses two short-lived containers on a unique, isolated network.

### 4.1 Untrusted runner

The runner loads and exercises the plugin. It is non-root, drops all Linux
capabilities, enables `no-new-privileges`, uses a read-only root filesystem, and
has bounded tmpfs storage. The original source directory is never bind-mounted.
The scanner first creates a sanitized staging snapshot after containment checks,
excluding symlinks, hardlinks, sockets, devices, VCS metadata, worktrees, and
files outside the scan root. Only that snapshot is mounted read-only. The runner
receives only synthetic credentials, files, conversations, and canary values.

The runner never receives the container engine socket, host network, host PID or
IPC namespaces, host credentials, or the user's workspace. CPU, memory, PID,
file, output, and wall-clock limits are mandatory and cannot be disabled by CLI
options.

### 4.2 Trusted egress gateway

The gateway contains no untrusted package code. It is the only component with
the minimum network capabilities required for transparent observation and
enforcement (`NET_ADMIN` and `NET_RAW`). The runner shares or routes through the
gateway-controlled network namespace. The gateway records:

- DNS queries and answers;
- HTTP methods, destinations, redirects, headers selected by policy, and body
  size/digest/canary matches;
- HTTPS CONNECT targets and TLS SNI; optionally decrypted HTTP metadata when the
  runner accepts the per-run synthetic CA;
- raw TCP connection attempts, destination IP/port, and byte counts;
- UDP destination IP/port and bounded payload metadata;
- denied localhost, private, link-local, cloud metadata, Unix-socket, proxy, and
  tunneling attempts.

The default profile does not forward traffic to the public Internet. DNS returns
the gateway sink address and the gateway provides deterministic synthetic
responses. This exposes destination and exfiltration intent without contacting a
third party.

The gateway has no host mounts, engine socket, credentials, or host network. Its
capabilities are confined to its container and network namespaces. It uses a
separate seccomp profile, read-only filesystem, bounded logs, and mandatory
resource and wall-clock limits. Malformed runner traffic is hostile input to
every gateway parser.

### 4.3 Node observation probe

A read-only preload probe records high-level intent from Node APIs including
`fetch`, `http`, `https`, `net`, `tls`, `dgram`, `dns`, WebSocket APIs, file
access, environment access, and `child_process`. Events are written to an
append-only bounded channel controlled by the runner harness.

The probe is evidence enrichment, not the security boundary. Network policy is
enforced by the gateway even when the plugin detects, bypasses, or disables the
probe. Because plugin code executes in the same process, probe events are
untrusted and potentially suppressible or forgeable. They cannot create a
high-confidence finding without gateway, orchestrator, canary, or other
independent evidence. Conflicting events are reported as instrumentation
interference.

### 4.4 Orchestrator and backend interface

The engine owns a backend-neutral orchestrator. A backend implements:

```text
available() -> backend capability result
prepare(runSpec) -> isolated run handle
runStage(handle, stageSpec) -> bounded stage evidence
collect(handle) -> normalized evidence
cleanup(handle) -> idempotent cleanup result
```

Docker and Podman adapters build argument arrays and invoke their CLIs without a
shell. Backend output is size-bounded and parsed as untrusted input. Every
resource carries a unique run label so cleanup can target only resources created
by that run.

Runner and gateway images are trusted scanner assets pinned by immutable digest.
Dynamic analysis never pulls or builds an image during a scan. Backends reject
remote Docker/Podman contexts and endpoints; the isolation backend must be local
to the scanner host. Rootless Podman is preferred when available.

## 5. Execution stages

Each stage runs in a fresh runner container so one stage cannot persist state
into the next.

1. **Load stage:** import the resolved plugin entry and record module-load
   behavior.
2. **Registration stage:** call the plugin's registration/apply entry with a
   minimal mock DSH context and capture registered tools and hooks.
3. **Invocation stage:** invoke discovered tool handlers with schema-derived
   synthetic inputs and canary data.

The orchestrator does not guess arbitrary application APIs. Unsupported plugin
contracts produce explicit stage limitations. A crash, timeout, event overflow,
probe failure, gateway failure, or cleanup uncertainty sets
`dynamicComplete=false`.

## 6. Static preflight gate

Static analysis always runs first. Dynamic execution is refused when preflight
finds conditions outside the first-release threat boundary, including:

- high-risk native executables or native Node modules selected for execution;
- container control sockets or explicit container-escape behavior;
- packages above configured hard artifact limits;
- unresolved entrypoints or incomplete core traversal;
- a missing, unsupported, or unhealthy isolation backend.

Refusal is a reportable result, not a scan crash. It does not erase static
findings and cannot be represented as a successful dynamic scan.

## 7. Canary model

All sensitive data is synthetic and unique per run. Canary classes include API
keys, bearer tokens, environment secrets, SSH-like files, workspace documents,
conversation text, memory records, and tool arguments. Reports contain canary
identifiers and evidence hashes, never full synthetic secret values.

An observed canary crossing a network, process, or persistence boundary creates a
high-confidence dynamic finding. Merely reading a canary is recorded separately
from transmitting it.

## 8. Findings and report schema

The professional report gains a stable `analysisLayers.dynamic` object:

```json
{
  "status": "not-requested | unavailable | refused | complete | incomplete",
  "complete": false,
  "backend": null,
  "profile": null,
  "stages": [],
  "networkAttempts": [],
  "dnsQueries": [],
  "processes": [],
  "fileEvents": [],
  "canaryEvents": [],
  "policyViolations": [],
  "limitations": [],
  "failures": [],
  "evidenceDigest": null
}
```

Initial dynamic finding families cover:

- canary-to-network exfiltration;
- DNS-based exfiltration or tunneling indicators;
- raw socket and unexpected protocol egress;
- child-process network tools and proxy/tunnel launch attempts;
- localhost, private network, cloud metadata, and Unix-socket access;
- undeclared dynamic capability observed at runtime;
- persistence attempts and dynamic-analysis interference.

Static and dynamic evidence are correlated into attack chains. Dynamic findings
use stable fingerprints derived from package identity, stage, event type,
destination class, and evidence location rather than ephemeral container IDs.

## 9. Verdict semantics

- Dynamic analysis is opt-in and disabled by default.
- Static completeness and dynamic completeness remain separate.
- A requested deep scan cannot report a fully successful deep verdict when
  `dynamicComplete=false`.
- No observed network traffic means only that the supplied stages and stimuli did
  not trigger traffic.
- A blocked attempt is still evidence of capability and intent.
- Dynamic evidence can raise risk and installation recommendations but cannot
  erase static findings.

## 10. CLI and configuration

The initial user-facing surface is intentionally small:

```text
--dynamic
--dynamic-backend auto|docker|podman
--dynamic-profile observe
--dynamic-timeout <bounded duration>
```

Hard security limits are centrally defined and only allow safer reductions.
Configuration may add declared destination policy and synthetic tool inputs but
cannot enable host execution, privileged runner mode, host networking, real
credentials, lifecycle scripts, or unrestricted Internet access.

GitHub Action integration is opt-in. Static scanning remains the default action
behavior.

## 11. Cleanup and failure handling

Cleanup runs on success, refusal, timeout, cancellation, parser failure, and
unexpected exceptions. It is idempotent and targets only the current run's
captured immutable container and network IDs. Labels are used only for recovery
and leak detection, never as the primary deletion authority. Cleanup uncertainty
is reported and makes dynamic analysis incomplete. A startup recovery pass may
report stale labeled resources but must not delete them unless ownership and age
are proven from scanner-created state.

The orchestrator records bounded stdout/stderr tails and structured reasons. It
must not include secrets, full request bodies, host absolute paths, or raw
container-engine diagnostics that may contain sensitive configuration.

## 12. Testing strategy

1. Unit tests use a fake backend and cover state transitions, limits, redaction,
   completeness, evidence normalization, and cleanup.
2. Argument-construction tests prove that Docker/Podman invocations include the
   required isolation flags and never use a shell.
3. Gateway/probe fixtures cover HTTP(S), redirects, DNS, TCP, UDP, TLS,
   WebSocket, child-process tools, private addresses, cloud metadata, canary
   transmission, event floods, crashes, and timeouts.
4. Container integration tests are opt-in and run without public Internet.
5. GitHub Actions runs static tests everywhere and a dedicated Linux dynamic
   smoke workflow when Docker is available.
6. Security review includes escape-oriented argument injection, cleanup races,
   output bombs, event spoofing, probe bypass, and gateway failure.

## 13. Delivery phases

### Phase A: contracts and fake backend

Add report contracts, policies, run state machine, synthetic canaries, evidence
normalization, fake backend tests, and CLI unavailable/refused semantics.

### Phase B: container runner

Add Docker/Podman capability detection, hardened runner creation, staged harness,
resource limits, labels, and idempotent cleanup. Network remains denied.

### Phase C: gateway and probe

Add DNS/HTTP(S)/TCP/UDP observation, Node preload events, canary correlation, and
dynamic findings. Public Internet remains disabled.

### Phase D: output and CI

Integrate JSON, SARIF, HTML, Action opt-in, dynamic smoke tests, documentation,
benchmarks, and independent security review.

MicroVM isolation, Windows Sandbox/Hyper-V, broader plugin-contract emulation,
and explicitly allowlisted live Internet replay remain future work.
