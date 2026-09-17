# Security Assurance Case

## Status and scope

This document explains the security properties that OWASP Agent Memory Guard (AMG) is designed to provide, the evidence supporting those properties, and the limits of that assurance. It applies to the tagged AMG version named by a release that links to this document. It is **not** a certification, penetration test, guarantee, or claim that AMG prevents every agent-memory attack.

AMG is a Python library and optional local REST service that mediates memory operations explicitly routed through `MemoryGuard`. The assurance boundary does not include the surrounding model, agent framework, tool execution system, identity provider, network perimeter, operating system, package registry, or a backing store accessed outside AMG.

## Security objectives

| ID | Objective | Intended property | Evidence | Important limit |
|---|---|---|---|---|
| SR-1 | Mediated memory writes | A write passed to `MemoryGuard.write` is evaluated by the configured detectors and policy before it is stored, quarantined, redacted, or rejected. | [`guard.py`](../../src/agent_memory_guard/guard.py), policy tests | Direct writes to the backing store bypass AMG. The default policy is permissive and does not actively block most findings. |
| SR-2 | Mediated memory reads | A read passed to `MemoryGuard.read` verifies a registered integrity baseline, runs detectors, applies the configured policy, and may return, redact, or reject the value. | [`guard.py`](../../src/agent_memory_guard/guard.py), read/integrity tests | A key with no integrity baseline cannot receive baseline verification. Direct reads bypass AMG. |
| SR-3 | Protected-key handling | Keys matching configured protected patterns are checked for protected-key modification/deletion, and strict/tiered policies can block those operations. | [`policy.py`](../../src/agent_memory_guard/policies/policy.py), protected-key detector and regression tests | Protection depends on the configured patterns and policy. `Policy.permissive()` is the default. |
| SR-4 | Heuristic threat screening | The default detector suite examines prompt-injection patterns, sensitive-data patterns, size/rate anomalies, protected keys, cross-task context, and self-reinforcement behavior. | Detector sources under [`src/agent_memory_guard/detectors`](../../src/agent_memory_guard/detectors), automated tests | Detectors are heuristic. Novel, encoded, contextual, or adversarial inputs may evade detection; benign inputs may be flagged. |
| SR-5 | Classification transitions | When callers use memory classes, AMG rejects an in-place reclassification and allows only transitions represented in the promotion graph, including explicit verification where configured. | [`classification.py`](../../src/agent_memory_guard/classification.py), classification tests | Class labels and verification decisions are supplied by the caller; AMG does not authenticate the human or service asserting them. Classification state is process-local unless an integration persists it. |
| SR-6 | Integrity evidence | AMG records SHA-256 baselines for configured immutable keys and raises an integrity error when a later mediated read does not match the in-process baseline. | Integrity registry and guard tests | This is tamper detection, not encryption or access control. Baselines are process-local by default and are lost on restart. |
| SR-7 | Security-event evidence | AMG emits structured events for blocked, quarantined, redacted, integrity-failed, or allowed-with-findings operations. | [`events.py`](../../src/agent_memory_guard/events.py), event tests | An operation with no finding does not necessarily emit an event. Event storage/export and log confidentiality are deployment responsibilities. |
| SR-8 | Safer local API defaults | `amg serve` binds to loopback by default and does not enable browser CORS unless explicitly configured. | [`cli.py`](../../src/agent_memory_guard/cli.py), [`server.py`](../../src/agent_memory_guard/server.py), server tests | The API has no built-in authentication or TLS. Non-loopback exposure requires an authenticated, TLS-terminating gateway and network controls. |

## Architecture and trust boundaries

```text
Untrusted or caller-controlled data
  user input | tool output | retrieved content | agent-authored content
                              |
                              v
                    application integration
                 (chooses key, class, source label,
                  task identifier and policy)
                              |
                    TB-1: library API boundary
                              |
                              v
 +----------------------------------------------------------------+
 | MemoryGuard                                                     |
 |  classification check -> detector pipeline -> policy decision   |
 |  -> allow/redact/quarantine/block -> event/snapshot handling     |
 +----------------------------------------------------------------+
          |                         |                         |
   TB-2: storage boundary   TB-3: telemetry boundary  TB-4: config boundary
          |                         |                         |
 backing MemoryStore        handlers/SIEM/logs         policy and detector setup
```

The optional FastAPI surface adds a network boundary before the application integration. Requests reaching that service are untrusted. The server is intended for local use by default; AMG does not supply principal authentication, authorization, rate limiting, tenant isolation, or TLS termination.

### Assets

The principal assets are memory values, protected policy/configuration keys, integrity baselines, classification/task metadata, quarantine contents, snapshots, security events, and deployment configuration. Some of these may contain sensitive content. AMG does not encrypt those assets at rest; the application and storage backend must provide confidentiality, access control, backup, retention, and deletion.

### Trust decisions

`SourceClass`, legacy `SourceType`, `MemoryClass`, `task_id`, `receipt_uri`, and any verification result supplied by an integration are metadata, not authenticated identity. The current library carries or evaluates those values but does not verify that the caller is authorized to assert them. `receipt_uri` is a correlation pointer; AMG does not fetch or cryptographically verify the referenced receipt.

The backing store is trusted not to bypass the wrapper. If another component writes directly to the store, AMG can detect a mismatch only for keys that have an active integrity baseline and are later read through AMG. Availability, rollback safety, and multi-process consistency depend on the selected store and integration.

## Secure-design argument

### Complete mediation within the documented boundary

The main control is explicit interposition: integrations call `MemoryGuard.write`, `read`, `delete`, or promotion/lifecycle methods instead of touching the store directly. The write path resolves source metadata, checks class transitions, runs detectors, asks the policy for an action, and only then commits, quarantines, redacts, or raises. The read path verifies integrity when a baseline exists, runs detectors, and applies the policy before returning a value.

This argument is limited to mediated calls. AMG cannot transparently intercept an unknown framework’s direct persistence calls. Integration documentation must therefore identify the actual call sites placed behind the guard.

### Least privilege and fail-safe deployment

The command-line server binds to loopback by default and cross-origin browser access is disabled unless an operator supplies allowed origins. This reduces accidental network exposure. Because the service has no built-in authentication or TLS, documentation requires a separately managed authenticated gateway before non-loopback use.

The library’s default policy is intentionally permissive for compatibility. It detects and records findings but does not create a fail-closed guarantee. Applications requiring enforcement must select and test a strict, tiered, or custom policy. Documentation and examples must not imply blocking when the default constructor is used.

### Defense in depth

AMG combines several independent mechanisms: heuristic content detectors, key-pattern protection, policy action mapping, optional memory classification/promotion rules, integrity baselines, quarantine, snapshots, and structured events. These controls address different failure modes but are not independent security principals. A shared integration error, unsafe policy, direct-store bypass, forged metadata, or detector evasion can affect multiple layers.

### Minimize and validate input

Policy parsing validates supported actions and key-dependent rules. Classification transitions are allowlisted. Server request models place structural constraints on network input. Detectors normalize and inspect values according to their documented capabilities. However, the project does not claim that every untrusted input across every optional integration is fully validated. Open input-handling and shell/workflow findings must be resolved and covered by regression tests before the OpenSSF Silver input-validation criterion is marked met.

### Transparency and recoverability

Security-relevant decisions can produce structured events. Quarantine and snapshots support investigation and rollback within the active process and selected store. Release notes, public issues, and regression tests document known corrections. These mechanisms do not replace an append-only audit log, secure external backup, or a deployment-specific incident-response plan.

## Common weakness countermeasures

| Weakness area | Current countermeasure | Verification | Residual work |
|---|---|---|---|
| Injection and unsafe memory content | Pattern and optional ML detectors; policy actions | Detector tests and project benchmark | Independent evaluation; encoded/contextual bypass testing; preserve benchmark limitations. |
| Sensitive-data persistence or output | Sensitive-data detector and redact action | Unit tests | Patterns are incomplete; logs, snapshots, quarantine, and backing stores still require data controls. |
| Protected configuration mutation | Protected-key detector and configured strict/tiered rules | Regression tests | Protected namespaces are configuration-dependent; caller authorization is not authenticated. |
| Cross-task contamination | Task metadata and detector | Unit tests | Task identifiers are caller-supplied and process-local. |
| Self-reinforcement | Source-aware repetition detector with independent-write decay | Regression tests | Source labels are caller-supplied; pending trust-boundary improvements must not treat unknown provenance as trusted. |
| Supply-chain reference drift | Dependabot/Scorecard and planned immutable action pinning | Public workflows and pinning regression test | Pinning must cover both workflows and the root composite action and be kept current. |
| Code defects | CI, Ruff, mypy, pytest, coverage, Semgrep | Public checks | Coverage must be enforced at the claimed threshold; non-blocking checks must not be described as enforced. |
| Vulnerability handling | Public policy and private/fallback report route | [`SECURITY.md`](../../SECURITY.md) | Verify the private channel is enabled and that at least two responders can access it. |
| Release tampering | HTTPS distribution and tagged releases | GitHub/PyPI records | Reproducible builds and cryptographic release signing/verification are not yet established. |

## Verification evidence

The release gate should record: the exact commit and version; supported Python matrix; unit/regression results; statement and branch coverage; lint and type-check status; Semgrep and dependency-monitoring results; package build/install checks; documentation-currentness review; unresolved security/correctness items; and whether artifacts are reproducible and signed. Contributor-reported results are useful but are not a substitute for project CI or independent review.

Project-authored benchmarks must identify the corpus, version, environment, method, and limitations. They must not be described as independent validation. External references, reproductions, integrations, audits, and adoptions should be characterized only as stated by the external source.

## Residual-risk statement

AMG can reduce risk when it is correctly placed on the memory path and configured for the deployment. It does not establish the identity or authority of the calling principal, secure direct access to the store, guarantee detector recall or precision, make an unauthenticated server safe for public exposure, provide tenant isolation, encrypt stored data, verify external receipt URIs, or certify compliance. The application owner remains responsible for architecture, policy choice, authentication/authorization, network security, secret management, storage security, monitoring, incident response, and validation against its own threat model.

## Maintenance

This assurance case must be reviewed when a release changes policy defaults, detector composition, trust metadata, server exposure, storage behavior, integrity semantics, or release controls. Known contradictions between this document, user documentation, and code are release blockers for a security-relevant release.
