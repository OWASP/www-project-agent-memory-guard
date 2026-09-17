# Threat Model

This threat model covers the AMG library and optional local REST service. It should be read with the [architecture](design.md) and [security assurance case](assurance-case.md). It does not claim complete prevention, independent validation, or security of the surrounding agent platform.

## Protected assets

| Asset | Security concern |
|---|---|
| Memory values | Poisoning, unauthorized change, unintended disclosure, stale or cross-task use. |
| Policy and protected-key configuration | Modification that weakens screening or enforcement. |
| Classification and source metadata | Forged or incorrect labels that influence detectors, promotion, or investigation. |
| Integrity baselines | Loss, reset, or inconsistency that prevents detection of later changes. |
| Quarantine and snapshots | Sensitive-content exposure, unreviewed release, unsafe rollback, or loss on restart. |
| Security events and receipt pointers | Missing, forged, sensitive, misleading, or unprotected telemetry. |
| API and release configuration | Unauthenticated network exposure, dependency compromise, or artifact/source mismatch. |

## Actors and data sources

Untrusted or potentially untrusted data can originate from a user, external tool, retrieved document, another agent, model-generated content, imported memory, API client, or compromised dependency. An operator or integration may also make an unsafe configuration choice or supply inaccurate source, class, task, verification, or receipt metadata.

AMG does not establish principal identity. Labels such as `system`, `verified_preference`, or `policy` are caller-supplied metadata and must not be treated as authenticated authority without a control outside AMG.

## Trust boundaries

```text
Untrusted content and metadata
          |
          v
TB-1  Application/framework integration
      - decides which calls are mediated
      - supplies key, policy, source/class/task metadata
          |
          v
TB-2  MemoryGuard process
      - classification and detector state
      - policy decision
      - integrity, quarantine, snapshots and events
          |
          +------------------+
          |                  |
          v                  v
TB-3  Backing store       TB-4  Logs/SIEM/callbacks

Optional network deployment:
client -> TB-0 unauthenticated FastAPI surface -> TB-1
```

**TB-0: Network boundary.** The optional server accepts untrusted requests. It binds to loopback by default and does not provide built-in authentication, authorization, tenant isolation, rate limiting, or TLS.

**TB-1: Integration boundary.** The surrounding application determines whether all relevant memory operations flow through AMG. Direct store access bypasses screening.

**TB-2: Process boundary.** Integrity baselines, classifications, quarantine, events, and default snapshots are process-local unless an integration persists or exports them. Restart and multi-process behavior must be designed explicitly.

**TB-3: Storage boundary.** The backing store is trusted to enforce its own access control, confidentiality, availability, backup, and consistency. AMG does not encrypt stored values.

**TB-4: Telemetry boundary.** Event handlers and external logging systems may receive sensitive content or metadata. They require separate access, retention, and transport controls.

## Threats and current controls

| ID | Threat or failure | Current AMG controls | Residual limitation |
|---|---|---|---|
| T1 | Direct or indirect prompt injection is written to memory and influences later agent behavior. | Prompt-injection detector; policy can allow, redact, quarantine, or block; events and snapshots. | Heuristic patterns can miss encoded, novel, multilingual, or context-dependent attacks. Default policy is permissive. |
| T2 | Sensitive content is stored or returned. | Sensitive-data detector; strict/tiered/custom rules can redact or block; read-path screening. | Pattern coverage is incomplete. Store, snapshot, quarantine, event, and log confidentiality are external responsibilities. |
| T3 | Protected configuration or identity-like keys are modified or deleted. | Configured protected-key patterns; strict/tiered rules; deletion guard; optional immutable baselines. | Protection depends on correct key patterns and policy. No caller authorization is performed. |
| T4 | Memory is changed outside AMG. | A mediated read can compare configured immutable-key values with active SHA-256 baselines. | Direct access is not prevented. Keys without baselines and baselines lost on restart are not covered. |
| T5 | Content from one task contaminates another task. | Caller-supplied task context and cross-task detector. | Task identifiers are not authenticated and state is process-local. |
| T6 | Repeated agent-authored writes reinforce a poisoned belief. | Self-reinforcement detector tracks repeated similar agent-authored writes; independent writes can decay the cool-down. | Source class is caller-supplied. Unknown provenance must not be silently treated as trusted external evidence. |
| T7 | Untrusted memory is promoted to a higher-trust class. | Allowlisted promotion graph; selected transitions require an explicit verification flag; in-place reclassification is rejected. | The verifier’s identity and authority are outside AMG. |
| T8 | An attacker bypasses the library or uses an integration that guards only part of the path. | Framework adapters and examples show explicit wrapping; architecture documents the mediation requirement. | AMG cannot automatically intercept unknown or direct persistence paths. |
| T9 | The optional API is exposed to untrusted networks. | Loopback bind by default; CORS disabled unless explicitly configured. | No built-in authentication, authorization, TLS, tenant isolation, or rate limiting. An external gateway is required for non-loopback use. |
| T10 | A malicious or compromised dependency/workflow changes build or release behavior. | Dependabot, Scorecard, static analysis, CI, review, and planned immutable action references. | Pinning and review must cover workflows and the root composite action; package and transitive dependency trust remains. |
| T11 | Events or receipt metadata create false assurance. | Structured event schema and explicit receipt pointer. | No-finding operations may not emit events. Receipt URIs are not retrieved or cryptographically verified. |
| T12 | A rollback or retirement operation removes or restores the wrong state. | Pre-action snapshots and protected-key checks. | Snapshot protection, persistence, authorization, and multi-process consistency depend on deployment. |
| T13 | Documentation or benchmarks cause unsafe configuration or exaggerated trust. | Release notes, currentness gate, reproducible scripts, explicit limitations. | Project-authored tests and benchmarks are not independent audits; stale docs are a release blocker until corrected. |

## Security assumptions

AMG’s intended properties depend on all of the following:

1. Relevant memory reads, writes, deletes, promotions, and lifecycle operations are routed through AMG.
2. The application selects and tests an enforcement policy suitable for its own key namespaces and risks.
3. Caller-supplied source, class, task, and verification metadata is validated or authenticated by the integration when the deployment relies on it.
4. The backing store and telemetry systems have appropriate access control, confidentiality, availability, and retention controls.
5. A non-loopback API deployment adds authenticated and authorized TLS termination, rate limiting, network isolation, and tenant controls.
6. Maintainers keep dependencies, documentation, tests, and detector behavior current and disclose known limitations.

## Abuse and misuse cases to test

Release and integration tests should include: direct and indirect injection; encoded or obfuscated payloads; protected-key wildcard edge cases; unknown source provenance; repeated agent-authored writes interrupted by user/tool writes; cross-task identifiers; invalid class transitions; process restart with persistent backing values; direct-store modification followed by mediated read; sensitive data on both write and read paths; oversized and rapidly changing values; malformed API input; non-loopback server configuration; CORS configuration; shell or workflow injection; and logging/snapshot leakage.

Tests should identify the exact version, commit, policy, detector set, corpus, and environment. Project-authored results must be labeled as such.

## Residual risk

AMG reduces some memory-layer risks when it is correctly integrated and configured. It does not prove that content is safe, establish principal identity, prevent store bypass, guarantee detector recall or precision, secure an exposed server, provide encryption or tenant isolation, verify receipt URIs, or certify compliance. Applications remain responsible for authorization, network and storage security, secret management, monitoring, incident response, and deployment-specific validation.

## Review triggers

Review this model whenever a release changes policy defaults, detector composition, source or memory classes, promotion rules, server exposure, storage or restart semantics, event contents, snapshot behavior, dependency/release controls, or supported integrations.
