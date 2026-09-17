# Architecture

This document describes the high-level design of OWASP Agent Memory Guard (AMG) as implemented in the current v0.3.x line. The [security assurance case](assurance-case.md) explains the corresponding security objectives, evidence, and limitations.

## Design principles

1. **Explicit mediation** — applications receive AMG’s controls only when they route memory operations through `MemoryGuard` or an integration that does so.
2. **Layered controls** — content detectors, key protection, policy actions, classification rules, integrity baselines, quarantine, snapshots, and events address different failure modes.
3. **Configurable enforcement** — the default policy is deliberately permissive for compatibility. Applications that require blocking must select and test a strict, tiered, or custom policy.
4. **Pluggable storage and integrations** — `MemoryGuard` accepts a compatible `MemoryStore`; framework adapters must document which actual read/write paths they mediate.
5. **Evidence with bounded claims** — project tests and benchmarks are reproducible project evidence, not guarantees or independent certification.

## Component view

```text
Application or framework integration
  chooses key/value, policy, source label, class and task context
                              |
                              v
+-------------------------------------------------------------------+
| MemoryGuard                                                       |
|                                                                   |
|  classification/promotion registry                                |
|               |                                                   |
|               v                                                   |
|  detector pipeline -> policy decision -> allow/redact/quarantine/ |
|                                      block                        |
|               |                      |                            |
|               v                      v                            |
|  integrity registry          events and callbacks                 |
|  snapshot store              quarantine                           |
+-------------------------------------------------------------------+
             |                         |
             v                         v
      MemoryStore backend       application telemetry/response
```

The default detector list in `MemoryGuard` contains:

- `PromptInjectionDetector`;
- `SensitiveDataDetector`;
- `SizeAnomalyDetector`;
- `RapidChangeDetector`;
- `ProtectedKeyDetector` configured from the active policy;
- `CrossTaskContaminationDetector`; and
- `SelfReinforcementDetector`.

Callers may supply a custom detector collection. AMG ensures that protected-key, cross-task, and self-reinforcement detectors are still present, but other optional detectors are not part of the default suite merely because they exist in the repository.

## Write path

```text
MemoryGuard.write(key, value, metadata)
  1. Normalize source metadata supplied by the caller.
  2. If a memory class is supplied, reject an in-place reclassification.
  3. Run the configured detector pipeline.
  4. Select the highest relevant finding and apply the configured policy.
  5a. BLOCK      -> emit an event, optionally capture a snapshot, raise.
  5b. QUARANTINE -> retain the candidate in the in-process quarantine, emit, return.
  5c. REDACT     -> transform the candidate, emit, then store.
  5d. ALLOW      -> store; emit only when findings are present.
  6. Update process-local classification, integrity, and self-reinforcement state.
```

The default policy is `Policy.permissive()`, whose fallback action is `allow`. `Policy.strict()` and `Policy.tiered()` add detector-specific rules but also retain `allow` as the fallback when no rule applies. Integrators must test the selected policy against their own key namespaces and threat model.

## Read and delete paths

A mediated read first verifies an active integrity baseline for the key, retrieves the value, runs the configured detectors, applies the policy, and then returns, redacts, or rejects the result. A read with no finding normally produces no `SecurityEvent`.

A mediated delete is rejected when the key matches a configured protected-key pattern. Otherwise AMG clears the backing value and its process-local integrity, classification, and self-reinforcement metadata.

## Policy engine

A policy contains ordered detector rules, a fallback action, protected-key patterns, immutable-key patterns, and a syntax version. Rules can be scoped by detector, minimum severity, and key pattern. The first applicable rule supplies the action. Policy parsing validates recognized actions and rejects key-dependent rules that cannot become effective because the corresponding protected/immutable configuration is absent.

Policy configuration is not principal authorization. AMG does not authenticate who supplied a policy or prove that a caller may assign a source label, task identifier, memory class, or verification result.

## Memory classes and source classes

AMG tracks two different forms of caller-supplied metadata:

| Concept | Current values | Use |
|---|---|---|
| `SourceClass` | `external_tool`, `user_input`, `agent_authored`, `system`, `unknown` | Self-reinforcement analysis and event correlation. |
| `MemoryClass` | `ephemeral`, `user_preference_candidate`, `verified_preference`, `retrieved_fact`, `tool_observation`, `policy` | Process-local classification and allowlisted promotion transitions. |

The default promotion graph permits only defined transitions and marks the candidate-to-verified-preference transition as requiring verification. The integration supplies the verification result; AMG does not authenticate an external verifier. Source and memory classes are not trust tokens.

## Storage and process state

`InMemoryStore` is the default backing store. `RedisMemoryStore` is provided as an optional persistent backend, and applications may implement the `MemoryStore` interface for another backend.

The classification registry, integrity baselines, quarantine, event list, and default snapshot store are maintained by the `MemoryGuard` process unless an integration explicitly persists or exports them. A process restart can therefore remove that local security state even when the backing memory values persist. Multi-process deployments need a deliberate consistency design; the library does not provide distributed coordination by default.

AMG does not encrypt backing-store values, snapshots, quarantine contents, or events. Confidentiality, access control, retention, backup, and deletion are responsibilities of the application and selected storage/telemetry systems.

## Integrity and snapshots

Configured immutable keys can receive SHA-256 baselines. A later mediated read raises an integrity error when the current serialized value does not match the active baseline. This detects some out-of-band modification; it does not prevent direct-store access, establish caller identity, or encrypt the data.

When `snapshot_on_block=True`, a blocked write captures a snapshot of the current store before raising. Lifecycle retirement also captures a pre-retirement snapshot. These support investigation and rollback in the active configuration but do not create an append-only compliance log or protected backup.

## Events

`SecurityEvent` records include an event identifier, timestamp, detector, severity, action, operation, key, message, source metadata, optional receipt URI, and additional metadata. Events are emitted for blocks, quarantine, redaction, integrity failures, and allowed operations with findings. They are not emitted for every successful no-finding operation.

A `receipt_uri` is carried for correlation only. AMG does not retrieve or cryptographically verify the referenced object.

## Optional REST server

The FastAPI server exposes scanning, guarded memory, event, health, and administrative reset behavior. The command-line server binds to `127.0.0.1` by default, and browser CORS is disabled unless origins are explicitly configured.

The server does not implement built-in principal authentication, authorization, tenant isolation, rate limiting, or TLS. It must not be exposed on a non-loopback interface unless a deployment supplies an authenticated, authorized, TLS-terminating gateway and appropriate network controls. The API is a local integration surface, not a production security perimeter by itself.

## Deployment boundary

AMG cannot protect:

- memory operations that bypass `MemoryGuard`;
- direct access to the backing store;
- a compromised application process or unsafe integration;
- forged caller-supplied source, class, task, or verification metadata;
- network exposure of the unauthenticated API server;
- secrets copied into events, snapshots, quarantine, or an insecure backend;
- attacks outside the configured detector and policy behavior; or
- availability and consistency failures in external services.

Applications should document their actual call path, select an enforcement policy deliberately, isolate the backing store, secure telemetry, test restart behavior, and validate controls against a deployment-specific threat model.
