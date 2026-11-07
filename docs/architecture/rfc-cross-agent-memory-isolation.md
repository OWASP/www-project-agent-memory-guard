# RFC: Cross-Agent Memory Isolation and Trust Boundaries

**Status:** Proposal, under review in [#167](https://github.com/OWASP/www-project-agent-memory-guard/pull/167); nothing in this document is implemented.
**Target:** v1.0.0 strict-mode design. **Baseline:** [#166](https://github.com/OWASP/www-project-agent-memory-guard/pull/166); the existing six-method `MemoryStore` protocol remains unchanged.

!!! warning
    Strict isolation, grants, coordinator, recovery envelopes and audit APIs below are proposals only. This RFC must remain marked as a proposal until maintainer approval.

## Goals and deliberately narrow v1.0.0 scope

The proposal defines an opt-in isolation boundary for agents sharing one memory store, with bounded ownership, attributable provenance, recovery and fail-closed authorization. It does **not** implement any of those features in this RFC.

The initial implementation milestone is intentionally limited to:

- one **in-process coordinator** owning an **ephemeral strict-mode state**;
- a coordinator-created empty store at startup (no pre-existing strict records);
- handle-only strict operations with coordinator-bound identity and provenance;
- ambient identity disabled;
- the existing six-method `MemoryStore` interface unchanged;
- no strict enumeration, bulk API, lifecycle callback or framework-adapter support;
- `retire_if()` explicitly unsupported in strict mode;
- no distributed coordinator, persistent strict recovery, cryptographic identity system or sandbox for malicious Python in the trusted process.

`RedisMemoryStore` and other persistent deployments remain on phase-one rules. Enumeration, lifecycle callbacks, adapter certification and persistent recovery are later milestones, not v1.0.0 promises.

## Existing boundary and threats

This extends [phase one (#155)](https://github.com/OWASP/www-project-agent-memory-guard/pull/155). `AccessPolicy` currently performs registry checks, first-match rules, defaults and class gates; delete and promote use the writers list; `AgentHandle` rejects `principal=` but legacy entry points still accept several provenance-shaped arguments; task context is guard-wide. Snapshot and rollback are admin-only whole-store operations. `_emit()` handlers are best-effort. YAML access fields are not yet loadable.

[#166](https://github.com/OWASP/www-project-agent-memory-guard/pull/166) characterizes the limits of independent guards sharing values: local labels, locks and events are not a shared security boundary. Those findings remain documented limits, not a reason to alter the existing phase-one API.

| Threat | Proposal and residual risk |
| --- | --- |
| Bob reads or deletes Alice’s notes | Immutable owner binding and one coordinator predicate; raw-store access remains outside the boundary. |
| Independent guards race on labels or grants | Strict mode permits only one coordinator and serializes decisions and commits. |
| A writer poisons an authorized namespace | Provenance is bound to each version; strict reads expose it in a separate envelope. Authorized writers remain a residual trust risk. |
| Caller claims Alice, SYSTEM or another task | Trusted handles bind identity and provenance; untrusted overrides are rejected before authorization or detectors. |
| Revocation or recovery resurrects authority | Current authorization is applied to the restorer; historical provenance is preserved rather than re-authorized. |
| Audit failure hides a committed mutation | Operation ids, acknowledged intent/outcome, bounded retry and fencing distinguish known commits from uncertain effects. |

The deployment authority, coordinator, verifier and audit sink are trusted. Agent text, tool payloads and identity/provenance fields are untrusted.

## Strict policy and authorization

Strictness is policy-wide. A strict policy requires `default: deny`, a closed principal registry and `ambient_identity: false`. Legacy policies retain current first-match behavior. v1.0.0 has no grants; grants are a later milestone and cannot be inferred from ordinary admin status.

Strict key scopes are restricted to validated literal prefixes with either one `{owner}` segment or a literal owner. Matching is whole-key and case-sensitive. Owner binding is immutable and never assigned by first writer. A scope-less strict `snapshot()` is rejected: every future snapshot API must name an owner scope or an explicitly authorized custodian scope.

The single evaluator receives the trusted actor, operation, key, current/target class metadata and immutable policy revision. It must be the only authorization algorithm used by `allows()`, `decide()`, `explain()` and enforcement. Optional trace recording records steps but cannot affect the verdict.

### What `admins` controls

Under strict mode, `admins` controls only the explicitly named administrative operations: policy-defined snapshot capture, rollback and any future administrative operation that is separately added. It does **not** grant ordinary reads, writes, deletes, enumeration, bulk access, recovery scope or a right to inspect another owner’s metadata. An admin can therefore be denied a read of Alice’s notes.

The legacy POLICY and VERIFIED_PREFERENCE class gates continue to default to `admins`, exactly as phase one. Strict policy authors may replace either gate with an explicit `class_writers` selector. `class_writers` is not a selector context in which `{owner}` is valid today; `{owner}` remains valid only in a rule’s key-bound writers/readers. Therefore Alice can promote her own memory only if the policy explicitly names `alice` (or a role containing Alice) in the relevant class-writer entry; `admins: [supervisor]` alone does not make Alice a class writer.

`explain()` must not reveal last-writer or other provenance unless the caller first passes the ordinary read authorization for that key. Admin status does not change that rule. The strict API rejects scope-less `snapshot()` rather than treating admin status as permission for the whole store.

Illustrative **proposed** policy (not loadable today):

```yaml
access:
  isolation: strict
  default: deny
  ambient_identity: false
  principals:
    alice: []
    bob: []
    supervisor: [lead]
  admins: [supervisor]
  class_writers:
    policy: [supervisor]
    verified_preference: [supervisor, alice]
  rules:
    - name: private-notes
      keys: ["notes.{owner}.*"]
      readers: ["{owner}"]
      writers: ["{owner}"]
    - name: team
      keys: ["team.*"]
      readers: ["alice", "bob"]
      writers: ["alice", "bob"]
```

| Actor and scope | read | write | delete | promote | scoped snapshot |
| --- | --- | --- | --- | --- | --- |
| Alice / `notes.alice.*` | allow | allow | allow | subject to class gate | owner scope only |
| Bob / `notes.alice.*` | deny | deny | deny | deny | deny |
| Supervisor / `notes.alice.*` | deny | deny | deny | deny | only if a future custodian capability names that scope |
| Alice / `team.*` | allow | allow | allow | class gate | no scope-less snapshot |
| Supervisor / any owner scope | ordinary read deny | ordinary write deny | ordinary delete deny | deny | no implicit custodian right |

The table intentionally separates administrative authority from data authority. Additions, removals and class changes during restoration use separate recovery operations; they are not all `restore_promote`.

## Legacy override rejection and trusted context

Strict mode rejects all untrusted identity/provenance overrides **before authorization and before detectors**, even when the value happens to equal the bound value. This includes `principal`, `source_class`, `source_type`, `task`, `task_id`, `receipt_uri` and `assurance`, plus historical aliases and normalization paths for those fields. In particular, `source_type=SourceType.SYSTEM` cannot let an untrusted caller claim trusted SYSTEM provenance. Strict entry points and adapters receive provenance only from a coordinator-issued handle. Ambient context and guard-wide task setters cannot replace it; calls without a valid handle fail closed.

The current phase-one behavior remains unchanged outside strict mode. No adapter is certified for strict mode in v1.0.0.

## Read provenance envelope

The existing `read()` return type does not change. A later strict API will provide a separate `read_entry(key)` method with no `default=` argument. It returns `None` for a missing key or a frozen record containing a copied value, immutable owner, writer, source class, task, assurance and current commit version. The envelope is not an authorization token: authorization is evaluated before it is constructed, and it cannot be passed back to impersonate its writer or owner.

Historical provenance and its current trust status are visible in this envelope after an authorized read. A consumer may use that status to decide whether to trust content; the envelope does not turn provenance into truth.

## Owner and custodian snapshots, recovery and restore classes

Strict `snapshot_on_block` is conservative: it is disabled by default in strict mode unless the coordinator policy explicitly enables it. When enabled, the blocked write first passes authorization for the requested capture. A denied or malformed capture creates no snapshot and discloses no key, value, owner or class.

Snapshots are never held in one legacy shared whole-store buffer. The coordinator maintains separate retention quotas and stores:

1. **owner-scoped snapshots**, keyed by owner and containing only that owner’s authorized keys; and
2. **custodian-scoped snapshots**, keyed by a declared recovery capability and containing only its explicitly authorized scope.

Eviction is within the same owner or custodian scope only; Alice’s quota cannot evict Bob’s or a custodian’s snapshots. Capture checks authorization before reading values, and custodian APIs expose opaque snapshot ids and minimal labels only. A custodian does not gain ordinary read access through capture, listing or callbacks. Snapshot listings and scope-less snapshots are rejected in v1.0.0.

Recovery validates, in order: the current restorer’s identity and current authorization for the restoration operation; snapshot integrity and scope; immutable owner constraints; metadata/provenance integrity; and required current class gates. Historical writers are **not** re-authorized. Removing a writer from the current registry or lowering its current assurance must not prevent incident recovery of a valid historical version. Restored records retain snapshot-bound historical owner, writer, source class, task and assurance, with a trust-status flag explaining current policy compatibility. The restorer is recorded separately.

Restore operation mapping is precise:

- `restore_write` covers a key added by restoration and a value/metadata replacement;
- `restore_delete` covers a key removed by restoration;
- `restore_promote` applies **only** when the key exists before and after restoration and its class changes.

A class-gate check still applies to every applicable operation. Owner changes, forged metadata and invalid snapshot provenance are rejected. Each restored mutation receives a fresh monotonically increasing current commit version; historical versions remain lineage references and never replace current counters.

Adversarial recovery tests must cover cross-owner eviction, unauthorized capture, custodian plaintext disclosure, added/removed keys, equal value with changed provenance, class changes, owner tampering, removed historical writers, insufficient current assurance for the restorer, invalid integrity, denied class gates and monotonic versions.

## Lifecycle and later milestones

`retire_if()` is explicitly unsupported in strict v1.0.0 and fails closed. Owners may still delete keys through the ordinary owner-bound operation. Future milestones may add owner-scoped lifecycle callbacks with all-or-nothing read/delete preflight, but that design is not part of this proposal’s initial implementation.

Strict enumeration, bulk reads/deletes, snapshot inventory, framework adapters and lifecycle callbacks are likewise deferred. No API may expose a partial unauthorized inventory while those milestones are developed.

## Audit protocol and fencing

A future `AuditSink` will accept idempotent intent and outcome records keyed by `(operation_id, phase, substep)`. Intent is accepted at the single serialization point before every mutation and before any mandatory cross-owner disclosure. A same-owner read is best-effort audited by default; it must not be made fail-closed solely because its audit notification timed out.

For mandatory operations:

- intent rejection or timeout before an effect returns `audit-unavailable`; no mutation or disclosure occurs;
- after a known commit, failure to acknowledge the outcome is reported as **“committed, audit pending”**, never as rollback;
- the same operation id and phase/substep are retried with a bounded strategy;
- a mutation fence remains until authoritative outcome acknowledgement, then is lifted;
- an uncertain commit is distinct from a known committed write with pending acknowledgement and is fenced conservatively;
- blind repetition of an indeterminate mutation is forbidden; restart of ephemeral state does not claim durability or reconciliation.

The audit record contains actor, assurance, operation, owner/scope, policy revision, decision and outcome, but no denied key existence, values or payloads. Existing `_emit()` notifications cannot substitute for acknowledged sink acceptance. Unsupported persistent backends have no assumed durability guarantee.

## Implementation sequence and validation commitments

1. Land the independent evaluator-consolidation PR: one legacy-compatible evaluator, optional trace recorder and generated-policy differential tests; do not add strict features.
2. After design approval, implement strict schema and handle validation.
3. Implement the in-process ephemeral coordinator, owner/custodian snapshots, recovery mapping and audit fencing.
4. Add later milestones for enumeration, lifecycle callbacks, persistent recovery and adapter certification.

The RFC remains a proposal until approval. Its documentation validation must preserve the existing MkDocs navigation policy, pass `git diff --check`, and compare warnings with upstream. The threat model and links must describe proposed behavior without implying that strict isolation exists today.
