# Write gates

Some writes need approval even when their text contains no detector finding.
Use a write gate for keys that affect permissions, outbound behavior or retrieval
scope. A gated proposal stays outside committed memory until trusted application
code resolves it. Normal reads, key enumeration and snapshots see committed
memory only.

## Approval

```python
from agent_memory_guard import Action, MemoryGuard, Policy, WriteGateRule

guard = MemoryGuard(policy=Policy(write_gates=(
    WriteGateRule("review_delivery", ("preferences.delivery.*",)),
)))

# Give agent code a handle, not the raw guard.
agent = guard.as_agent("assistant")
action = agent.write("preferences.delivery.enabled", True)
assert action == Action.REQUIRE_APPROVAL
assert agent.read("preferences.delivery.enabled") is None

# Run on the trusted host after the owner has reviewed this exact proposal.
proposal, = guard.pending_writes
assert proposal.value is True
guard.approve(proposal.write_id, digest=proposal.digest)
assert agent.read("preferences.delivery.enabled") is True
```

`write()` still returns an `Action`. Only `ALLOW` and `REDACT` indicate a committed
write. The new `REQUIRE_APPROVAL` and `REQUIRE_CORROBORATION` actions indicate a
pending write. They are write-only gates, not content-detector actions or read
policies.

The host can inspect `guard.pending_writes`, reject an exact proposal with
`guard.reject(write_id, digest=...)`, or remove expired proposals with
`guard.expire_pending()`. Inspection and resolution expire overdue proposals too.
The default lifetime is 300 seconds. `MemoryGuard(max_pending_writes=100)` bounds
pending state; reaching capacity raises `PendingWriteError` and commits nothing.

The digest binds the value, key, requesting principal and task. Values must be
finite JSON values with string object keys and at most 64 levels of nesting.
The guard copies them by serialization; mutating an input or a returned proposal
value cannot change what is approved. A proposal's `repr` and write-gate events
omit its payload. Write-gate processing adds no payload to traces. Keys, custom
detector output and other existing event fields still follow the application's
own data-minimization policy.

Reads of gated keys return fresh copies under the same finite JSON contract,
even without access rules. Preexisting values outside that contract are rejected
rather than exposed as mutable references into committed memory.

## Corroboration

```python
from agent_memory_guard import SourceClass

policy = Policy(write_gates=(
    WriteGateRule(
        "verify_scope", ("retrieval.scope.*",),
        action=Action.REQUIRE_CORROBORATION,
        corroborations=2,
        trusted_source_classes=(SourceClass.SYSTEM,),
    ),
))
guard = MemoryGuard(policy=policy)
guard.as_agent("assistant").write("retrieval.scope.project", "synthetic-project")
proposal, = guard.pending_writes

# These attestations belong to trusted application code, after source validation.
guard.corroborate(proposal.write_id, digest=proposal.digest,
                  source_domain="verified-record:one")
assert guard.read(proposal.key) is None
guard.corroborate(proposal.write_id, digest=proposal.digest,
                  source_domain="verified-record:two")
assert guard.read(proposal.key) == "synthetic-project"
```

The application must authenticate each source, check that its evidence supports
the exact proposal, and derive a stable provenance domain. Copies, citations and
repeated results from one origin must share a domain. Repeating a domain counts
once. `SourceClass` and domain strings are caller assertions, not authentication
or proof of independence. The default trusted class is `SYSTEM`; applications may
explicitly configure other classes only when their own trust boundary justifies
them. `source_class` on an agent's ordinary `write()` never supplies a vote.

`approve()` cannot bypass a corroboration gate, and `corroborate()` cannot resolve
an approval gate. Neither resolution API is available on `AgentHandle`. Keep the
raw guard, pending proposals and host control callbacks outside agent/tool scope.
Event handlers may enqueue a decision for later; synchronous resolution from an
active write or gate event raises `PendingWriteError`.

## Policy configuration

```yaml
write_gates:
  - name: review_delivery
    keys: preferences.delivery.*
    action: require_approval
    ttl_seconds: 300
  - name: verify_scope
    keys: retrieval.scope.*
    action: require_corroboration
    corroborations: 2
    trusted_source_classes: [system]
```

Rules are ordered; the first matching write gate wins. Unmatched keys retain
their existing behavior. Content detection runs before a proposal is created:
block and quarantine prevent it, and redaction runs before the copied value is
presented for approval. Resolution rechecks the original writer's access,
classification, current policy, target state and detectors. Changed targets or
policy invalidate the proposal; content-denied or failed backend attempts do not
consume it. Revalidation cannot silently commit a newly transformed value that
differs from the approved digest.

Successful guard writes, deletes, retirement, classification promotion and
rollback invalidate affected pending proposals, including changes that later
restore the old value. Switching task context invalidates outstanding proposals.
Rejection and expiry never commit. Approval commits at most once per proposal.

## Scope and framework integrations

Pending state and resolution are in-memory, within one live guard in one trusted
application process. Copies and unpickled guards do not inherit pending work;
restarts require a new proposal. Lifecycle events use the existing in-memory
event log, not a durable audit service.

The guard serializes its mutation and resolution paths with its lock. It checks a
detached target state to detect current out-of-band backend changes, but this is
not a cross-process compare-and-set. Other guards, processes and direct store
writers must not race it. The backend must provide normal atomic `set` behavior;
a backend that partially commits and then raises cannot provide exactly-once
resolution through this API. Durable pending state and distributed coordination
require a separate backend contract.

Built-in adapters treat pending actions as uncommitted: they do not forward
content or update external memory. The HTTP `/write` response reports
`stored: false`. Trusted host resolution commits the guard's store only. It does
not automatically replay an external framework's write, resume a tool call or
advance a framework's message index. The host integration owns that continuation
using the exact approved value. Calling the adapter again normally creates a new
proposal. The separate middleware and hook packages also withhold pending content
even when their normal violation mode is warn or strip.
