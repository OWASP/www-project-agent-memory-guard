# Multi-Agent Access Control

When several agents share one memory, one shared `MemoryGuard` already checks the
*content* of every agent's writes and reads. Access rules add the other half: the
guard learns **which agent is asking**, so you can say who may read and write each
key.

```python
from agent_memory_guard import AccessRule, MemoryGuard, Policy, format_trace

policy = Policy.strict().with_access(
    AccessRule("plan", keys=["plan.*"], writers=["supervisor"], readers=["*"]),
    AccessRule("notebooks", keys=["notes.{owner}.*"], writers=["{owner}"], readers=["{owner}"]),
    default="allow",          # keys no rule covers stay open to everyone
    admins=["supervisor"],    # who may snapshot, roll back and write POLICY memory
)
guard = MemoryGuard(policy=policy, trace=True)

supervisor = guard.as_agent("supervisor")
writer = guard.as_agent("writer")

supervisor.write("plan.step1", "collect Q3 numbers")   # allowed
writer.read("plan.step1")                              # allowed: readers ["*"]
writer.write("plan.step1", "skip the review")          # AccessDenied
print(format_trace(guard.last_trace()))                # how the guard decided
```

A runnable version is in `examples/multi_agent_access.py`.

## How a decision is made

Access is checked first, before any detector runs, before the guard looks for
the key, and before the store is touched. Every stage must pass:

1. **Registry.** If you pass `principals={...}`, only those agents exist.
2. **Admins.** `snapshot()`, `rollback()` and `retire_if()` need one of `admins`.
3. **Rules.** The first rule whose `keys` match decides: `writers` for write,
   delete and promote, `readers` for read.
4. **Default.** Keys no rule covers get `default` (`"allow"` or `"deny"`).
5. **Class gate.** Writing, deleting or promoting POLICY or VERIFIED_PREFERENCE
   memory needs `class_writers` (by default, the `admins`). It runs after the
   rules, so an agent that may not touch a key learns nothing about its label.

If you name no `admins`, agents can't snapshot, roll back, retire or touch
POLICY and VERIFIED_PREFERENCE memory. Code that calls the guard without an
agent identity still can, as in 0.3.

A denial raises `AccessDenied`, logs an `access_control` event naming the agent
and the rule, and takes no snapshot. `AccessDenied` is a `PolicyViolation`, so
code that already catches `PolicyViolation` keeps working. If access allows the
operation, the usual detectors and content rules run as before.

## Who is acting

- **A handle.** `guard.as_agent("writer")` returns an `AgentHandle`. Give the
  handle, not the guard, to agent and tool code: it always acts as that agent and
  refuses `principal=`. Its `snapshot()` and `rollback()` return a snapshot id,
  never the stored data.
- **`principal=`** on `write`, `read`, `delete`, `promote`, `snapshot`,
  `rollback` and `retire_if`, for orchestrator code.
- **A `with` block.** Inside `with guard.as_agent("writer"):`, plain
  `guard.write(...)` calls on *that guard* run as the writer. This is how you use
  adapters that don't know about agents yet. Other guards ignore the block. Set
  `ambient_identity=False` to turn this off.
  - The block covers the functions it calls, asyncio tasks it starts, and
    threads it starts with `contextvars.copy_context()`.
  - It works through `@contextmanager` wrappers and `ExitStack`.
  - When a generator pauses at a `yield` inside the block, its caller keeps its
    own identity, so two agents' streams can interleave safely.
- Otherwise the caller is **anonymous**, and matches only `"*"` and `default`.

Agent ids are 1 to 64 characters of letters, digits, `_` and `-`. Roles come only
from the `principals` registry, never from the caller.

## Selectors

| Selector | Matches |
|---|---|
| `"*"` | anyone, including anonymous callers |
| `"writer"` | the agent with that id |
| `"role:lead"` | agents the registry gives that role (needs `principals=`) |
| `"{owner}"` | the agent named by the key's `{owner}` segment |

`{owner}` must be a whole key segment after a literal prefix, as in
`agents.{owner}.*`. A segment that is not a valid id, such as `Payments Bot`,
belongs to nobody, so it is denied.

## Looking inside

- `guard.explain("write", "plan.step1", principal="writer")` shows how access
  would be decided, without doing anything. A handle's `explain()` shows only the
  rule that decided.
- `MemoryGuard(trace=True)` records every step of each operation: identity,
  access rules, each detector and what it found, the deciding policy rule, the
  snapshot and the commit. `guard.last_trace()` returns the steps, and each event
  carries them in `metadata["trace"]`. It roughly doubles the cost of an
  operation, so use it for demos, debugging and incident review.
- Every event has a `principal` field.

## Limits to know

- **This is not authentication.** In-process identity is whatever the calling
  code says. It protects against confused or poisoned agents, not against
  malicious code in the same process. Never let model output choose the agent id.
- **Whoever holds the raw guard sees everything.** `snapshot()`, `list_snapshots()`
  and the `retire_if()` predicate see every value. Keep the guard with your
  orchestrator and give agents handles.
- **Protected keys stay frozen for everyone**, including writers named in an
  access rule. When one agent should own a key, use an access rule instead of
  `protected_keys`.
- **Private namespaces hide echo loops.** Self-reinforcement history is kept per
  key, so two agents echoing each other in their own `{owner}` keys are not
  detected. Keep anything agents iterate on together in a shared key.
- **Labels live in memory.** `snapshot()` and `rollback()` keep class labels and
  last writers, but a new guard over the same store starts without them.
- **Adapters.** Framework adapters don't pass the agent yet; wrap each agent's
  step in `with guard.as_agent(...)`. Some adapter paths read the backing store
  directly (for example CrewAI `GuardedMemory.search()`), so access rules don't
  cover them.
- **YAML.** Access rules are Python-only for now. A YAML policy with `access:`,
  `principals:` or `agents:`, or a rule with fields such as `agents:` or
  `writers:`, fails to load instead of being silently ignored. Other unknown
  fields give a `PolicyWarning`.
