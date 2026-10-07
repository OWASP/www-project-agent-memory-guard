# Multi-Agent Access Control

When several agents share one memory, one shared `MemoryGuard` already checks the
*content* of every agent's writes and reads. Access rules add the other half: the
guard learns **which agent is asking**, so you can say who may read and write each
key.

```python
from agent_memory_guard import AccessDenied, AccessRule, MemoryGuard, Policy, format_trace

policy = Policy.strict().with_access(
    AccessRule("plan", keys=["plan.*"], writers=["supervisor"], readers=["*"]),
    AccessRule("notebooks", keys=["notes.{owner}.*"], writers=["{owner}"], readers=["{owner}"]),
    default="allow",          # keys no rule covers stay open to everyone
    admins=["supervisor"],    # only the supervisor may call snapshot() and rollback()
)
guard = MemoryGuard(policy=policy, trace=True)

supervisor = guard.as_agent("supervisor")
writer = guard.as_agent("writer")

supervisor.write("plan.step1", "collect Q3 numbers")   # allowed
writer.read("plan.step1")                              # allowed: readers ["*"]
try:
    writer.write("plan.step1", "skip the review")      # denied
except AccessDenied as exc:
    print(exc)
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
4. **Default.** Keys no rule covers get `default` (`"allow"` or `"deny"`;
   `"deny"` if you leave it out).
5. **Class gate.** Writing, deleting or promoting POLICY or VERIFIED_PREFERENCE
   memory needs the `admins`, unless `class_writers` names someone else for that
   class. A class you leave out of `class_writers` keeps the admins; to open one
   to everyone, say so: `class_writers={"verified_preference": ["*"]}`. The gate
   runs after the rules, so an agent that may not write, delete or promote a key
   learns nothing about its label. A `rollback()` that would change memory of a gated class
   also needs its class writers.

If you name no `admins`, nobody may snapshot, roll back or retire, or write,
delete or promote POLICY and VERIFIED_PREFERENCE memory, unless `class_writers`
names someone for that class. To let code that calls
the guard without an agent identity do so, as in 0.3, add `"<anonymous>"` to
`admins`. Code that
loses its agent identity (see below) then gets those rights too, so prefer
naming the agents.

A denial raises `AccessDenied`, logs an `access_control` event naming the agent
and what denied it (`access_stage` and `reason`, plus `access_rule` when a rule
or `class_writers[...]` denied it), and takes no snapshot. `AccessDenied` is a `PolicyViolation`, so
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
  adapters that don't know about agents yet. Other guards ignore the block. Pass
  `ambient_identity=False` to `with_access()` to turn this off.
    - The block covers the functions it calls, asyncio tasks it starts, and
      threads it starts with `contextvars.copy_context()`.
    - It works through `@contextmanager` wrappers, `ExitStack` and classes
      whose `__enter__` or `__aenter__` enters the handle.
    - A `with` statement in an ordinary function belongs to that function, even
      when a generator further up the stack called it (a streaming view, or a
      framework loop such as LangGraph's `stream()`), so tasks and threads it
      starts get its identity. That holds when the `with` names the handle or a
      `@contextmanager` whose own `with` enters it. A block entered through
      `ExitStack` or an explicit `__enter__()` call can outlive the `with`, so
      it counts as the generator's (below).
    - When a generator pauses at a `yield` inside the block, its caller keeps
      its own identity, so two agents' streams can interleave safely. The
      generator's own code keeps the block's identity wherever it is resumed,
      even on another thread.
    - Tasks and threads started while a generator holds a block open in the
      same context start **anonymous**: the guard cannot tell whether the
      generator or its caller started them. That covers a block written in the
      generator itself and one entered for it through `ExitStack` or a helper's
      explicit `__enter__()`. Give them a handle instead.
    - Exit a block in the thread or task that entered it (a generator's block
      may end wherever the generator is resumed). Exiting it from anywhere
      else raises `RuntimeError` and ends the block everywhere.
- Otherwise the caller is **anonymous**, and matches only `"*"`,
  `"<anonymous>"` and `default`. A thread started without
  `contextvars.copy_context()` is anonymous too, except on free-threaded Python
  (3.14t) or with `-X thread_inherit_context=1`: there every new thread
  inherits the context of the code that starts it, open block included, for
  its whole life. Create thread pools and long-lived worker threads outside any
  block, or hand their jobs a handle.

Agent ids are 1 to 64 characters of letters, digits, `_` and `-`, and cannot
start with `-`. Roles come only from the `principals` registry, never from the
caller.

## Selectors

| Selector | Matches |
|---|---|
| `"*"` | anyone, including anonymous callers |
| `"writer"` | the agent with that id |
| `"role:lead"` | agents the registry gives that role (needs `principals=`) |
| `"{owner}"` | the agent named by the key's `{owner}` segment |
| `"<anonymous>"` | callers with no agent identity |

`{owner}` must be a whole key segment after a literal prefix, as in
`agents.{owner}.*`. A segment that is not a valid id, such as `Payments Bot`,
belongs to nobody, so it is denied.

## Looking inside

- `guard.explain("write", "plan.step1", principal="writer")` shows how access
  would be decided, without doing anything. A handle's `explain()` shows only the
  rule that decided. For `rollback`, pass `snapshot_id=` to check a snapshot
  other than the latest.
- `MemoryGuard(trace=True)` records every step of each operation: identity,
  access rules, each detector and what it found, the deciding policy rule, the
  snapshot and the commit. `guard.last_trace()` returns the steps of the last
  operation in the current thread or asyncio task, so call it in the code that
  ran the operation. Each event carries the steps in `metadata["trace"]`; when
  one operation logs several events (`retire_if()`), each carries the opening
  steps and the steps since the previous event. Tracing roughly doubles the cost
  of an operation, so use it for demos, debugging and incident review.
- Every event has a `principal` field.

## Limits to know

- **This is not authentication.** In-process identity is whatever the calling
  code says. It protects against confused or poisoned agents, not against
  malicious code in the same process. Never let model output choose the agent id.
- **Values are copied.** With access rules, the guard stores a deep copy of what
  is written and returns a deep copy on read, so an agent cannot change memory
  it may only read by editing the object it got back. Values must be
  deep-copyable.
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
  directly, so access rules don't cover them: CrewAI `GuardedMemory.search()`,
  LlamaIndex `get_messages()` and LangChain index reads. Use the guard or a
  handle directly for anything access rules must protect. LlamaIndex
  `delete_message()` and `delete_messages()` raise `AccessDenied` and leave the
  backing store alone when the agent may not delete the messages.
- **Callbacks run under the guard's lock.** With access rules, every operation
  except a read holds the guard's lock while detectors, event handlers, store
  methods and the `retire_if()` predicate run. They must not wait on another
  thread that uses the same guard, or both wait forever.
- **Snapshot churn.** Access denials take no snapshot, but a content-blocked
  write by any agent still takes one into the snapshot buffer (50 by default),
  so many blocked writes can push out a known-good snapshot. Keep a known-good
  copy elsewhere, or raise `SnapshotStore(max_snapshots=...)`.
- **Cleanup run by the garbage collector.** A stream's `finally` code that runs
  while the garbage collector closes the stream cannot open a `with` block (it
  raises `RuntimeError`); call the handle's methods there. On Python 3.9 and
  3.10, a stream paused inside a block is never freed if it sits in a reference
  cycle (for example `self.stream = self._run()`), so its `finally` never runs.
  Close streams you stop early with `stream.close()`.
- **Context managers that hide how they enter a handle.** An `__enter__` that
  is not Python code (such as a `functools.partial` of the handle's `__enter__`),
  or a `@contextmanager` that yields twice or ignores `close()`, can leave a
  block open after its `with` ends, and the agent's identity then applies to the
  code after it. Enter handles with a plain `with` inside your context managers.
- **YAML.** Access rules are Python-only for now. A YAML policy with `access:`,
  `principals:` or `agents:`, or a rule with fields such as `agents:` or
  `writers:`, fails to load instead of being silently ignored. Other unknown
  fields give a `PolicyWarning`.
