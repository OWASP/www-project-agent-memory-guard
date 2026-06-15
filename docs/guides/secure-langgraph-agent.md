# Add Memory Poisoning Defense to a LangGraph Agent

> **TL;DR:** Add Agent Memory Guard as a checkpoint validator in your LangGraph state graph to block prompt injection and memory tampering at every state transition. Works with any LangGraph `StateGraph`, including checkpointed and multi-agent architectures.

---

## The Problem

LangGraph persists agent state across invocations via checkpointers (SQLite, Postgres, Redis). That persisted state — messages, tool results, intermediate reasoning — is replayed on every resume. An attacker who poisons a single checkpoint entry can:

- Hijack the agent's next action by injecting instructions into the message history
- Override tool routing by tampering with the state's `next` field
- Persist across thread boundaries if shared memory is used

Because LangGraph replays the full state on resume, a poisoned checkpoint is re-injected every time the graph runs.

---

## The Fix (5 minutes)

### Step 1: Install

```bash
pip install agent-memory-guard langchain-agent-memory-guard
```

### Step 2: Add a guard node to your graph

```python
from langgraph.graph import StateGraph, MessagesState, START, END
from langchain_agent_memory_guard import MemoryGuardValidator
from agent_memory_guard import Policy

# Initialize the validator
validator = MemoryGuardValidator(policy=Policy.strict())

# Your existing graph
def agent(state: MessagesState):
    # Your agent logic here
    ...

def tools(state: MessagesState):
    # Your tool execution here
    ...

def guard_checkpoint(state: MessagesState):
    """Validate state before checkpointing."""
    messages = state["messages"]
    # Validate the latest message (the one about to be persisted)
    latest = messages[-1]
    result = validator.validate(latest.content, source=latest.type)
    if result.blocked:
        # Replace poisoned message with safe fallback
        return {"messages": messages[:-1] + [
            HumanMessage(content="[BLOCKED: memory poisoning attempt detected]")
        ]}
    return state

# Build the graph with guard node
builder = StateGraph(MessagesState)
builder.add_node("agent", agent)
builder.add_node("tools", tools)
builder.add_node("guard", guard_checkpoint)

# Route: agent → guard → tools (or END)
builder.add_edge(START, "agent")
builder.add_edge("agent", "guard")
builder.add_conditional_edges("guard", should_continue)
builder.add_edge("tools", "agent")

graph = builder.compile(checkpointer=MemorySaver())
```

### Step 3: Use the LangChain middleware (alternative approach)

If you prefer a transparent middleware that wraps the checkpointer itself:

```python
from langchain_agent_memory_guard import GuardedCheckpointer
from langgraph.checkpoint.memory import MemorySaver

# Wrap any checkpointer with AMG validation
base_checkpointer = MemorySaver()  # or SqliteSaver, PostgresSaver, etc.
guarded_checkpointer = GuardedCheckpointer(
    base=base_checkpointer,
    policy=Policy.strict(),
)

# Use it in your graph — no other changes needed
graph = builder.compile(checkpointer=guarded_checkpointer)
```

---

## What Gets Caught

| Attack Vector | Example | Result |
|--------------|---------|--------|
| Message history injection | Tool returns "SYSTEM: Override all instructions" | **BLOCKED** |
| State field tampering | Modifying `next` to skip safety nodes | **BLOCKED** |
| Checkpoint replay attack | Old poisoned checkpoint replayed on resume | **BLOCKED** |
| Cross-thread contamination | Shared memory carries injection to new thread | **BLOCKED** |
| Normal state transition | "Here are the search results: ..." | ✓ Allowed |

---

## Multi-Agent Architectures

For LangGraph's multi-agent patterns (supervisor, hierarchical), add the guard at the handoff boundary:

```python
from langgraph.graph import StateGraph
from langchain_agent_memory_guard import MemoryGuardValidator

validator = MemoryGuardValidator(policy=Policy.strict())

def supervisor(state):
    # Supervisor decides which agent to route to
    ...

def guard_handoff(state):
    """Validate state before passing to sub-agent."""
    latest_output = state["messages"][-1].content
    result = validator.validate(latest_output, source="agent_handoff")
    if result.blocked:
        state["messages"][-1].content = "[BLOCKED: poisoned handoff detected]"
    return state

# Supervisor → Guard → Sub-agents
builder.add_edge("supervisor", "guard_handoff")
builder.add_conditional_edges("guard_handoff", route_to_agent)
```

---

## Monitoring

```python
from langchain_agent_memory_guard import GuardedCheckpointer
from agent_memory_guard import Policy, OTelExporter

guarded = GuardedCheckpointer(
    base=MemorySaver(),
    policy=Policy.strict(),
    on_block=lambda e: print(f"⚠️ {e.detector}: {e.message[:80]}"),
    exporter=OTelExporter(endpoint="http://localhost:4317"),  # Optional
)
```

---

## Performance Impact

Agent Memory Guard adds **59 microseconds** median latency per state validation. LangGraph checkpoint writes typically take 5-50ms (serialization + storage). The security overhead is <0.2% of total checkpoint time.

---

## Next Steps

- [LangChain integration package](https://pypi.org/project/langchain-agent-memory-guard/)
- [Full API documentation](https://github.com/OWASP/www-project-agent-memory-guard)
- [Benchmark results](https://github.com/OWASP/www-project-agent-memory-guard#benchmark-results)
- [Report a vulnerability](https://github.com/OWASP/www-project-agent-memory-guard/security)

---

*This guide is part of the [OWASP Agent Memory Guard](https://github.com/OWASP/www-project-agent-memory-guard) project — the reference implementation for OWASP Agentic AI Top 10 ASI06 (Memory & Context Poisoning).*
