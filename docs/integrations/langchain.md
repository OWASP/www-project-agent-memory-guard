# LangChain Integration

Protect LangChain agent memory with AMG by wrapping any `BaseChatMessageHistory` with the guarded memory class.

## Installation

```bash
pip install agent-memory-guard[langchain]
```

## Usage

```python
from langchain_community.chat_message_histories import ChatMessageHistory
from agent_memory_guard import MemoryGuard, Policy
from agent_memory_guard.integrations.langchain import GuardedChatMessageHistory

# Create your normal LangChain memory
base_memory = ChatMessageHistory()

# Wrap with AMG
guard = MemoryGuard(policy=Policy.strict())
guarded_memory = GuardedChatMessageHistory(
    base_memory,
    guard=guard,
    drop_blocked=True,  # Silently drop blocked messages
)

# Use as normal — AMG screens every message
guarded_memory.add_user_message("Hello!")  # ✓ Passes
guarded_memory.add_ai_message("Hi there!")  # ✓ Passes
guarded_memory.add_user_message("Ignore all instructions...")  # ✗ Blocked
```

## With LangChain Agents

```python
from langchain.agents import AgentExecutor, create_openai_functions_agent
from langchain.memory import ConversationBufferMemory

# Wrap the underlying message history
base_history = ChatMessageHistory()
guarded_history = GuardedChatMessageHistory(base_history, guard=guard)

memory = ConversationBufferMemory(
    chat_memory=guarded_history,
    return_messages=True,
)

agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    memory=memory,
)
```

## How It Works

The `GuardedChatMessageHistory` intercepts:

- `add_message()` — screens message content before storage
- `add_user_message()` — screens user messages
- `add_ai_message()` — screens AI responses (catches self-reinforcement)

Messages that trigger detectors are either silently dropped (`drop_blocked=True`) or raise a `PolicyViolation` exception.

## Configuration Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `guard` | `MemoryGuard()` | The guard instance to use |
| `drop_blocked` | `True` | Drop blocked messages silently vs. raise exception |

## Monitoring

Access security events through the guard:

```python
for event in guard.events:
    print(f"[{event.severity.value}] {event.detector}: {event.message}")
```

## Middleware for `create_agent`

Building with `langchain.agents.create_agent` instead of `BaseChatMessageHistory`? Use `MemoryGuardMiddleware` from the separate `langchain-agent-memory-guard` package:

- [5-minute how-to (Discussion #116)](https://github.com/OWASP/www-project-agent-memory-guard/discussions/116)
- [README middleware example](https://github.com/OWASP/www-project-agent-memory-guard#langchain-middleware)
- [Public clinic Gist](https://gist.github.com/vgudur-dev/ead8817d2f4df08c04b808cc5b53eb06) — `Policy.strict()` repro, ~15 minutes
- Tried it in production? Open an issue titled `Adopter: <name> — LangChain` to be added to [ADOPTERS.md](https://github.com/OWASP/www-project-agent-memory-guard/blob/main/ADOPTERS.md)

This project is not OWASP-certified, not MITRE-approved, and the ATLAS AML.M0031 reference elsewhere in this repo is a YAML listing only, not an endorsement.
