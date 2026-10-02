# LlamaIndex Integration

Protect LlamaIndex chat stores with AMG by wrapping any `BaseChatStore` with the guarded store class.

## Installation

```bash
pip install agent-memory-guard[llamaindex]
```

## Usage

```python
from llama_index.core.storage.chat_store import SimpleChatStore
from agent_memory_guard import MemoryGuard, Policy
from agent_memory_guard.integrations.llamaindex import GuardedChatStore

# Create your normal LlamaIndex chat store
base_store = SimpleChatStore()

# Wrap with AMG
guard = MemoryGuard(policy=Policy.strict())
guarded_store = GuardedChatStore(
    store=base_store,
    guard=guard,
    drop_blocked=True,
)

# Use as a drop-in replacement
guarded_store.add_message("session_1", user_message)  # Screened by AMG
messages = guarded_store.get_messages("session_1")
```

## With Chat Engine

```python
from llama_index.core.chat_engine import SimpleChatEngine
from llama_index.core.memory import ChatMemoryBuffer

# Create guarded store
guarded_store = GuardedChatStore(store=SimpleChatStore(), guard=guard)

# Use in memory buffer
memory = ChatMemoryBuffer.from_defaults(
    chat_store=guarded_store,
    chat_store_key="user_session_123",
)

# Create chat engine with protected memory
chat_engine = SimpleChatEngine.from_defaults(memory=memory)
response = chat_engine.chat("Hello!")
```

## How It Works

The `GuardedChatStore` intercepts all chat store operations:

| Method | AMG Behavior |
|--------|-------------|
| `set_messages()` | Screens each message, drops blocked ones |
| `add_message()` | Screens before storage |
| `get_messages()` | Returns stored messages (optionally re-screens) |
| `delete_messages()` | Allowed (cleanup) |

## Configuration Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `store` | required | The underlying `BaseChatStore` to wrap |
| `guard` | `MemoryGuard()` | The guard instance |
| `drop_blocked` | `True` | Drop blocked messages vs. raise exception |

## Batch Screening

When `set_messages()` is called with multiple messages, each is individually screened. Only messages that pass all detectors are stored:

```python
messages = [safe_msg, malicious_msg, safe_msg_2]
guarded_store.set_messages("session", messages)
# Only safe_msg and safe_msg_2 are stored
```
