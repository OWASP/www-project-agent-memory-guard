from agent_memory_guard.storage.memory_store import InMemoryStore, MemoryStore
from agent_memory_guard.storage.snapshots import Snapshot, SnapshotStore

__all__ = ["MemoryStore", "InMemoryStore", "Snapshot", "SnapshotStore"]

import importlib.util

if importlib.util.find_spec("redis") is not None:
    from agent_memory_guard.storage.redis_store import RedisMemoryStore

    __all__ += ["RedisMemoryStore"]
