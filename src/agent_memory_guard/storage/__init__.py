from agent_memory_guard.storage.memory_store import InMemoryStore, MemoryStore
from agent_memory_guard.storage.snapshots import Snapshot, SnapshotStore

__all__ = ["MemoryStore", "InMemoryStore", "Snapshot", "SnapshotStore"]

import importlib.util

# redis_store.py imports redis lazily inside _require_redis(), so importing the
# module never raises ImportError even when redis is absent. find_spec() is the
# only reliable way to gate the export on whether the package is actually installed.
if importlib.util.find_spec("redis") is not None:
    from agent_memory_guard.storage.redis_store import RedisMemoryStore

    __all__ += ["RedisMemoryStore"]
