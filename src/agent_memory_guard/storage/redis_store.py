"""Redis-backed MemoryStore for persistent, distributed agent memory."""
from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any


def _require_redis() -> Any:
    try:
        import redis

        return redis
    except ImportError:
        raise ImportError(
            "Redis support is not installed. "
            "Run: pip install agent-memory-guard[redis]"
        )


class RedisMemoryStore:
    """Redis-backed implementation of the MemoryStore protocol.

    Persists agent memory across restarts and supports distributed multi-agent
    deployments via key namespacing. Values are JSON-serialized — only
    JSON-serializable types (str, int, float, bool, list, dict, None) round-trip
    exactly. Non-serializable types (e.g. datetime) are coerced to str via
    ``default=str`` and will deserialize as strings, not their original type.

    Args:
        url: Redis connection URL (e.g. ``"redis://localhost:6379/0"``).
        redis_client: Pre-built client instance — takes priority over all other
            connection args. Useful for injecting ``fakeredis.FakeRedis()`` in tests.
        namespace: Key prefix for multi-tenant isolation (default: ``"amg"``).
            All Redis keys are stored as ``"{namespace}:{key}"``.
        default_ttl: Optional TTL in seconds applied to every ``set()`` call.
        sentinels: List of ``(host, port)`` tuples for Redis Sentinel.
        sentinel_service_name: Master service name (required when using sentinels).
        decode_responses: Passed to the Redis client; must stay ``True`` for JSON
            string handling to work correctly (default: ``True``).
        **kwargs: Extra keyword arguments forwarded to ``redis.Redis()``.

    Example:
        >>> store = RedisMemoryStore(url="redis://localhost:6379", namespace="agent-1")
        >>> guard = MemoryGuard(store=store, policy=Policy.strict())
    """

    def __init__(
        self,
        url: str | None = None,
        *,
        redis_client: Any = None,
        namespace: str | None = None,
        default_ttl: int | None = None,
        sentinels: list[tuple[str, int]] | None = None,
        sentinel_service_name: str | None = None,
        decode_responses: bool = True,
        **kwargs: Any,
    ) -> None:
        self._namespace = namespace or "amg"
        self._default_ttl = default_ttl

        if redis_client is not None:
            self._client = redis_client
        elif sentinels is not None:
            redis = _require_redis()
            if not sentinel_service_name:
                raise ValueError(
                    "sentinel_service_name is required when sentinels are provided"
                )
            sentinel = redis.sentinel.Sentinel(
                sentinels, decode_responses=decode_responses, **kwargs
            )
            self._client = sentinel.master_for(sentinel_service_name)
        elif url is not None:
            redis = _require_redis()
            self._client = redis.from_url(url, decode_responses=decode_responses, **kwargs)
        else:
            redis = _require_redis()
            self._client = redis.Redis(decode_responses=decode_responses, **kwargs)

    # ---- internal helpers ------------------------------------------------

    def _prefix(self, key: str) -> str:
        return f"{self._namespace}:{key}"

    def _strip(self, prefixed: str | bytes) -> str:
        # Guard against clients configured with decode_responses=False, which
        # return bytes keys from scan_iter. Without this, bytes would leak into
        # MemoryGuard and crash str operations like key.startswith("system.").
        if isinstance(prefixed, bytes):
            prefixed = prefixed.decode("utf-8")
        prefix = f"{self._namespace}:"
        if prefixed.startswith(prefix):
            return prefixed[len(prefix):]
        # Unexpected key outside our namespace — return as-is rather than silently
        # corrupt it with a wrong index slice (can happen if namespace contains
        # Redis glob characters like * or ? and scan_iter returns unrelated keys).
        return prefixed

    def _decode(self, raw: str | bytes | None) -> str | None:
        """Decode a raw Redis value to str, handling bytes from decode_responses=False."""
        if raw is None:
            return None
        if isinstance(raw, bytes):
            return raw.decode("utf-8")
        return raw

    def _serialize(self, value: Any) -> str:
        # default=str is intentionally lossy for non-JSON-serializable types
        # (e.g. datetime -> "2024-01-01T00:00:00"). The deserialized value will
        # be a string, not the original type. This is the correct tradeoff for a
        # distributed store — it prevents crashes without silently swallowing data.
        return json.dumps(value, default=str)

    def _deserialize(self, raw: str) -> Any:
        return json.loads(raw)

    # ---- MemoryStore protocol --------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        raw = self._decode(self._client.get(self._prefix(key)))
        if raw is None:
            return default
        return self._deserialize(raw)

    def set(self, key: str, value: Any) -> None:
        serialized = self._serialize(value)
        if self._default_ttl is not None:
            self._client.set(self._prefix(key), serialized, ex=self._default_ttl)
        else:
            self._client.set(self._prefix(key), serialized)

    def delete(self, key: str) -> None:
        self._client.delete(self._prefix(key))

    def keys(self) -> Iterator[str]:
        # scan_iter is non-blocking (cursor-based); never use KEYS in production.
        # Note: in a shared Redis instance with millions of unrelated keys, SCAN
        # traverses the entire keyspace — latency scales with total DB size, not
        # just this namespace. Storing keys in a Redis Hash would isolate the scan,
        # but Hashes don't support per-field TTL, making top-level prefixed keys the
        # only correct approach when default_ttl is needed.
        # Snapshot into a list first to avoid mutation-during-iteration issues,
        # matching the same pattern as InMemoryStore.keys().
        all_keys = [
            self._strip(k)
            for k in self._client.scan_iter(self._prefix("*"))
        ]
        return iter(all_keys)

    def items(self) -> Iterator[tuple[str, Any]]:
        prefixed_keys = list(self._client.scan_iter(self._prefix("*")))
        if not prefixed_keys:
            return iter([])
        # Pipeline the GETs to avoid N round-trips
        pipe = self._client.pipeline()
        for pk in prefixed_keys:
            pipe.get(pk)
        values = pipe.execute()
        result = []
        for pk, raw in zip(prefixed_keys, values):
            decoded = self._decode(raw)
            if decoded is not None:
                result.append((self._strip(pk), self._deserialize(decoded)))
        return iter(result)

    def __contains__(self, key: str) -> bool:
        return bool(self._client.exists(self._prefix(key)))

    # ---- non-protocol extras (matching InMemoryStore) --------------------

    def __len__(self) -> int:
        # O(N) — no native prefix-count command in Redis. Acceptable because
        # agents typically hold a few dozen memory keys, not millions.
        return sum(1 for _ in self._client.scan_iter(self._prefix("*")))

    def snapshot(self) -> dict[str, Any]:
        """Return a point-in-time dict of all keys/values under this namespace.

        Uses a single scan + pipelined MGET rather than N individual GETs.
        """
        prefixed_keys = list(self._client.scan_iter(self._prefix("*")))
        if not prefixed_keys:
            return {}
        pipe = self._client.pipeline()
        for pk in prefixed_keys:
            pipe.get(pk)
        values = pipe.execute()
        result = {}
        for pk, raw in zip(prefixed_keys, values):
            decoded = self._decode(raw)
            if decoded is not None:
                result[self._strip(pk)] = self._deserialize(decoded)
        return result

    def restore(self, data: dict[str, Any]) -> None:
        """Atomically replace all namespaced keys with the contents of ``data``.

        Executes inside a single pipelined transaction (MULTI/EXEC) so no
        concurrent reader ever sees an empty or partially restored store.

        Concurrency note: ``existing`` is collected via SCAN before the pipeline
        opens. A key written by a concurrent agent between the SCAN and EXEC will
        not be included in the deletion set and will survive the restore. This is
        a fundamental limitation of namespaced pattern lookups in Redis — SCAN
        cannot run inside a WATCH/MULTI block — and is acceptable for typical
        agent memory workloads.
        """
        existing = list(self._client.scan_iter(self._prefix("*")))
        pipe = self._client.pipeline(transaction=True)
        if existing:
            pipe.delete(*existing)
        for key, value in data.items():
            serialized = self._serialize(value)
            if self._default_ttl is not None:
                pipe.set(self._prefix(key), serialized, ex=self._default_ttl)
            else:
                pipe.set(self._prefix(key), serialized)
        pipe.execute()
