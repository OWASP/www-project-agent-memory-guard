"""Performance benchmark: InMemoryStore vs RedisMemoryStore (fakeredis).

Not a strict latency test — fakeredis has no real network overhead.
The goal is to measure relative overhead of the Redis abstraction layer
(JSON serialization, prefix handling, scan_iter) against the raw dict baseline.

Run with: pytest tests/benchmarks/test_redis_benchmark.py -v -s
"""
from __future__ import annotations

import statistics
import time

import pytest

fakeredis = pytest.importorskip("fakeredis", reason="fakeredis not installed")

from agent_memory_guard.storage.memory_store import InMemoryStore
from agent_memory_guard.storage.redis_store import RedisMemoryStore

N = 1000  # operations per benchmark


def _measure(fn, iterations: int) -> list[float]:
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t0)
    return times


def _report(label: str, times: list[float]) -> None:
    median_us = statistics.median(times) * 1_000_000
    mean_us = statistics.mean(times) * 1_000_000
    ops_per_sec = 1 / statistics.mean(times)
    print(
        f"  {label:<40} "
        f"median={median_us:7.2f} µs  "
        f"mean={mean_us:7.2f} µs  "
        f"ops/s={ops_per_sec:,.0f}"
    )


@pytest.fixture(scope="module")
def mem_store():
    return InMemoryStore()


@pytest.fixture(scope="module")
def redis_store():
    client = fakeredis.FakeRedis(decode_responses=True)
    return RedisMemoryStore(redis_client=client, namespace="bench")


def test_write_benchmark(mem_store, redis_store, capsys):
    print(f"\n{'='*60}")
    print(f"  WRITE benchmark  ({N} sequential set() calls)")
    print(f"{'='*60}")

    mem_times = _measure(
        lambda: mem_store.set("bench.key", "value-data-string"), N
    )
    redis_times = _measure(
        lambda: redis_store.set("bench.key", "value-data-string"), N
    )

    with capsys.disabled():
        _report("InMemoryStore.set()", mem_times)
        _report("RedisMemoryStore.set()", redis_times)

    overhead = statistics.median(redis_times) / statistics.median(mem_times)
    with capsys.disabled():
        print(f"  Overhead factor: {overhead:.1f}x")

    # RedisMemoryStore should complete N writes without error
    assert len(redis_times) == N


def test_read_benchmark(mem_store, redis_store, capsys):
    mem_store.set("bench.read", "read-value")
    redis_store.set("bench.read", "read-value")

    print(f"\n{'='*60}")
    print(f"  READ benchmark  ({N} sequential get() calls)")
    print(f"{'='*60}")

    mem_times = _measure(lambda: mem_store.get("bench.read"), N)
    redis_times = _measure(lambda: redis_store.get("bench.read"), N)

    with capsys.disabled():
        _report("InMemoryStore.get()", mem_times)
        _report("RedisMemoryStore.get()", redis_times)

    overhead = statistics.median(redis_times) / statistics.median(mem_times)
    with capsys.disabled():
        print(f"  Overhead factor: {overhead:.1f}x")

    assert len(redis_times) == N


def test_snapshot_benchmark(capsys):
    """Snapshot benchmark with 100 keys — exercises scan_iter + pipelined MGET."""
    mem = InMemoryStore()
    client = fakeredis.FakeRedis(decode_responses=True)
    redis = RedisMemoryStore(redis_client=client, namespace="snap-bench")

    for i in range(100):
        mem.set(f"key.{i}", f"value-{i}")
        redis.set(f"key.{i}", f"value-{i}")

    mem_times = _measure(mem.snapshot, 200)
    redis_times = _measure(redis.snapshot, 200)

    print(f"\n{'='*60}")
    print(f"  SNAPSHOT benchmark  (100 keys, 200 calls)")
    print(f"{'='*60}")
    with capsys.disabled():
        _report("InMemoryStore.snapshot()", mem_times)
        _report("RedisMemoryStore.snapshot()", redis_times)

    assert len(redis_times) == 200


def test_summary_table(mem_store, redis_store, capsys):
    """Prints a combined summary table for all operations."""
    ops = {
        "set": (
            lambda: mem_store.set("s", "v"),
            lambda: redis_store.set("s", "v"),
        ),
        "get": (
            lambda: mem_store.get("s"),
            lambda: redis_store.get("s"),
        ),
        "contains": (
            lambda: "s" in mem_store,
            lambda: "s" in redis_store,
        ),
        "delete": (
            lambda: mem_store.delete("s"),
            lambda: redis_store.delete("s"),
        ),
    }

    print(f"\n{'='*70}")
    print(f"  SUMMARY — median latency per operation ({N} iterations each)")
    print(f"  {'Op':<12} {'InMemoryStore':>18} {'RedisMemoryStore':>20} {'Overhead':>10}")
    print(f"{'='*70}")

    with capsys.disabled():
        for op, (mem_fn, redis_fn) in ops.items():
            # seed a value so get/delete don't just fast-path on miss
            mem_store.set("s", "v")
            redis_store.set("s", "v")

            mem_t = statistics.median(_measure(mem_fn, N)) * 1e6
            redis_t = statistics.median(_measure(redis_fn, N)) * 1e6
            overhead = redis_t / mem_t if mem_t > 0 else float("inf")
            print(
                f"  {op:<12} {mem_t:>15.2f} µs  {redis_t:>17.2f} µs  {overhead:>8.1f}x"
            )
        print(f"{'='*70}")
