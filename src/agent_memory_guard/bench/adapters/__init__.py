"""Adapters that plug concrete memory systems into AMSB.

The baseline adapters here (an unguarded dictionary and two Agent Memory Guard
configurations) always import cleanly and are what the committed leaderboard is
built from. Third-party adapters live in :mod:`third_party` and import their
target lazily, so grading mem0/Letta/Zep is opt-in and never a hard dependency.
"""
from __future__ import annotations

from agent_memory_guard.bench.adapters.baseline import (
    AMGHardenedAdapter,
    AMGStrictAdapter,
    UnguardedDictAdapter,
    baseline_adapters,
)

__all__ = [
    "UnguardedDictAdapter",
    "AMGStrictAdapter",
    "AMGHardenedAdapter",
    "baseline_adapters",
]
