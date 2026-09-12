"""Shared fixtures/helpers for AMSB tests: small deterministic fake adapters."""
from __future__ import annotations

from typing import Any

from agent_memory_guard.bench.adapter import MemorySystemAdapter, RememberOutcome


class StoreEverythingAdapter(MemorySystemAdapter):
    """No defenses: stores verbatim, recalls verbatim. Grades at the floor."""

    name = "store-everything"
    version = "test"

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}

    def remember(
        self, key: str, value: Any, *, source_class: str = "external_tool"
    ) -> RememberOutcome:
        self._data[key] = value
        return RememberOutcome.STORED

    def recall(self, key: str) -> Any | None:
        return self._data.get(key)


class BlockEverythingAdapter(MemorySystemAdapter):
    """Refuses every write: perfect defense but unusable (100% false positives)."""

    name = "block-everything"
    version = "test"

    def remember(
        self, key: str, value: Any, *, source_class: str = "external_tool"
    ) -> RememberOutcome:
        return RememberOutcome.BLOCKED

    def recall(self, key: str) -> Any | None:
        return None


class PerfectAdapter(MemorySystemAdapter):
    """Blocks malicious writes, stores benign ones — the ideal system.

    It cheats by consulting the canary, which only a test oracle can do; real
    adapters cannot. Used to assert the top of the scale (grade A, no FP).
    """

    name = "oracle"
    version = "test"

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        # Injected by the test so the oracle knows which writes are attacks.
        self.malicious_values: set = set()

    def remember(
        self, key: str, value: Any, *, source_class: str = "external_tool"
    ) -> RememberOutcome:
        if value in self.malicious_values:
            return RememberOutcome.BLOCKED
        self._data[key] = value
        return RememberOutcome.STORED

    def recall(self, key: str) -> Any | None:
        return self._data.get(key)
