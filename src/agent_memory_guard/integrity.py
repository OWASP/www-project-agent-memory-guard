from __future__ import annotations

import hashlib
import json
from typing import Any

from agent_memory_guard.exceptions import IntegrityError


def canonical_serialize(value: Any) -> bytes:
    """Stable JSON serialization for hashing.

    sort_keys ensures dicts hash identically regardless of insertion order;
    separators strip whitespace so formatting changes don't break baselines.
    """
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False
    ).encode("utf-8")


def hash_value(value: Any) -> str:
    """SHA-256 hex digest of a memory value."""
    return hashlib.sha256(canonical_serialize(value)).hexdigest()


class IntegrityRegistry:
    """Tracks SHA-256 baselines for keys flagged as protected/immutable."""

    def __init__(self) -> None:
        self._baselines: dict[str, str] = {}

    def baseline(self, key: str, value: Any) -> str:
        digest = hash_value(value)
        self._baselines[key] = digest
        return digest

    def has_baseline(self, key: str) -> bool:
        return key in self._baselines

    def expected(self, key: str) -> str | None:
        return self._baselines.get(key)

    def verify(self, key: str, value: Any) -> None:
        expected = self._baselines.get(key)
        if expected is None:
            return
        actual = hash_value(value)
        if actual != expected:
            raise IntegrityError(
                f"Integrity check failed for key '{key}'",
                key=key,
                expected=expected,
                actual=actual,
            )

    def clear(self, key: str | None = None) -> None:
        if key is None:
            self._baselines.clear()
        else:
            self._baselines.pop(key, None)
