"""Self-reinforcement detector — Layer 1 of the three-layer ASI06 defense.

Catches the self-poisoning failure mode: an agent reads its own prior
agent_authored memory, mildly elaborates on it, writes it back, then reads
the elaborated version on the next turn and elaborates again. Over a few
iterations a hallucination or attacker-suggestion is reinforced into a
durable "fact" the agent now relies on.

This detector enforces two rules per (key) over a rolling window:

1. **Cool-down**: at most `max_self_writes` consecutive `agent_authored`
   writes within `cooldown_seconds`. Further writes flag for review.
2. **Self-similarity**: an `agent_authored` write whose value is >= the
   `similarity_threshold` to a recently stored `agent_authored` value on
   the same key is treated as reinforcement of the previous write, not
   independent corroboration. A separate `external_tool` or `user_input`
   write resets the counter (independent evidence breaks the loop).
"""
from __future__ import annotations

import difflib
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from agent_memory_guard.detectors.base import DetectionResult
from agent_memory_guard.detectors.injection import _stringify
from agent_memory_guard.events import Severity, SourceClass


@dataclass
class _SelfWriteHistory:
    """Sliding history of recent agent_authored writes on a single key."""

    writes: deque[tuple[float, str]] = field(default_factory=deque)
    last_independent_write_at: float = 0.0


class SelfReinforcementDetector:
    """Flags rapid, self-similar agent_authored writes to the same key.

    Only fires on writes whose `source_class == AGENT_AUTHORED`. Writes
    from other source classes (`EXTERNAL_TOOL`, `USER_INPUT`, `SYSTEM`)
    are treated as independent evidence and reset the cool-down counter.
    """

    name = "self_reinforcement"

    def __init__(
        self,
        *,
        cooldown_seconds: float = 60.0,
        max_self_writes: int = 3,
        similarity_threshold: float = 0.85,
        history_size: int = 8,
        severity: Severity = Severity.MEDIUM,
    ) -> None:
        if max_self_writes < 1:
            raise ValueError("max_self_writes must be >= 1")
        if not 0.0 <= similarity_threshold <= 1.0:
            raise ValueError("similarity_threshold must be in [0, 1]")
        self._cooldown = cooldown_seconds
        self._max_self_writes = max_self_writes
        self._similarity_threshold = similarity_threshold
        self._history_size = history_size
        self._severity = severity
        self._by_key: dict[str, _SelfWriteHistory] = {}

    def reset(self, key: str | None = None) -> None:
        if key is None:
            self._by_key.clear()
        else:
            self._by_key.pop(key, None)

    def note_independent_write(self, key: str) -> None:
        """Called by `MemoryGuard` when a non-agent_authored write lands;
        clears the cool-down counter so the next agent write isn't penalised
        for self-reinforcement when independent evidence has just arrived."""
        history = self._by_key.get(key)
        if history is not None:
            history.writes.clear()
            history.last_independent_write_at = time.monotonic()

    def inspect(self, key: str, value: Any, *, operation: str) -> DetectionResult:
        # source_class is carried on the inspect call via a contextvar-style
        # convention: the guard sets it on the detector before each write.
        # We default to UNKNOWN if no class was set.
        source_class: SourceClass = getattr(
            self, "_pending_source_class", SourceClass.UNKNOWN
        )
        if operation != "write" or source_class != SourceClass.AGENT_AUTHORED:
            return DetectionResult(self.name, matched=False)

        text = _stringify(value)
        now = time.monotonic()
        history = self._by_key.setdefault(key, _SelfWriteHistory())

        cutoff = now - self._cooldown
        while history.writes and history.writes[0][0] < cutoff:
            history.writes.popleft()

        recent_self_writes = len(history.writes)

        most_similar = 0.0
        most_similar_age = float("inf")
        for ts, prev_text in history.writes:
            ratio = _quick_ratio(text, prev_text)
            if ratio > most_similar:
                most_similar = ratio
                most_similar_age = now - ts

        history.writes.append((now, text))
        while len(history.writes) > self._history_size:
            history.writes.popleft()

        if (
            recent_self_writes >= self._max_self_writes
            and most_similar >= self._similarity_threshold
        ):
            return DetectionResult(
                detector=self.name,
                matched=True,
                severity=self._severity,
                message=(
                    f"Self-reinforcement loop on '{key}': "
                    f"{recent_self_writes + 1} agent_authored writes in "
                    f"{self._cooldown:.0f}s with similarity "
                    f"{most_similar:.2f} to a write {most_similar_age:.1f}s ago"
                ),
                metadata={
                    "self_writes_in_window": recent_self_writes + 1,
                    "max_self_writes": self._max_self_writes,
                    "similarity": round(most_similar, 3),
                    "similarity_threshold": self._similarity_threshold,
                    "cooldown_seconds": self._cooldown,
                },
            )
        return DetectionResult(self.name, matched=False)


def _quick_ratio(a: str, b: str) -> float:
    """Cheap upper-bound similarity ratio. ``difflib.SequenceMatcher`` is O(N*M)
    in the worst case; for long strings we cap the comparison length to keep
    the detector under the project's sub-100µs latency budget."""
    if not a or not b:
        return 0.0
    cap = 1024
    return difflib.SequenceMatcher(a=a[:cap], b=b[:cap], autojunk=False).quick_ratio()


__all__ = ["SelfReinforcementDetector"]
