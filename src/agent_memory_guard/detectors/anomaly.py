from __future__ import annotations

import time
from collections import deque
from typing import Any

from agent_memory_guard.detectors.base import DetectionResult
from agent_memory_guard.detectors.injection import _stringify
from agent_memory_guard.events import Severity


class SizeAnomalyDetector:
    """Flags memory writes that are unusually large or grow unusually fast.

    This detector mitigates buffer overflow or massive data poisoning attempts
    by enforcing maximum size limits and detecting abrupt spikes in size.

    Attributes:
        name: The unique identifier for this detector.
    """

    name = "size_anomaly"

    def __init__(
        self,
        max_bytes: int = 64 * 1024,
        growth_factor: float = 10.0,
        severity: Severity = Severity.MEDIUM,
    ) -> None:
        self._max_bytes = max_bytes
        self._growth_factor = growth_factor
        self._last_size: dict[str, int] = {}
        self._severity = severity

    def inspect(self, key: str, value: Any, *, operation: str) -> DetectionResult:
        """Inspect the size of a memory value.

        Args:
            key: The memory key being modified.
            value: The string or raw value to inspect.
            operation: The memory operation being performed.

        Returns:
            DetectionResult: The match outcome, including size details if a violation occurs.
        """
        size = len(_stringify(value).encode("utf-8"))
        previous = self._last_size.get(key)
        self._last_size[key] = size

        if size > self._max_bytes:
            return DetectionResult(
                detector=self.name,
                matched=True,
                severity=self._severity,
                message=f"Memory value for '{key}' exceeds size limit ({size} > {self._max_bytes} bytes)",
                metadata={"size": size, "limit": self._max_bytes},
            )

        if previous and previous > 0 and size > previous * self._growth_factor:
            return DetectionResult(
                detector=self.name,
                matched=True,
                severity=self._severity,
                message=f"Memory value for '{key}' grew {size / previous:.1f}x in one write",
                metadata={"size": size, "previous": previous},
            )

        return DetectionResult(self.name, matched=False)


class RapidChangeDetector:
    """Flags suspiciously high write frequency on a single key (churn attack).

    This detector identifies automated loop or denial-of-service attempts
    affecting key persistence.

    Attributes:
        name: The unique identifier for this detector.
    """

    name = "rapid_change"

    def __init__(
        self,
        window_seconds: float = 5.0,
        max_writes: int = 20,
        severity: Severity = Severity.MEDIUM,
    ) -> None:
        self._window = window_seconds
        self._max = max_writes
        self._writes: dict[str, deque[float]] = {}
        self._severity = severity

    def inspect(self, key: str, value: Any, *, operation: str) -> DetectionResult:
        """Inspect write frequency for a memory key.

        Args:
            key: The memory key being updated.
            value: The value being written.
            operation: The operation name. Only checks 'write' operations.

        Returns:
            DetectionResult: The check result including write frequency details.
        """
        if operation != "write":
            return DetectionResult(self.name, matched=False)

        now = time.monotonic()
        history = self._writes.setdefault(key, deque())
        history.append(now)
        cutoff = now - self._window
        while history and history[0] < cutoff:
            history.popleft()

        if len(history) > self._max:
            return DetectionResult(
                detector=self.name,
                matched=True,
                severity=self._severity,
                message=f"Rapid write churn on '{key}': {len(history)} writes in {self._window}s",
                metadata={"writes": len(history), "window": self._window},
            )
        return DetectionResult(self.name, matched=False)
