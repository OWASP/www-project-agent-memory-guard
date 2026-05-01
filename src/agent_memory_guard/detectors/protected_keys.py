from __future__ import annotations

import fnmatch
from typing import Any, Iterable

from agent_memory_guard.detectors.base import DetectionResult
from agent_memory_guard.events import Severity


class ProtectedKeyDetector:
    """Flags writes targeting keys declared immutable by policy."""

    name = "protected_key"

    def __init__(
        self,
        protected: Iterable[str] = (),
        severity: Severity = Severity.CRITICAL,
    ) -> None:
        self._patterns = list(protected)
        self._severity = severity

    def add(self, pattern: str) -> None:
        self._patterns.append(pattern)

    def matches(self, key: str) -> str | None:
        for pattern in self._patterns:
            if fnmatch.fnmatchcase(key, pattern):
                return pattern
        return None

    def inspect(self, key: str, value: Any, *, operation: str) -> DetectionResult:
        if operation != "write":
            return DetectionResult(self.name, matched=False)
        match = self.matches(key)
        if not match:
            return DetectionResult(self.name, matched=False)
        return DetectionResult(
            detector=self.name,
            matched=True,
            severity=self._severity,
            message=f"Write to protected key '{key}' (matched pattern '{match}')",
            metadata={"pattern": match},
        )
