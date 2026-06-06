from __future__ import annotations

import fnmatch
from collections.abc import Iterable
from typing import Any

from agent_memory_guard.detectors.base import DetectionResult
from agent_memory_guard.events import Severity


class ProtectedKeyDetector:
    """Flags writes targeting keys declared protected or immutable by policy.

    Attributes:
        name: The unique identifier for this detector.
    """

    name = "protected_key"

    def __init__(
        self,
        protected: Iterable[str] = (),
        severity: Severity = Severity.CRITICAL,
    ) -> None:
        self._patterns = list(protected)
        self._severity = severity

    def add(self, pattern: str) -> None:
        """Add a key pattern to the collection of protected keys.

        Args:
            pattern: The glob pattern matching protected keys.
        """
        self._patterns.append(pattern)

    def matches(self, key: str) -> str | None:
        """Check if a memory key matches any protected patterns.

        Args:
            key: The memory key to check.

        Returns:
            str | None: The matching glob pattern, or None if no match is found.
        """
        for pattern in self._patterns:
            if fnmatch.fnmatchcase(key, pattern):
                return pattern
        return None

    def inspect(self, key: str, value: Any, *, operation: str) -> DetectionResult:
        """Inspect write operations to prevent modification of protected keys.

        Args:
            key: The target memory key.
            value: The value being written.
            operation: The memory operation being performed. Only checks 'write' operations.

        Returns:
            DetectionResult: The check outcome, matched=True if targeting a protected key.
        """
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
