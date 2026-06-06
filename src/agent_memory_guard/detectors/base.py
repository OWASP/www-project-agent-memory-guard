from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from agent_memory_guard.events import Severity


@dataclass
class DetectionResult:
    """Verdict returned by a single detector."""

    detector: str
    matched: bool
    severity: Severity = Severity.INFO
    message: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class Detector(Protocol):
    """Protocol defining the interface for memory guard detectors.

    Detectors inspect memory read and write operations to identify security events,
    anomalies, or injections.

    Attributes:
        name: The unique string identifier of the detector.
    """

    name: str

    def inspect(self, key: str, value: Any, *, operation: str) -> DetectionResult:
        """Inspect a memory operation for security findings.

        Args:
            key: The memory key being accessed or written.
            value: The value being read or written.
            operation: The memory operation (e.g. 'read', 'write').

        Returns:
            DetectionResult: The verdict containing match status, severity,
                and details.
        """
        ...
