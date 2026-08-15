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


#: Confidence assigned to a match at each severity, for callers that report a
#: single 0.0-1.0 score. A detector that computes a real score puts it in
#: ``metadata["confidence"]`` and that value is preferred over this table.
_SEVERITY_CONFIDENCE: dict[Severity, float] = {
    Severity.INFO: 0.10,
    Severity.LOW: 0.30,
    Severity.MEDIUM: 0.60,
    Severity.HIGH: 0.85,
    Severity.CRITICAL: 0.99,
}


def detection_confidence(result: DetectionResult) -> float:
    """Return a 0.0-1.0 confidence for a detection result.

    ``DetectionResult`` carries a severity rather than a score, because most
    detectors are pattern-based and have no meaningful probability to report.
    Callers that present a single confidence therefore derive one from the
    severity, unless the detector supplied a real score in its metadata.

    A result that did not match has confidence 0.0.
    """

    if not result.matched:
        return 0.0
    supplied = result.metadata.get("confidence")
    if isinstance(supplied, (int, float)) and not isinstance(supplied, bool):
        return float(supplied)
    return _SEVERITY_CONFIDENCE.get(result.severity, 0.5)


def scan_text(detector: Detector, text: Any, *, key: str = "", operation: str = "scan") -> DetectionResult:
    """Run a detector over a standalone piece of text.

    The detector protocol is built around memory operations and takes a key
    alongside the value. Text-scanning entry points have no key, so they pass
    an empty one and name the operation "scan".
    """

    return detector.inspect(key, text, operation=operation)
