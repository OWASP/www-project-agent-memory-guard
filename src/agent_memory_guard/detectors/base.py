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
    name: str

    def inspect(self, key: str, value: Any, *, operation: str) -> DetectionResult: ...
