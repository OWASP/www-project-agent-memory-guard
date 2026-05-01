from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(str, Enum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"
    QUARANTINE = "quarantine"


@dataclass
class SecurityEvent:
    """Structured record of a guard decision, suitable for SIEM forwarding."""

    detector: str
    severity: Severity
    action: Action
    key: str
    message: str
    operation: str = "write"
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "detector": self.detector,
            "severity": self.severity.value,
            "action": self.action.value,
            "operation": self.operation,
            "key": self.key,
            "message": self.message,
            "metadata": self.metadata,
        }
