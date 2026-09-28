"""Security event and supporting types."""
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


class SourceType(str, Enum):
    """Provenance of a memory write — where the write came from."""
    USER_INPUT = "user_input"
    TOOL_OUTPUT = "tool_output"
    MODEL_INFERENCE = "model_inference"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class SourceClass(str, Enum):
    """Caller-supplied provenance class for self-reinforcement detection.

    The taxonomy comes from the three-layer ASI06 architecture discussed on
    microsoft/autogen#7683 — `external_tool` and `user_input` are external
    inputs (untrusted by default), `agent_authored` covers an agent writing
    back its own reasoning (the self-poisoning surface), `system` is
    config/admin/runtime infrastructure.

    SourceClass is metadata supplied by the caller. It does not authenticate a
    principal, verify source identity, or prove that content is trustworthy.
    Deployments must establish those properties independently before treating
    a provenance class as trusted corroboration.
    """
    EXTERNAL_TOOL = "external_tool"
    USER_INPUT = "user_input"
    AGENT_AUTHORED = "agent_authored"
    SYSTEM = "system"
    UNKNOWN = "unknown"


@dataclass
class SecurityEvent:
    """Structured record of a guard decision, suitable for SIEM forwarding.

    Attributes:
        detector: The name of the detector that triggered this event.
        severity: The severity level of the detected event.
        action: The mitigation action taken by the policy engine.
        key: The memory key being accessed.
        message: Descriptive log message outlining the finding.
        operation: The database/memory operation name. Defaults to "write".
        source_class: Caller-supplied provenance metadata for the write operation;
            not an authentication or identity assertion. Defaults to SourceClass.UNKNOWN.
        receipt_uri: Optional URI pointing to an external cryptographically signed audit receipt.
            Defaults to None.
        source_type: Legacy provenance type. Defaults to SourceType.UNKNOWN.
        metadata: Arbitrary additional event metadata. Defaults to an empty dict.
        timestamp: Epoch timestamp when the event was recorded. Defaults to current time.
        event_id: Unique string identifier for this event. Defaults to a random UUID.
    """

    detector: str
    severity: Severity
    action: Action
    key: str
    message: str
    operation: str = "write"
    source_class: SourceClass = SourceClass.UNKNOWN
    receipt_uri: str | None = None
    source_type: SourceType = SourceType.UNKNOWN
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
            "source_class": self.source_class.value,
            "receipt_uri": self.receipt_uri,
            "source_type": self.source_type.value,
            "metadata": self.metadata,
        }


__all__ = ["Action", "SecurityEvent", "Severity", "SourceClass", "SourceType"]
