"""Low-level hook for integrating Agent Memory Guard into AutoGen pipelines.

This module provides the core scanning logic that can be used standalone
or composed into higher-level abstractions like GuardedGroupChat.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Literal

from agent_memory_guard import MemoryGuard, Policy, PolicyViolation, SourceClass
from agent_memory_guard.storage import InMemoryStore
from autogen_agent_memory_guard.exceptions import MemoryGuardViolation

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result of scanning a message through the memory guard."""

    allowed: bool
    message_content: str
    violation_type: str | None = None
    latency_us: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)


class MemoryGuardHook:
    """Core hook that scans messages through Agent Memory Guard.

    This hook wraps the agent-memory-guard library and provides a simple
    interface for scanning AutoGen messages before they enter chat history.

    Args:
        policy: Security policy to enforce. Defaults to Policy.strict().
        on_violation: How to handle violations:
            - "block": Raise MemoryGuardViolation (default)
            - "warn": Log warning and allow message through
            - "strip": Replace violating content with a safe placeholder
            - "quarantine": Store in quarantine and replace with notice
        strip_replacement: Replacement text when on_violation="strip".
        enable_metrics: Whether to track scan metrics.
    """

    def __init__(
        self,
        policy: Policy | None = None,
        on_violation: Literal["block", "warn", "strip", "quarantine"] = "block",
        strip_replacement: str = "[Content removed by Agent Memory Guard - policy violation detected]",
        enable_metrics: bool = True,
    ) -> None:
        self._policy = policy or Policy.strict()
        self._on_violation = on_violation
        self._strip_replacement = strip_replacement
        self._enable_metrics = enable_metrics

        # Internal guard instance with in-memory store
        self._store = InMemoryStore()
        self._guard = MemoryGuard(self._store, policy=self._policy)

        # Metrics
        self._total_scans = 0
        self._violations_detected = 0
        self._total_latency_us = 0.0
        self._message_counter = 0

    @property
    def total_scans(self) -> int:
        """Total number of messages scanned."""
        return self._total_scans

    @property
    def violations_detected(self) -> int:
        """Total number of violations detected."""
        return self._violations_detected

    @property
    def avg_latency_us(self) -> float:
        """Average scan latency in microseconds."""
        if self._total_scans == 0:
            return 0.0
        return self._total_latency_us / self._total_scans

    def scan_message(
        self,
        content: str,
        sender: str = "unknown",
        role: str = "assistant",
        metadata: dict[str, Any] | None = None,
    ) -> ScanResult:
        """Scan a single message through the memory guard."""
        self._total_scans += 1
        self._message_counter += 1

        source_class = self._role_to_source_class(role)
        key = f"autogen.{sender}.msg.{self._message_counter}"

        start = time.perf_counter_ns()
        try:
            decision = self._guard.write(
                key,
                content,
                source=sender,
                source_class=source_class,
            )
            latency_us = (time.perf_counter_ns() - start) / 1000

            if self._enable_metrics:
                self._total_latency_us += latency_us

            if decision.value in ("require_approval", "require_corroboration"):
                # Keep pending content out of every forwarding mode and error text.
                raise MemoryGuardViolation(
                    message_content="",
                    violation_type=decision.value,
                    sender=sender,
                    details={"pending": True},
                )

            return ScanResult(
                allowed=True,
                message_content=content,
                latency_us=latency_us,
            )

        except PolicyViolation as exc:
            latency_us = (time.perf_counter_ns() - start) / 1000
            self._violations_detected += 1

            if self._enable_metrics:
                self._total_latency_us += latency_us

            violation_type = self._extract_violation_type(exc)

            result = ScanResult(
                allowed=False,
                message_content=content,
                violation_type=violation_type,
                latency_us=latency_us,
                details={"exception": str(exc), "sender": sender, "role": role},
            )

            return self._handle_violation(result, sender)

    def _handle_violation(self, result: ScanResult, sender: str) -> ScanResult:
        """Handle a detected violation based on the configured mode."""
        if self._on_violation == "block":
            raise MemoryGuardViolation(
                message_content=result.message_content,
                violation_type=result.violation_type or "unknown",
                sender=sender,
                details=result.details,
            )
        elif self._on_violation == "warn":
            logger.warning(
                "Memory guard violation [%s] from '%s': %s",
                result.violation_type,
                sender,
                result.message_content[:100],
            )
            result.allowed = True
            return result
        elif self._on_violation == "strip":
            result.message_content = self._strip_replacement
            result.allowed = True
            return result
        elif self._on_violation == "quarantine":
            logger.warning(
                "Quarantined message from '%s': %s",
                sender,
                result.violation_type,
            )
            result.message_content = (
                f"[Message quarantined by Agent Memory Guard - "
                f"{result.violation_type} detected from {sender}]"
            )
            result.allowed = True
            return result
        else:
            raise ValueError(f"Unknown violation mode: {self._on_violation}")

    @staticmethod
    def _role_to_source_class(role: str) -> SourceClass:
        """Map AutoGen message roles to AMG source classes."""
        mapping = {
            "user": SourceClass.USER_INPUT,
            "assistant": SourceClass.AGENT_AUTHORED,
            "tool": SourceClass.EXTERNAL_TOOL,
            "system": SourceClass.SYSTEM,
            "function": SourceClass.EXTERNAL_TOOL,
        }
        return mapping.get(role, SourceClass.AGENT_AUTHORED)

    @staticmethod
    def _extract_violation_type(exc: PolicyViolation) -> str:
        """Extract the violation type from a PolicyViolation exception."""
        exc_str = str(exc).lower()
        if "injection" in exc_str:
            return "prompt_injection"
        elif "secret" in exc_str or "sensitive" in exc_str:
            return "sensitive_data"
        elif "protected" in exc_str:
            return "protected_key"
        elif "size" in exc_str:
            return "size_anomaly"
        return "policy_violation"

    def get_metrics(self) -> dict[str, Any]:
        """Return current scan metrics."""
        return {
            "total_scans": self._total_scans,
            "violations_detected": self._violations_detected,
            "violation_rate": (
                self._violations_detected / self._total_scans
                if self._total_scans > 0
                else 0.0
            ),
            "avg_latency_us": self.avg_latency_us,
            "total_latency_us": self._total_latency_us,
        }

    def reset_metrics(self) -> None:
        """Reset all scan metrics."""
        self._total_scans = 0
        self._violations_detected = 0
        self._total_latency_us = 0.0
