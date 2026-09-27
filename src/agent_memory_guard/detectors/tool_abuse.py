"""Tool Abuse Detector — detects unauthorized or suspicious tool usage patterns.

Catches attempts to:
- Store tool call results that grant escalated permissions
- Record tool outputs that modify agent behavior/instructions
- Inject tool-call-like structures into memory to trick agents
- Store tool outputs containing shell commands or code execution
"""
from __future__ import annotations

import re
from typing import Any

from agent_memory_guard.detectors.base import DetectionResult
from agent_memory_guard.detectors.injection import _stringify
from agent_memory_guard.events import Severity

# Patterns that indicate tool abuse attempts
TOOL_ABUSE_PATTERNS: list[tuple[re.Pattern[str], str, Severity]] = [
    # Fake tool call structures injected into memory
    (
        re.compile(
            r'\{\s*"(?:tool_call|function_call|action)".*"(?:name|function)".*"(?:arguments|input)"',
            re.DOTALL,
        ),
        "Fake tool call structure injected into memory",
        Severity.HIGH,
    ),
    # Shell command execution via tool output
    (
        re.compile(
            r"(?:subprocess|os\.system|os\.popen|exec|eval)\s*\(.*\)|"
            r"(?:bash|sh|cmd|powershell)\s+-c\s+",
            re.IGNORECASE,
        ),
        "Shell command execution pattern in tool output",
        Severity.CRITICAL,
    ),
    # Permission escalation via tool output
    (
        re.compile(
            r"(?:grant|assign|elevate|escalate)\s+(?:admin|root|sudo|superuser|owner)\s+(?:access|permission|role|privilege)",
            re.IGNORECASE,
        ),
        "Permission escalation attempt via tool output",
        Severity.HIGH,
    ),
    # Agent instruction override via tool result
    (
        re.compile(
            r"(?:new|updated|revised)\s+(?:system\s+)?(?:instructions?|directives?|rules?)\s*[:\-=]",
            re.IGNORECASE,
        ),
        "Agent instruction override via tool result",
        Severity.HIGH,
    ),
    # Data exfiltration patterns
    (
        re.compile(
            r"(?:send|post|upload|exfiltrate|transmit)\s+(?:to|data|all|everything)\s+(?:to\s+)?(?:https?://|ftp://)",
            re.IGNORECASE,
        ),
        "Data exfiltration pattern detected",
        Severity.CRITICAL,
    ),
    # Unauthorized file system access
    (
        re.compile(
            r"(?:read|write|delete|modify|access)\s+(?:file|directory|folder|path)\s*[:\-=]\s*['\"/]",
            re.IGNORECASE,
        ),
        "Unauthorized file system access pattern",
        Severity.MEDIUM,
    ),
]

# Patterns indicating tool output that should not be stored directly
UNSAFE_TOOL_OUTPUT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"<\s*(?:script|iframe|object|embed)\b", re.IGNORECASE),
        "HTML injection in tool output",
    ),
    (
        re.compile(r"(?:DROP|DELETE|ALTER|TRUNCATE)\s+(?:TABLE|DATABASE|INDEX)", re.IGNORECASE),
        "SQL injection in tool output",
    ),
    (
        re.compile(r"__(?:import|builtins|class|subclasses)__", re.IGNORECASE),
        "Python code injection in tool output",
    ),
]


class ToolAbuseDetector:
    """Detects unauthorized or suspicious tool usage patterns in memory writes.

    This detector catches attempts to:
    - Inject fake tool call structures into memory
    - Store tool outputs that contain code execution commands
    - Record permission escalation attempts via tool results
    - Exfiltrate data through tool output storage
    """

    name = "tool_abuse"

    def __init__(self, severity: Severity = Severity.HIGH) -> None:
        self._severity = severity

    def inspect(self, key: str, value: Any, *, operation: str) -> DetectionResult:
        """Check for tool abuse patterns in the value."""
        text = _stringify(value)
        if not text or len(text) < 5:
            return DetectionResult(self.name, matched=False)

        hits: list[dict[str, str]] = []

        # Check main tool abuse patterns
        for pattern, description, severity in TOOL_ABUSE_PATTERNS:
            match = pattern.search(text)
            if match:
                hits.append(
                    {
                        "pattern": description,
                        "severity": severity.value,
                        "matched_text": match.group(0)[:100],
                    }
                )

        # Check unsafe tool output patterns
        for pattern, description in UNSAFE_TOOL_OUTPUT_PATTERNS:
            match = pattern.search(text)
            if match:
                hits.append(
                    {
                        "pattern": description,
                        "severity": Severity.HIGH.value,
                        "matched_text": match.group(0)[:100],
                    }
                )

        if not hits:
            return DetectionResult(self.name, matched=False)

        # Use the highest severity found
        _sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        max_severity = max(
            (Severity(h["severity"]) for h in hits),
            key=lambda s: _sev_order.get(s.value, 0),
            default=self._severity,
        )

        return DetectionResult(
            detector=self.name,
            matched=True,
            severity=max_severity,
            message=f"Tool abuse pattern detected in '{key}': {hits[0]['pattern']}",
            metadata={
                "hits": hits[:5],
                "total_hits": len(hits),
                "operation": operation,
            },
        )
