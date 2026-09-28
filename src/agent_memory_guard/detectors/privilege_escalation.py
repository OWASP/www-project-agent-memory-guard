"""Privilege Escalation Detector — detects attempts to elevate agent permissions via memory.

Catches attempts to:
- Modify agent role/permission levels stored in memory
- Inject admin/root access grants into memory
- Override access control lists via memory poisoning
- Escalate trust levels through memory manipulation
"""
from __future__ import annotations

import re
from typing import Any

from agent_memory_guard.detectors.base import DetectionResult
from agent_memory_guard.detectors.injection import _stringify
from agent_memory_guard.events import Severity

# Keys that are sensitive for privilege escalation
SENSITIVE_KEY_PATTERNS = [
    re.compile(r"(?:role|permission|access|privilege|trust|auth)", re.IGNORECASE),
    re.compile(r"(?:admin|root|sudo|superuser|owner|system)", re.IGNORECASE),
    re.compile(r"(?:allowed_tools|capabilities|scope|grants)", re.IGNORECASE),
]

# Value patterns indicating privilege escalation
ESCALATION_PATTERNS: list[tuple[re.Pattern[str], str, Severity]] = [
    # Direct role assignment
    (
        re.compile(
            r"(?:role|access_level|permission_level)\s*[:=]\s*['\"]?(?:admin|root|superuser|owner|system|god)",
            re.IGNORECASE,
        ),
        "Direct admin/root role assignment",
        Severity.CRITICAL,
    ),
    # Trust level manipulation
    (
        re.compile(
            r"(?:trust_level|confidence|authority)\s*[:=]\s*(?:['\"]?(?:full|maximum|unlimited|unrestricted)|1\.0|100)",
            re.IGNORECASE,
        ),
        "Trust level set to maximum/unrestricted",
        Severity.HIGH,
    ),
    # Capability expansion
    (
        re.compile(
            r"(?:can|allowed_to|permitted_to|capabilities)\s*[:=].*(?:all|everything|\*|unlimited)",
            re.IGNORECASE,
        ),
        "Unrestricted capability grant",
        Severity.HIGH,
    ),
    # Access control bypass
    (
        re.compile(
            r"(?:bypass|skip|disable|ignore)\s+(?:auth|authentication|authorization|access.?control|security|validation)",
            re.IGNORECASE,
        ),
        "Access control bypass instruction",
        Severity.CRITICAL,
    ),
    # Scope expansion
    (
        re.compile(
            r"(?:scope|access)\s*[:=]\s*['\"]?(?:global|all|unrestricted|\*)",
            re.IGNORECASE,
        ),
        "Scope expanded to global/unrestricted",
        Severity.HIGH,
    ),
    # Tool access expansion
    (
        re.compile(
            r"(?:tools?|functions?|actions?)\s*[:=]\s*\[?\s*['\"]?\*['\"]?\s*\]?",
            re.IGNORECASE,
        ),
        "Wildcard tool access grant",
        Severity.HIGH,
    ),
    # Guardrail disabling
    (
        re.compile(
            r"(?:guardrails?|safety|filters?|moderation)\s*[:=]\s*(?:false|off|disabled|none|0)",
            re.IGNORECASE,
        ),
        "Safety guardrails disabled",
        Severity.CRITICAL,
    ),
    # Self-modification permission
    (
        re.compile(
            r"(?:self_modify|auto_update|self_evolve|modify_own)\s*[:=]\s*(?:true|enabled|allowed|1)",
            re.IGNORECASE,
        ),
        "Self-modification permission granted",
        Severity.HIGH,
    ),
]


class PrivilegeEscalationDetector:
    """Detects attempts to escalate agent privileges via memory manipulation.

    This detector monitors memory writes for patterns that indicate
    attempts to:
    - Assign admin/root roles to the agent
    - Disable safety guardrails
    - Expand tool access beyond intended scope
    - Bypass authentication/authorization
    - Grant self-modification capabilities
    """

    name = "privilege_escalation"

    def __init__(self, severity: Severity = Severity.HIGH) -> None:
        self._severity = severity

    def inspect(self, key: str, value: Any, *, operation: str) -> DetectionResult:
        """Check for privilege escalation patterns."""
        text = _stringify(value)
        if not text:
            return DetectionResult(self.name, matched=False)

        hits: list[dict[str, str]] = []

        # Check if key itself is a sensitive permission key
        key_is_sensitive = any(p.search(key) for p in SENSITIVE_KEY_PATTERNS)

        # Check value patterns
        for pattern, description, severity in ESCALATION_PATTERNS:
            match = pattern.search(text)
            if match:
                # Increase severity if writing to a sensitive key
                _sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                _sev_upgrade = {"info": "low", "low": "medium", "medium": "high", "high": "critical", "critical": "critical"}
                effective_severity = severity
                if key_is_sensitive and _sev_order.get(severity.value, 0) < 4:
                    effective_severity = Severity(_sev_upgrade[severity.value])
                hits.append(
                    {
                        "pattern": description,
                        "severity": effective_severity.value,
                        "matched_text": match.group(0)[:100],
                        "key_sensitive": str(key_is_sensitive),
                    }
                )

        if not hits:
            return DetectionResult(self.name, matched=False)

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
            message=(
                f"Privilege escalation attempt in '{key}': {hits[0]['pattern']}"
                f"{' (sensitive key)' if key_is_sensitive else ''}"
            ),
            metadata={
                "hits": hits[:5],
                "total_hits": len(hits),
                "key_sensitive": key_is_sensitive,
                "operation": operation,
            },
        )
