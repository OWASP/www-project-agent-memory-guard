"""Excessive Autonomy Detector — detects attempts to grant agents unchecked autonomy.

Catches attempts to:
- Remove human-in-the-loop requirements from memory
- Store instructions that bypass approval workflows
- Grant unlimited action budgets or iteration limits
- Disable confirmation prompts for destructive actions
- Enable autonomous decision-making without oversight

Maps to OWASP Top 10 for LLM: LLM08 (Excessive Agency)
"""
from __future__ import annotations

import re
from typing import Any

from agent_memory_guard.detectors.base import DetectionResult
from agent_memory_guard.detectors.injection import _stringify
from agent_memory_guard.events import Severity

AUTONOMY_PATTERNS: list[tuple[re.Pattern[str], str, Severity]] = [
    # Removing human oversight
    (
        re.compile(
            r"(?:human_(?:in_the_loop|oversight|approval|review))\s*[:=]\s*(?:false|off|disabled|none|0|never)",
            re.IGNORECASE,
        ),
        "Human oversight disabled",
        Severity.CRITICAL,
    ),
    # Unlimited iterations/actions
    (
        re.compile(
            r"(?:max_(?:iterations|actions|steps|retries|loops))\s*[:=]\s*(?:inf|infinity|unlimited|None|-1|999999)",
            re.IGNORECASE,
        ),
        "Unlimited action budget set",
        Severity.HIGH,
    ),
    # Auto-approve all actions
    (
        re.compile(
            r"(?:auto_(?:approve|execute|confirm|run))\s*[:=]\s*(?:true|all|always|1|enabled)",
            re.IGNORECASE,
        ),
        "Auto-approval for all actions enabled",
        Severity.HIGH,
    ),
    # Bypass confirmation
    (
        re.compile(
            r"(?:require_confirmation|confirm_before|ask_before)\s*[:=]\s*(?:false|never|none|0|disabled)",
            re.IGNORECASE,
        ),
        "Action confirmation requirement removed",
        Severity.HIGH,
    ),
    # Autonomous mode activation
    (
        re.compile(
            r"(?:autonomous_mode|full_autonomy|unsupervised|unattended)\s*[:=]\s*(?:true|enabled|active|1)",
            re.IGNORECASE,
        ),
        "Autonomous mode activated without oversight",
        Severity.HIGH,
    ),
    # Budget/cost limit removal
    (
        re.compile(
            r"(?:budget|cost_limit|spending_limit|token_limit)\s*[:=]\s*(?:unlimited|inf|None|-1|999999)",
            re.IGNORECASE,
        ),
        "Budget/cost limits removed",
        Severity.MEDIUM,
    ),
    # Instruction to act without asking
    (
        re.compile(
            r"(?:do\s+not|don'?t|never)\s+(?:ask|confirm|check|verify|wait)\s+(?:before|for\s+(?:approval|permission))",
            re.IGNORECASE,
        ),
        "Instruction to act without confirmation",
        Severity.HIGH,
    ),
    # Unrestricted tool usage
    (
        re.compile(
            r"(?:use\s+any\s+tool|all\s+tools?\s+(?:available|allowed|permitted)|no\s+tool\s+restrictions)",
            re.IGNORECASE,
        ),
        "Unrestricted tool usage instruction",
        Severity.MEDIUM,
    ),
    # Disable rate limiting
    (
        re.compile(
            r"(?:rate_limit|throttle|cooldown)\s*[:=]\s*(?:0|none|disabled|off|false)",
            re.IGNORECASE,
        ),
        "Rate limiting disabled",
        Severity.MEDIUM,
    ),
    # Self-spawning agents
    (
        re.compile(
            r"(?:spawn|create|fork|clone)\s+(?:new\s+)?(?:agent|worker|subprocess|task)\s*(?:without|no)\s*(?:limit|restriction|approval)",
            re.IGNORECASE,
        ),
        "Unrestricted agent spawning",
        Severity.HIGH,
    ),
]


class ExcessiveAutonomyDetector:
    """Detects attempts to grant agents excessive autonomy via memory manipulation.

    This detector monitors for patterns that would remove human oversight,
    disable confirmation requirements, or grant unlimited action budgets
    to AI agents through memory poisoning.

    Maps to OWASP Top 10 for LLM Applications: LLM08 (Excessive Agency).
    """

    name = "excessive_autonomy"

    def __init__(self, severity: Severity = Severity.HIGH) -> None:
        self._severity = severity

    def inspect(self, key: str, value: Any, *, operation: str) -> DetectionResult:
        """Check for excessive autonomy patterns."""
        text = _stringify(value)
        if not text:
            return DetectionResult(self.name, matched=False)

        hits: list[dict[str, str]] = []

        for pattern, description, severity in AUTONOMY_PATTERNS:
            match = pattern.search(text)
            if match:
                hits.append(
                    {
                        "pattern": description,
                        "severity": severity.value,
                        "matched_text": match.group(0)[:100],
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
            message=f"Excessive autonomy pattern in '{key}': {hits[0]['pattern']}",
            metadata={
                "hits": hits[:5],
                "total_hits": len(hits),
                "owasp_mapping": "LLM08 (Excessive Agency)",
                "operation": operation,
            },
        )
