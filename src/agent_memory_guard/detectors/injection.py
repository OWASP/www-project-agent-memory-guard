from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from agent_memory_guard.detectors.base import DetectionResult
from agent_memory_guard.events import Severity

DEFAULT_INJECTION_PATTERNS: tuple[str, ...] = (
    r"ignore (?:all |any |the )?(?:previous|prior|above) (?:instructions|messages|rules)",
    r"disregard (?:all |any |the )?(?:previous|prior|above) (?:instructions|messages|rules)",
    r"forget (?:all |any |the )?(?:previous|prior|above) (?:instructions|messages|rules)",
    r"\byou are now\b.{0,40}(?:dan|jailbroken|admin|root|developer mode)",
    r"\bsystem\s*[:\-]\s*you (?:are|must|will)",
    r"</?\s*(?:system|assistant|tool)\s*>",
    r"\bact as (?:an? )?(?:admin|root|system|developer|unrestricted)",
    r"\b(?:reveal|print|leak|dump|exfiltrate)\s+(?:the\s+)?(?:system\s+)?(?:prompt|instructions|secrets|api[_\s-]?key)",
    r"\bnew (?:instructions|directive|persona)\s*[:\-]",
    r"\boverride\s+(?:safety|security|guardrails|policy)",
)


class PromptInjectionDetector:
    """Regex-based screen for indirect prompt-injection markers in memory values.

    This detector monitors memory inputs for common injection keywords, instructions
    overrides, jailbreak phrases, and system prompt leakage attempts.

    Attributes:
        name: The unique identifier for this detector.
    """

    name = "prompt_injection"

    def __init__(
        self,
        patterns: Iterable[str] = DEFAULT_INJECTION_PATTERNS,
        severity: Severity = Severity.HIGH,
    ) -> None:
        self._patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]
        self._severity = severity

    def inspect(self, key: str, value: Any, *, operation: str) -> DetectionResult:
        """Inspect a memory value for potential prompt injection patterns.

        Args:
            key: The memory key being targeted.
            value: The data value to inspect.
            operation: The memory operation being performed.

        Returns:
            DetectionResult: The check result including list of pattern matches if any.
        """
        text = _stringify(value)
        if not text:
            return DetectionResult(self.name, matched=False)

        hits: list[str] = []
        for pattern in self._patterns:
            match = pattern.search(text)
            if match:
                hits.append(match.group(0))

        if not hits:
            return DetectionResult(self.name, matched=False)

        return DetectionResult(
            detector=self.name,
            matched=True,
            severity=self._severity,
            message=f"Possible prompt-injection markers in '{key}'",
            metadata={"hits": hits[:5], "operation": operation},
        )


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple, set)):
        return "\n".join(_stringify(v) for v in value)
    if isinstance(value, dict):
        return "\n".join(f"{k}: {_stringify(v)}" for k, v in value.items())
    return str(value)
