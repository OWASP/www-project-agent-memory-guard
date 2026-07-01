from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from agent_memory_guard.detectors.base import DetectionResult
from agent_memory_guard.detectors.injection import _stringify
from agent_memory_guard.events import Severity

DEFAULT_PERSISTENCE_INJECTION_PATTERNS: tuple[str, ...] = (
    r"(?i)\bignore\s+(?:previous|prior|all|earlier)\s+(?:instructions?|prompts?|rules?)\b[^.]{0,80}\b"
    r"(?:once\s+stored|after\s+saving|when\s+persisted|in\s+future\s+turns?|from\s+now\s+on)\b",
    r"(?i)\b(?:store|save|persist|remember|memorize)\s+(?:this|the\s+following)\s+as\s+(?:a\s+)?"
    r"(?:system|root|admin)\s+(?:instruction|prompt|directive)\b",
    r"\[(?:SYSTEM[-_\s]?MEMORY[-_\s]?PERSIST|MEMORY[-_\s]?PERSIST|PERSIST[-_\s]?INSTRUCTION|"
    r"REMEMBER[-_\s]?ALWAYS)\]",
    r"\[user_memory\s*=\s*[^\]]{5,200}\]\s*\[user_memory\s*=",
    r"(?im)^\s*(?:SYSTEM|ASSISTANT|DEVELOPER|ROOT)\s*[:>][^.]{0,200}\b"
    r"(?:you\s+are|act\s+as|pretend\s+to\s+be|from\s+now\s+on)\b",
)


class MemoryPersistenceInjectionDetector:
    """Flags memory writes whose payload only matters on a *later* read.

    Ordinary prompt-injection detectors screen the current turn. This detector
    targets a different moment: a value is being written into durable memory
    (long-term store, chat-memory advisor, vector store) and the payload is
    shaped to activate on a *future* retrieval rather than the current one —
    e.g. a directive is paired with "once stored" / "from now on", a
    persistence canary token, a forged prior-turn marker, or a role-tag
    prefix intended to be replayed as a trusted system/assistant turn later.

    This complements ``PromptInjectionDetector`` (which catches immediate
    override attempts) by covering the delayed-activation / sleeper-payload
    shape that is specific to the memory-write surface.

    Attributes:
        name: The unique identifier for this detector.
    """

    name = "memory_persistence_injection"

    def __init__(
        self,
        patterns: Iterable[str] = DEFAULT_PERSISTENCE_INJECTION_PATTERNS,
        severity: Severity = Severity.HIGH,
    ) -> None:
        self._patterns = [re.compile(p, re.DOTALL) for p in patterns]
        self._severity = severity

    def inspect(self, key: str, value: Any, *, operation: str) -> DetectionResult:
        """Inspect a memory write for delayed-activation persistence payloads.

        Args:
            key: The memory key being targeted.
            value: The data value to inspect.
            operation: The memory operation being performed. Only 'write'
                operations are inspected; a delayed payload has no effect
                until it is written and later read back.

        Returns:
            DetectionResult: The check result including matched pattern
                snippets if any.
        """
        if operation != "write":
            return DetectionResult(self.name, matched=False)

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
            message=f"Possible delayed-activation memory persistence payload in '{key}'",
            metadata={"hits": hits[:5], "operation": operation},
        )


__all__ = ["MemoryPersistenceInjectionDetector", "DEFAULT_PERSISTENCE_INJECTION_PATTERNS"]
