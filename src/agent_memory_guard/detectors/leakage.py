from __future__ import annotations

import re
from typing import Any, Iterable

from agent_memory_guard.detectors.base import DetectionResult
from agent_memory_guard.detectors.injection import _stringify
from agent_memory_guard.events import Severity


DEFAULT_LEAKAGE_PATTERNS: dict[str, str] = {
    "aws_access_key": r"\bAKIA[0-9A-Z]{16}\b",
    "aws_secret_key": r"(?i)aws(.{0,20})?(secret|private)?[\s_-]?access[\s_-]?key[\s_-]?[:=][\s\"']*([A-Za-z0-9/+=]{40})",
    "github_token": r"\bghp_[A-Za-z0-9]{36}\b",
    "github_oauth": r"\bgho_[A-Za-z0-9]{36}\b",
    "openai_key": r"\bsk-[A-Za-z0-9_-]{20,}\b",
    "anthropic_key": r"\bsk-ant-[A-Za-z0-9_-]{20,}\b",
    "google_api_key": r"\bAIza[0-9A-Za-z_-]{35}\b",
    "slack_token": r"\bxox[abpr]-[0-9A-Za-z-]{10,}\b",
    "private_key_pem": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "jwt": r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "credit_card": r"\b(?:\d[ -]*?){13,19}\b",
    "ssn_us": r"\b\d{3}-\d{2}-\d{4}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
}


class SensitiveDataDetector:
    """Flags secrets/PII present in memory values prior to write or after read."""

    name = "sensitive_data"

    def __init__(
        self,
        patterns: dict[str, str] | None = None,
        ignore: Iterable[str] = ("email",),
        severity: Severity = Severity.HIGH,
    ) -> None:
        merged = dict(DEFAULT_LEAKAGE_PATTERNS) if patterns is None else dict(patterns)
        for name in ignore:
            merged.pop(name, None)
        self._patterns = {name: re.compile(p) for name, p in merged.items()}
        self._severity = severity

    def inspect(self, key: str, value: Any, *, operation: str) -> DetectionResult:
        text = _stringify(value)
        if not text:
            return DetectionResult(self.name, matched=False)

        findings: list[str] = []
        for label, pattern in self._patterns.items():
            if pattern.search(text):
                findings.append(label)

        if not findings:
            return DetectionResult(self.name, matched=False)

        return DetectionResult(
            detector=self.name,
            matched=True,
            severity=self._severity,
            message=f"Sensitive data ({', '.join(findings)}) detected in '{key}'",
            metadata={"categories": findings, "operation": operation},
        )

    def redact(self, value: Any) -> Any:
        text = _stringify(value)
        for label, pattern in self._patterns.items():
            text = pattern.sub(f"[REDACTED:{label}]", text)
        return text
