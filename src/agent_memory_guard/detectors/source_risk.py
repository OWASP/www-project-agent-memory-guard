from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Protocol

from agent_memory_guard.detectors.base import DetectionResult
from agent_memory_guard.detectors.injection import _stringify
from agent_memory_guard.events import Severity, SourceClass

log = logging.getLogger("agent_memory_guard.source_risk")


@dataclass(frozen=True)
class SourceRiskAssessment:
    """Structured semantic assessment returned by a source-risk evaluator."""

    attack_probability: float
    claim_type: str = "unknown"
    claimed_subject: str = "unknown"
    confidence: float = 0.0
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "attack_probability", _clamp01(float(self.attack_probability))
        )
        object.__setattr__(self, "confidence", _clamp01(float(self.confidence)))


class SourceRiskEvaluator(Protocol):
    """Provider contract for semantic memory-poisoning assessments."""

    def assess(
        self,
        *,
        key: str,
        value: Any,
        source_class: SourceClass,
        operation: str,
    ) -> SourceRiskAssessment: ...


@dataclass(frozen=True)
class OpenAICompatibleEvaluator:
    """Optional evaluator that calls an OpenAI-compatible chat completions API.

    This is intentionally dependency-free and uses stdlib ``urllib`` so the
    project can keep the core package lightweight. Callers are expected to
    provide an API key and model either explicitly or via environment:

    - ``AMG_SOURCE_RISK_API_KEY``
    - ``AMG_SOURCE_RISK_MODEL``
    - ``AMG_SOURCE_RISK_BASE_URL`` (optional)
    """

    api_key: str | None = None
    model: str | None = None
    base_url: str = "https://api.openai.com/v1"
    provider: str | None = None
    site_url: str | None = None
    app_name: str | None = None
    dotenv_path: str | None = ".env"
    timeout_seconds: float = 15.0

    def __post_init__(self) -> None:
        _load_dotenv(self.dotenv_path)
        provider = (
            self.provider
            or os.environ.get("AMG_SOURCE_RISK_PROVIDER")
            or ("openrouter" if os.environ.get("OPENROUTER_API_KEY") else "openai")
        ).lower()
        object.__setattr__(self, "provider", provider)
        if self.api_key is None:
            object.__setattr__(
                self,
                "api_key",
                _resolve_api_key(provider),
            )
        if self.model is None:
            object.__setattr__(self, "model", _resolve_model(provider))
        env_base = os.environ.get("AMG_SOURCE_RISK_BASE_URL")
        if env_base:
            object.__setattr__(self, "base_url", env_base.rstrip("/"))
        elif (
            provider == "openrouter"
            and self.base_url == "https://api.openai.com/v1"
        ):
            object.__setattr__(self, "base_url", "https://openrouter.ai/api/v1")
        if self.site_url is None:
            object.__setattr__(
                self, "site_url", os.environ.get("AMG_SOURCE_RISK_SITE_URL")
            )
        if self.app_name is None:
            object.__setattr__(
                self, "app_name", os.environ.get("AMG_SOURCE_RISK_APP_NAME")
            )

    def assess(
        self,
        *,
        key: str,
        value: Any,
        source_class: SourceClass,
        operation: str,
    ) -> SourceRiskAssessment:
        if not self.api_key or not self.model:
            raise RuntimeError(
                "OpenAICompatibleEvaluator requires api_key and model "
                "(or AMG_SOURCE_RISK_API_KEY / AMG_SOURCE_RISK_MODEL)"
            )

        payload = {
            "model": self.model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a security classifier for agent memory writes. "
                        "Return JSON with keys: attack_probability, claim_type, "
                        "claimed_subject, confidence, reason. "
                        "attack_probability and confidence must be floats in [0,1]. "
                        "claim_type should be one of: user_preference, identity_claim, "
                        "policy_claim, tool_observation, retrieved_fact, instruction_claim, unknown. "
                        "claimed_subject should be one of: user, system, agent, third_party, unknown."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "key": key,
                            "value": _stringify(value)[:4000],
                            "source_class": source_class.value,
                            "operation": operation,
                        },
                        ensure_ascii=False,
                    ),
                },
            ],
        }
        request = urllib.request.Request(
            url=f"{self.base_url.rstrip('/')}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers=_build_headers(
                api_key=self.api_key,
                provider=self.provider or "openai",
                site_url=self.site_url,
                app_name=self.app_name,
            ),
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout_seconds
            ) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:  # pragma: no cover - network path
            raise RuntimeError(f"source-risk evaluator request failed: {exc}") from exc

        try:
            content = body["choices"][0]["message"]["content"]
            parsed = json.loads(content)
        except (KeyError, IndexError, json.JSONDecodeError) as exc:
            raise RuntimeError("source-risk evaluator returned invalid JSON") from exc

        return SourceRiskAssessment(
            attack_probability=parsed.get("attack_probability", 0.0),
            claim_type=str(parsed.get("claim_type", "unknown")),
            claimed_subject=str(parsed.get("claimed_subject", "unknown")),
            confidence=parsed.get("confidence", 0.0),
            reason=str(parsed.get("reason", "")),
            metadata={
                "provider": self.provider or "openai",
                "backend": "openai_compatible",
                "model": self.model,
            },
        )


DEFAULT_SOURCE_WEIGHTS: dict[SourceClass, float] = {
    SourceClass.SYSTEM: 0.0,
    SourceClass.USER_INPUT: 0.15,
    SourceClass.AGENT_AUTHORED: 0.45,
    SourceClass.EXTERNAL_TOOL: 0.8,
    SourceClass.UNKNOWN: 0.9,
}

DEFAULT_TARGET_SENSITIVITY: tuple[tuple[str, float], ...] = (
    ("policies.*", 1.0),
    ("identity.*", 1.0),
    ("preferences.*", 0.9),
    ("facts.*", 0.5),
    ("tool_results.*", 0.2),
    ("scratch.*", 0.1),
)


class SourceRiskDetector:
    """Source-aware semantic detector for memory poisoning risk.

    The detector combines:
    - semantic attack probability from a provider
    - prior risk associated with the write's ``source_class``
    - sensitivity of the target memory namespace
    - authority mismatches (e.g. external tool -> preferences.*)
    """

    name = "source_risk"

    def __init__(
        self,
        evaluator: SourceRiskEvaluator,
        *,
        risk_threshold: float = 0.6,
        min_confidence: float = 0.0,
        source_weights: dict[SourceClass, float] | None = None,
        target_sensitivity: tuple[tuple[str, float], ...] = DEFAULT_TARGET_SENSITIVITY,
    ) -> None:
        self._evaluator = evaluator
        self._risk_threshold = _clamp01(risk_threshold)
        self._min_confidence = _clamp01(min_confidence)
        self._source_weights = dict(DEFAULT_SOURCE_WEIGHTS)
        if source_weights:
            self._source_weights.update(source_weights)
        self._target_sensitivity = target_sensitivity

    def inspect(self, key: str, value: Any, *, operation: str) -> DetectionResult:
        if operation != "write":
            return DetectionResult(self.name, matched=False)

        text = _stringify(value)
        if not text:
            return DetectionResult(self.name, matched=False)

        source_class: SourceClass = getattr(
            self, "_pending_source_class", SourceClass.UNKNOWN
        )

        try:
            assessment = self._evaluator.assess(
                key=key,
                value=value,
                source_class=source_class,
                operation=operation,
            )
        except Exception:
            log.exception("SourceRiskDetector evaluator failed")
            return DetectionResult(self.name, matched=False)

        if assessment.confidence < self._min_confidence:
            return DetectionResult(self.name, matched=False)

        target_sensitivity = _target_sensitivity_for(key, self._target_sensitivity)
        source_risk = self._source_weights.get(source_class, DEFAULT_SOURCE_WEIGHTS[SourceClass.UNKNOWN])
        authority_mismatch = _authority_mismatch(
            key=key,
            source_class=source_class,
            claim_type=assessment.claim_type,
            claimed_subject=assessment.claimed_subject,
        )
        final_risk = min(
            1.0,
            (assessment.attack_probability * 0.45)
            + (source_risk * 0.25)
            + (target_sensitivity * 0.15)
            + (0.25 if authority_mismatch else 0.0),
        )

        if final_risk < self._risk_threshold:
            return DetectionResult(self.name, matched=False)

        severity = _severity_for(final_risk)
        mismatch_text = " with authority mismatch" if authority_mismatch else ""
        reason = assessment.reason or "semantic source-risk assessment"
        return DetectionResult(
            detector=self.name,
            matched=True,
            severity=severity,
            message=(
                f"Source-aware poisoning risk on '{key}'{mismatch_text}: "
                f"{reason}"
            ),
            metadata={
                "attack_probability": round(assessment.attack_probability, 4),
                "claim_type": assessment.claim_type,
                "claimed_subject": assessment.claimed_subject,
                "confidence": round(assessment.confidence, 4),
                "source_class": source_class.value,
                "target_sensitivity": round(target_sensitivity, 4),
                "source_risk": round(source_risk, 4),
                "authority_mismatch": authority_mismatch,
                "final_risk": round(final_risk, 4),
                **assessment.metadata,
            },
        )


def _target_sensitivity_for(
    key: str, patterns: tuple[tuple[str, float], ...]
) -> float:
    for pattern, weight in patterns:
        if fnmatchcase(key, pattern):
            return _clamp01(weight)
    return 0.3


def _authority_mismatch(
    *,
    key: str,
    source_class: SourceClass,
    claim_type: str,
    claimed_subject: str,
) -> bool:
    if fnmatchcase(key, "tool_results.*") or fnmatchcase(key, "scratch.*"):
        return False
    if fnmatchcase(key, "preferences.*"):
        return source_class not in {SourceClass.USER_INPUT, SourceClass.SYSTEM}
    if fnmatchcase(key, "identity.*"):
        return source_class not in {SourceClass.USER_INPUT, SourceClass.SYSTEM}
    if fnmatchcase(key, "policies.*"):
        return source_class != SourceClass.SYSTEM
    if claimed_subject == "user" and source_class not in {
        SourceClass.USER_INPUT,
        SourceClass.SYSTEM,
    }:
        return claim_type in {"user_preference", "identity_claim", "unknown"}
    if claimed_subject == "system":
        return source_class != SourceClass.SYSTEM
    return False


def _severity_for(risk: float) -> Severity:
    if risk >= 0.9:
        return Severity.CRITICAL
    if risk >= 0.75:
        return Severity.HIGH
    return Severity.MEDIUM


def _clamp01(value: float) -> float:
    return min(1.0, max(0.0, value))


def _load_dotenv(path: str | None) -> None:
    if not path:
        return
    env_file = Path(path)
    if not env_file.is_absolute():
        env_file = Path.cwd() / env_file
    if not env_file.exists():
        return
    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        os.environ.setdefault(key, value)


def _resolve_api_key(provider: str) -> str | None:
    candidates = ["AMG_SOURCE_RISK_API_KEY"]
    if provider == "openrouter":
        candidates.extend(["OPENROUTER_API_KEY", "OPENAI_API_KEY"])
    else:
        candidates.extend(["OPENAI_API_KEY", "OPENROUTER_API_KEY"])
    for key in candidates:
        value = os.environ.get(key)
        if value:
            return value
    return None


def _resolve_model(provider: str) -> str | None:
    candidates = ["AMG_SOURCE_RISK_MODEL"]
    if provider == "openrouter":
        candidates.extend(["OPENROUTER_MODEL", "OPENAI_MODEL"])
    else:
        candidates.extend(["OPENAI_MODEL", "OPENROUTER_MODEL"])
    for key in candidates:
        value = os.environ.get(key)
        if value:
            return value
    return None


def _build_headers(
    *,
    api_key: str | None,
    provider: str,
    site_url: str | None,
    app_name: str | None,
) -> dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    if provider == "openrouter":
        if site_url:
            headers["HTTP-Referer"] = site_url
        if app_name:
            headers["X-Title"] = app_name
    return headers


__all__ = [
    "DEFAULT_SOURCE_WEIGHTS",
    "DEFAULT_TARGET_SENSITIVITY",
    "OpenAICompatibleEvaluator",
    "SourceRiskAssessment",
    "SourceRiskDetector",
    "SourceRiskEvaluator",
]
