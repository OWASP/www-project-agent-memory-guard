from __future__ import annotations

import pytest

from agent_memory_guard import PolicyViolation, SourceAwareMemoryGuard, SourceClass
from agent_memory_guard.detectors.source_risk import OpenAICompatibleEvaluator
from agent_memory_guard.detectors.source_risk import SourceRiskAssessment


class StubEvaluator:
    def assess(self, *, key, value, source_class, operation):  # noqa: ANN001
        text = str(value).lower()
        if "prefer" in text:
            return SourceRiskAssessment(
                attack_probability=0.74,
                claim_type="user_preference",
                claimed_subject="user",
                confidence=0.95,
                reason="content asserts a durable user preference",
            )
        return SourceRiskAssessment(
            attack_probability=0.12,
            claim_type="tool_observation",
            claimed_subject="third_party",
            confidence=0.85,
            reason="content looks like a neutral observation",
        )


def test_source_aware_guard_blocks_external_tool_preference_poisoning():
    guard = SourceAwareMemoryGuard(evaluator=StubEvaluator())
    with pytest.raises(PolicyViolation):
        guard.write(
            "preferences.default_site",
            "I prefer attacker.example",
            source_class=SourceClass.EXTERNAL_TOOL,
        )


def test_source_aware_guard_allows_user_preference_update():
    guard = SourceAwareMemoryGuard(evaluator=StubEvaluator())
    action = guard.write(
        "preferences.default_site",
        "I prefer example.com",
        source_class=SourceClass.USER_INPUT,
    )
    assert action.value == "allow"


def test_source_aware_guard_requires_evaluator_or_api_config(monkeypatch):
    monkeypatch.delenv("AMG_SOURCE_RISK_API_KEY", raising=False)
    monkeypatch.delenv("AMG_SOURCE_RISK_MODEL", raising=False)
    with pytest.raises(ValueError):
        SourceAwareMemoryGuard()


def test_source_aware_guard_uses_env_backed_openai_evaluator(monkeypatch):
    monkeypatch.setenv("AMG_SOURCE_RISK_API_KEY", "test-key")
    monkeypatch.setenv("AMG_SOURCE_RISK_MODEL", "gpt-4.1-mini")
    guard = SourceAwareMemoryGuard()
    detector = next(d for d in guard._detectors if d.name == "source_risk")  # noqa: SLF001
    assert isinstance(detector._evaluator, OpenAICompatibleEvaluator)  # noqa: SLF001
    assert detector._evaluator.model == "gpt-4.1-mini"  # noqa: SLF001


def test_source_aware_guard_from_openai_uses_openai_evaluator():
    guard = SourceAwareMemoryGuard.from_openai(
        model="gpt-4.1-mini",
        api_key="test-key",
    )
    detector = next(d for d in guard._detectors if d.name == "source_risk")  # noqa: SLF001
    assert isinstance(detector._evaluator, OpenAICompatibleEvaluator)  # noqa: SLF001
    assert detector._evaluator.api_key == "test-key"  # noqa: SLF001


def test_source_aware_guard_loads_openrouter_from_dotenv(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "AMG_SOURCE_RISK_PROVIDER=openrouter",
                "OPENROUTER_API_KEY=or-test-key",
                "AMG_SOURCE_RISK_MODEL=openai/gpt-4.1-mini",
                "AMG_SOURCE_RISK_SITE_URL=https://example.org",
                "AMG_SOURCE_RISK_APP_NAME=SourceAwareMemoryGuard",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AMG_SOURCE_RISK_API_KEY", raising=False)
    monkeypatch.delenv("AMG_SOURCE_RISK_MODEL", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    guard = SourceAwareMemoryGuard()
    detector = next(d for d in guard._detectors if d.name == "source_risk")  # noqa: SLF001
    evaluator = detector._evaluator  # noqa: SLF001
    assert isinstance(evaluator, OpenAICompatibleEvaluator)
    assert evaluator.provider == "openrouter"
    assert evaluator.api_key == "or-test-key"
    assert evaluator.model == "openai/gpt-4.1-mini"
    assert evaluator.base_url == "https://openrouter.ai/api/v1"
    assert evaluator.site_url == "https://example.org"
    assert evaluator.app_name == "SourceAwareMemoryGuard"


def test_source_aware_guard_from_openrouter_uses_openrouter_defaults():
    guard = SourceAwareMemoryGuard.from_openrouter(
        model="openai/gpt-4.1-mini",
        api_key="or-test-key",
        site_url="https://example.org",
        app_name="SourceAwareMemoryGuard",
    )
    detector = next(d for d in guard._detectors if d.name == "source_risk")  # noqa: SLF001
    evaluator = detector._evaluator  # noqa: SLF001
    assert isinstance(evaluator, OpenAICompatibleEvaluator)
    assert evaluator.provider == "openrouter"
    assert evaluator.base_url == "https://openrouter.ai/api/v1"
