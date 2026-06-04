from __future__ import annotations

import pytest

from agent_memory_guard import PolicyViolation, SourceAwareMemoryGuard, SourceClass
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
