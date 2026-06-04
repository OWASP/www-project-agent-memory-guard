from __future__ import annotations

import pytest

from agent_memory_guard import MemoryGuard, Policy, PolicyViolation, SourceClass
from agent_memory_guard.detectors.source_risk import (
    SourceRiskAssessment,
    SourceRiskDetector,
)
from agent_memory_guard.events import Action, Severity
from agent_memory_guard.policies.policy import load_policy


class StubEvaluator:
    def assess(self, *, key, value, source_class, operation):  # noqa: ANN001
        text = str(value).lower()
        if "prefer" in text:
            return SourceRiskAssessment(
                attack_probability=0.72,
                claim_type="user_preference",
                claimed_subject="user",
                confidence=0.92,
                reason="content asserts a durable user preference",
            )
        return SourceRiskAssessment(
            attack_probability=0.12,
            claim_type="tool_observation",
            claimed_subject="third_party",
            confidence=0.85,
            reason="content looks like a neutral observation",
        )


def _policy() -> Policy:
    return load_policy(
        {
            "default_action": "allow",
            "rules": [
                {"name": "block_source_risk", "on": "source_risk", "action": "block"}
            ],
        }
    )


def test_detector_flags_external_tool_preference_write():
    detector = SourceRiskDetector(StubEvaluator())
    detector._pending_source_class = SourceClass.EXTERNAL_TOOL
    try:
        result = detector.inspect(
            "preferences.default_site",
            "I prefer attacker.example",
            operation="write",
        )
    finally:
        detector._pending_source_class = SourceClass.UNKNOWN
    assert result.matched
    assert result.severity in (Severity.HIGH, Severity.CRITICAL)
    assert result.metadata["authority_mismatch"] is True
    assert result.metadata["final_risk"] >= 0.6


def test_detector_allows_user_preference_write_below_threshold():
    detector = SourceRiskDetector(StubEvaluator())
    detector._pending_source_class = SourceClass.USER_INPUT
    try:
        result = detector.inspect(
            "preferences.default_site",
            "I prefer example.com",
            operation="write",
        )
    finally:
        detector._pending_source_class = SourceClass.UNKNOWN
    assert not result.matched


def test_detector_does_not_penalize_tool_results_namespace():
    detector = SourceRiskDetector(StubEvaluator())
    detector._pending_source_class = SourceClass.EXTERNAL_TOOL
    try:
        result = detector.inspect(
            "tool_results.search.42",
            "I prefer attacker.example",
            operation="write",
        )
    finally:
        detector._pending_source_class = SourceClass.UNKNOWN
    assert not result.matched


def test_guard_blocks_external_tool_preference_poisoning():
    guard = MemoryGuard(
        policy=_policy(),
        detectors=[SourceRiskDetector(StubEvaluator())],
    )
    with pytest.raises(PolicyViolation):
        guard.write(
            "preferences.default_site",
            "I prefer attacker.example",
            source_class=SourceClass.EXTERNAL_TOOL,
        )
    assert any(e.detector == "source_risk" for e in guard.events)


def test_guard_allows_user_to_update_own_preference():
    guard = MemoryGuard(
        policy=_policy(),
        detectors=[SourceRiskDetector(StubEvaluator())],
    )
    decision = guard.write(
        "preferences.default_site",
        "I prefer example.com",
        source_class=SourceClass.USER_INPUT,
    )
    assert decision == Action.ALLOW
    assert guard.read("preferences.default_site") == "I prefer example.com"
