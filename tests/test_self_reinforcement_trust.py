"""Regression tests for trust-aware self-reinforcement decay."""
from __future__ import annotations

from collections.abc import Collection
from typing import Any, cast

import pytest

from agent_memory_guard import MemoryGuard, SourceClass
from agent_memory_guard.detectors.base import DetectionResult
from agent_memory_guard.detectors.self_reinforcement import SelfReinforcementDetector


def _drive(
    detector: SelfReinforcementDetector,
    key: str,
    value: str,
    source_class: SourceClass = SourceClass.AGENT_AUTHORED,
) -> DetectionResult:
    detector._pending_source_class = source_class
    try:
        return detector.inspect(key, value, operation="write")
    finally:
        detector._pending_source_class = SourceClass.UNKNOWN


def test_untrusted_source_does_not_decay_counter():
    detector = SelfReinforcementDetector(
        max_self_writes=2,
        similarity_threshold=0.5,
        trusted_source_classes={SourceClass.SYSTEM},
    )
    _drive(detector, "k", "stable fact")
    _drive(detector, "k", "stable fact")
    detector.note_independent_write("k", SourceClass.USER_INPUT)
    assert _drive(detector, "k", "stable fact").matched


def test_explicitly_trusted_source_decays_counter():
    detector = SelfReinforcementDetector(
        max_self_writes=2,
        similarity_threshold=0.5,
        trusted_source_classes={SourceClass.SYSTEM},
    )
    _drive(detector, "k", "stable fact")
    _drive(detector, "k", "stable fact")
    detector.note_independent_write("k", SourceClass.SYSTEM)
    assert not _drive(detector, "k", "stable fact").matched


def test_default_sources_preserve_legacy_decay():
    detector = SelfReinforcementDetector(
        max_self_writes=2,
        similarity_threshold=0.5,
    )
    _drive(detector, "k", "stable fact")
    _drive(detector, "k", "stable fact")
    detector.note_independent_write("k", SourceClass.USER_INPUT)
    assert not _drive(detector, "k", "stable fact").matched


def test_empty_trusted_sources_disable_decay():
    detector = SelfReinforcementDetector(
        max_self_writes=2,
        similarity_threshold=0.5,
        trusted_source_classes=set(),
    )
    _drive(detector, "k", "stable fact")
    _drive(detector, "k", "stable fact")
    detector.note_independent_write("k", SourceClass.SYSTEM)
    assert _drive(detector, "k", "stable fact").matched


def test_rejects_agent_authored_as_trusted_corroboration():
    with pytest.raises(ValueError):
        SelfReinforcementDetector(
            trusted_source_classes={SourceClass.AGENT_AUTHORED}
        )


def test_rejects_non_source_class_trusted_values():
    with pytest.raises(TypeError):
        SelfReinforcementDetector(
            trusted_source_classes={"system"}  # type: ignore[arg-type]
        )


def test_rejects_unhashable_non_source_class_trusted_values():
    invalid = cast(Collection[SourceClass], cast(Any, [["system"]]))
    with pytest.raises(TypeError, match="SourceClass values"):
        SelfReinforcementDetector(trusted_source_classes=invalid)


def test_guard_untrusted_user_input_does_not_decay_self_loop():
    detector = SelfReinforcementDetector(
        max_self_writes=2,
        similarity_threshold=0.5,
        trusted_source_classes={SourceClass.SYSTEM},
    )
    guard = MemoryGuard(detectors=[detector])
    for _ in range(2):
        guard.write(
            "fact.x",
            "Atlantis is in the Atlantic",
            source_class=SourceClass.AGENT_AUTHORED,
        )
    guard.write(
        "fact.x",
        "Atlantis is in the Atlantic",
        source_class=SourceClass.USER_INPUT,
    )
    before = len(guard.events)
    guard.write(
        "fact.x",
        "Atlantis is in the Atlantic",
        source_class=SourceClass.AGENT_AUTHORED,
    )
    assert any(
        event.detector == "self_reinforcement" for event in guard.events[before:]
    )


def test_guard_trusted_system_write_decays_self_loop():
    detector = SelfReinforcementDetector(
        max_self_writes=2,
        similarity_threshold=0.5,
        trusted_source_classes={SourceClass.SYSTEM},
    )
    guard = MemoryGuard(detectors=[detector])
    for _ in range(2):
        guard.write(
            "fact.x",
            "Atlantis is in the Atlantic",
            source_class=SourceClass.AGENT_AUTHORED,
        )
    guard.write(
        "fact.x",
        "Atlantis is in the Atlantic",
        source_class=SourceClass.SYSTEM,
    )
    before = len(guard.events)
    guard.write(
        "fact.x",
        "Atlantis is in the Atlantic",
        source_class=SourceClass.AGENT_AUTHORED,
    )
    assert not any(
        event.detector == "self_reinforcement" for event in guard.events[before:]
    )
