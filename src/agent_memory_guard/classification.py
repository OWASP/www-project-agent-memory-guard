"""Provenance-based memory classification and promotion rules.

Implements the ASI06 mitigation pattern proposed by armorer-labs on
microsoft/autogen#7673: every memory entry carries an explicit class label
indicating where it came from and how much it is trusted. Promotions
between classes are gated by a transition matrix, so untrusted sources
(retrieved text, tool output) cannot silently become trusted policy or
verified preferences without explicit verification.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class MemoryClass(str, Enum):
    """Provenance label attached to every guarded memory entry."""

    EPHEMERAL = "ephemeral"
    USER_PREFERENCE_CANDIDATE = "user_preference_candidate"
    VERIFIED_PREFERENCE = "verified_preference"
    RETRIEVED_FACT = "retrieved_fact"
    TOOL_OBSERVATION = "tool_observation"
    POLICY = "policy"


UNTRUSTED_CLASSES: frozenset[MemoryClass] = frozenset(
    {MemoryClass.RETRIEVED_FACT, MemoryClass.TOOL_OBSERVATION}
)

DURABLE_CLASSES: frozenset[MemoryClass] = frozenset(
    {
        MemoryClass.VERIFIED_PREFERENCE,
        MemoryClass.POLICY,
        MemoryClass.RETRIEVED_FACT,
        MemoryClass.TOOL_OBSERVATION,
    }
)

EPHEMERAL_CLASSES: frozenset[MemoryClass] = frozenset(
    {MemoryClass.EPHEMERAL, MemoryClass.USER_PREFERENCE_CANDIDATE}
)


@dataclass(frozen=True)
class PromotionEdge:
    """Allowed transition from one class to another and what it requires."""

    source: MemoryClass
    target: MemoryClass
    requires_verification: bool = False


# Default promotion graph. Anything not in this set is rejected outright.
# - ephemeral -> user_preference_candidate: assistant noticed a repeated request
# - user_preference_candidate -> verified_preference: requires explicit user opt-in
# - retrieved_fact -> tool_observation: cite a retrieval inside an observation
# - retrieved_fact / tool_observation NEVER promote to policy or verified_preference;
#   policy changes must originate from POLICY writes by a trusted principal.
DEFAULT_PROMOTION_GRAPH: tuple[PromotionEdge, ...] = (
    PromotionEdge(MemoryClass.EPHEMERAL, MemoryClass.USER_PREFERENCE_CANDIDATE),
    PromotionEdge(
        MemoryClass.USER_PREFERENCE_CANDIDATE,
        MemoryClass.VERIFIED_PREFERENCE,
        requires_verification=True,
    ),
    PromotionEdge(MemoryClass.RETRIEVED_FACT, MemoryClass.TOOL_OBSERVATION),
)


class PromotionRules:
    """Lookup helper around a promotion graph."""

    def __init__(self, edges: tuple[PromotionEdge, ...] = DEFAULT_PROMOTION_GRAPH) -> None:
        self._edges: dict[tuple[MemoryClass, MemoryClass], PromotionEdge] = {
            (e.source, e.target): e for e in edges
        }

    def edge(self, source: MemoryClass, target: MemoryClass) -> PromotionEdge | None:
        return self._edges.get((source, target))

    def is_allowed(self, source: MemoryClass, target: MemoryClass) -> bool:
        return (source, target) in self._edges

    def requires_verification(self, source: MemoryClass, target: MemoryClass) -> bool:
        edge = self._edges.get((source, target))
        return bool(edge and edge.requires_verification)


class ClassificationRegistry:
    """Tracks the class and originating task of every guarded key."""

    def __init__(self) -> None:
        self._classes: dict[str, MemoryClass] = {}
        self._origin_task: dict[str, str | None] = {}

    def set(self, key: str, mclass: MemoryClass, *, task_id: str | None = None) -> None:
        self._classes[key] = mclass
        self._origin_task[key] = task_id

    def get(self, key: str) -> MemoryClass | None:
        return self._classes.get(key)

    def task_of(self, key: str) -> str | None:
        return self._origin_task.get(key)

    def clear(self, key: str | None = None) -> None:
        if key is None:
            self._classes.clear()
            self._origin_task.clear()
        else:
            self._classes.pop(key, None)
            self._origin_task.pop(key, None)

    def keys_with_class(self, mclass: MemoryClass) -> list[str]:
        return [k for k, c in self._classes.items() if c == mclass]


__all__ = [
    "MemoryClass",
    "PromotionEdge",
    "PromotionRules",
    "ClassificationRegistry",
    "UNTRUSTED_CLASSES",
    "DURABLE_CLASSES",
    "EPHEMERAL_CLASSES",
    "DEFAULT_PROMOTION_GRAPH",
]
