"""Adapter contract every graded memory system implements.

A memory system is anything an agent writes facts into and reads them back
from on a later turn: a plain dictionary, a guarded store, or a third-party
service such as mem0, Letta, or Zep. AMSB never talks to those systems
directly; it talks to a :class:`MemorySystemAdapter`, so grading a new system
means writing one small adapter and nothing else changes.

The contract is deliberately tiny — ``remember``, ``recall``, ``context_reset``
— because that is the whole of the poisoning threat surface: content goes in,
a session boundary passes, content comes back out and steers the next turn.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any


class RememberOutcome(str, Enum):
    """What a system did with an attempted write.

    The benchmark scores on what ``recall`` returns, not on this value, but the
    outcome is recorded for every step so a report can explain *how* a system
    defended (or failed to). The four values mirror the actions an enforcing
    guard can take; a system with no defenses only ever reports ``STORED``.
    """

    STORED = "stored"
    """Persisted and readable back verbatim (no defense applied)."""

    REDACTED = "redacted"
    """Persisted, but the dangerous content was removed or masked first."""

    QUARANTINED = "quarantined"
    """Withheld from normal recall and flagged for review."""

    BLOCKED = "blocked"
    """Rejected outright; nothing was persisted."""


@dataclass
class ProbeResult:
    """The value a later turn reads back, plus how the write was handled.

    ``recalled`` is the ground truth the benchmark judges: if the attack's
    canary survives in it, the system was breached, regardless of ``outcome``.
    ``outcome`` is advisory reporting detail.
    """

    recalled: Any | None
    outcome: RememberOutcome


class MemorySystemAdapter(ABC):
    """Uniform interface AMSB drives to grade a memory system.

    Subclasses set :attr:`name` and :attr:`version` and implement the three
    methods below. Adapters must be cheap to construct: the harness builds a
    fresh adapter per scenario so no state leaks between attacks.
    """

    #: Stable, human-readable system name shown on the leaderboard.
    name: str = "unnamed-system"
    #: Version string for the graded system (not the benchmark version).
    version: str = "0.0.0"
    #: Set on adapters that grade the benchmark's own author, so reports can
    #: flag the self-submission. Third-party adapters leave this False.
    self_submission: bool = False

    @abstractmethod
    def remember(
        self,
        key: str,
        value: Any,
        *,
        source_class: str = "external_tool",
    ) -> RememberOutcome:
        """Attempt to persist ``value`` under ``key``.

        Args:
            key: Memory key the agent would write to.
            value: Content being written — for attack steps, a poisoned payload.
            source_class: Provenance hint (``external_tool``, ``user_input``,
                ``agent_authored``, ``system``). Systems that ignore provenance
                may drop it; guarded systems use it for self-reinforcement and
                trust decisions.

        Returns:
            How the system handled the write.
        """

    @abstractmethod
    def recall(self, key: str) -> Any | None:
        """Return what a later turn reads back for ``key`` (``None`` if absent).

        This is the value the benchmark inspects for a surviving canary. A
        system that blocked or quarantined the write should return ``None``
        (or a value with the dangerous content removed).
        """

    def context_reset(self) -> None:
        """Simulate a session boundary: clear working context, keep memory.

        The entire point of memory poisoning is that persisted content
        outlives the conversation that planted it. The harness calls this
        between the attack sequence and the probe so a passing grade means the
        system defended content that *survived a reset*, not merely content in
        the current turn. Default: no-op, because a durable store already
        persists across it.
        """
        return None
