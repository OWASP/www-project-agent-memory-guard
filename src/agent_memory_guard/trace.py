"""Decision traces: the steps a guard took to allow or stop one operation.

With ``MemoryGuard(trace=True)`` every operation records a list of
:class:`TraceStep` objects: who was acting, which access rule matched, which
detectors ran and what they found, which policy rule decided, and what was
finally stored. ``guard.last_trace()`` returns the steps of the last operation,
each event carries them in ``metadata["trace"]``, and :func:`format_trace`
renders them as text.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class TraceStep:
    """One step of a decision.

    Attributes:
        stage: What the guard was doing, e.g. ``identity``, ``rule``, ``detector``,
            ``policy``, ``snapshot``, ``commit`` or ``result``.
        detail: What it looked at, e.g. a rule name or a detector name.
        outcome: What it concluded, e.g. ``match``, ``high`` or ``block``.
    """

    stage: str
    detail: str
    outcome: str = ""

    def as_dict(self) -> dict[str, str]:
        return {"stage": self.stage, "detail": self.detail, "outcome": self.outcome}

    def __str__(self) -> str:
        return f"{self.stage:<10} {self.detail}" + (f" -> {self.outcome}" if self.outcome else "")


def format_trace(steps: Iterable[TraceStep] | None) -> str:
    """Render trace steps as numbered lines, one step per line."""
    if not steps:
        return ""
    return "\n".join(f"{i:>2}. {step}" for i, step in enumerate(steps, 1))


__all__ = ["TraceStep", "format_trace"]
