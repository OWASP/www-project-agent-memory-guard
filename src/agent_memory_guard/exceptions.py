from __future__ import annotations

from typing import Any


def _rebuild(cls: type[BaseException], args: tuple[Any, ...]) -> BaseException:
    exc = cls.__new__(cls, *args)
    exc.args = args  # some bases, such as OSError, set args in __init__
    return exc


class MemoryGuardError(Exception):
    """Base exception for Agent Memory Guard."""

    def __reduce__(self) -> tuple[Any, ...]:
        # Rebuild without calling __init__, whose arguments differ from ``args``,
        # so these exceptions survive pickling (process pools) and copying.
        return (_rebuild, (type(self), self.args), self.__dict__)


class PolicyViolation(MemoryGuardError):
    """Raised when a memory operation violates an enforcement policy."""

    def __init__(self, message: str, rule: str | None = None, key: str | None = None):
        super().__init__(message)
        self.rule = rule
        self.key = key


class IntegrityError(MemoryGuardError):
    """Raised when a memory entry fails its integrity baseline check."""

    def __init__(self, message: str, key: str, expected: str, actual: str):
        super().__init__(message)
        self.key = key
        self.expected = expected
        self.actual = actual


class ClassificationError(MemoryGuardError):
    """Raised on illegal class transitions or cross-task contamination."""

    def __init__(
        self,
        message: str,
        *,
        key: str,
        source_class: str | None = None,
        target_class: str | None = None,
        origin_task: str | None = None,
        current_task: str | None = None,
    ) -> None:
        super().__init__(message)
        self.key = key
        self.source_class = source_class
        self.target_class = target_class
        self.origin_task = origin_task
        self.current_task = current_task


class AccessDenied(PolicyViolation):
    """Raised when an agent may not perform an operation on a key.

    It is a ``PolicyViolation`` (with ``rule="access_control"``), so code that
    already catches ``PolicyViolation`` handles it unchanged. ``decision`` is the
    :class:`~agent_memory_guard.policies.access.AccessDecision` that denied it.
    """

    def __init__(self, decision: Any) -> None:
        super().__init__(
            f"{decision.operation} of {decision.key!r} denied: {decision.reason}",
            rule="access_control",
            key=decision.key,
        )
        self.decision = decision
        self.principal: str | None = decision.principal


class UnknownPrincipal(LookupError):
    """Raised by ``guard.as_agent(id)`` when the policy's registry does not declare ``id``."""


class PolicyWarning(UserWarning):
    """A policy loaded, but part of it may not do what its author expects."""
