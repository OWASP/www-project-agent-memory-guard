from __future__ import annotations


class MemoryGuardError(Exception):
    """Base exception for Agent Memory Guard."""


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
