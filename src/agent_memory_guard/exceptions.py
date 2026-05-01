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
