"""OWASP Agent Memory Guard — runtime defense against memory poisoning (ASI06)."""

from agent_memory_guard.guard import MemoryGuard
from agent_memory_guard.events import SecurityEvent, Severity, Action
from agent_memory_guard.exceptions import (
    MemoryGuardError,
    PolicyViolation,
    IntegrityError,
)
from agent_memory_guard.policies.policy import Policy

__version__ = "0.2.1"

__all__ = [
    "MemoryGuard",
    "Policy",
    "SecurityEvent",
    "Severity",
    "Action",
    "MemoryGuardError",
    "PolicyViolation",
    "IntegrityError",
    "__version__",
]
