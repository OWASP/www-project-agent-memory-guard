"""OWASP Agent Memory Guard — runtime defense against memory poisoning (ASI06)."""

from agent_memory_guard.events import Action, SecurityEvent, Severity, SourceType
from agent_memory_guard.exceptions import (
    IntegrityError,
    MemoryGuardError,
    PolicyViolation,
)
from agent_memory_guard.guard import MemoryGuard
from agent_memory_guard.policies.policy import Policy

__version__ = "0.2.2"

__all__ = [
    "Action",
    "IntegrityError",
    "MemoryGuard",
    "MemoryGuardError",
    "Policy",
    "PolicyViolation",
    "SecurityEvent",
    "Severity",
    "SourceType",
    "__version__",
]