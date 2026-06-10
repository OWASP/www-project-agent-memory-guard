"""OWASP Agent Memory Guard — runtime defense against memory poisoning (ASI06)."""

from agent_memory_guard.classification import (
    DEFAULT_PROMOTION_GRAPH,
    MemoryClass,
    PromotionEdge,
    PromotionRules,
)
from agent_memory_guard.events import Action, SecurityEvent, Severity, SourceClass, SourceType
from agent_memory_guard.exceptions import (
    ClassificationError,
    IntegrityError,
    MemoryGuardError,
    PolicyViolation,
)
from agent_memory_guard.guard import MemoryGuard
from agent_memory_guard.policies.policy import Policy

__version__ = "0.3.0-dev"

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
    "MemoryClass",
    "PromotionEdge",
    "PromotionRules",
    "DEFAULT_PROMOTION_GRAPH",
    "SecurityEvent",
    "Severity",
    "Action",
    "SourceClass",
    "MemoryGuardError",
    "PolicyViolation",
    "IntegrityError",
    "ClassificationError",
    "__version__",
]
