"""OWASP Agent Memory Guard — runtime defense against memory poisoning (ASI06)."""

from agent_memory_guard.classification import (
    DEFAULT_PROMOTION_GRAPH,
    MemoryClass,
    PromotionEdge,
    PromotionRules,
)
from agent_memory_guard.events import Action, SecurityEvent, Severity, SourceClass, SourceType
from agent_memory_guard.exceptions import (
    AccessDenied,
    ClassificationError,
    IntegrityError,
    MemoryGuardError,
    PolicyViolation,
    PolicyWarning,
    UnknownPrincipal,
)
from agent_memory_guard.guard import MemoryGuard
from agent_memory_guard.identity import AgentHandle
from agent_memory_guard.policies.access import AccessDecision, AccessPolicy, AccessRule
from agent_memory_guard.policies.policy import Policy
from agent_memory_guard.trace import TraceStep, format_trace

__version__ = "0.4.0"

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
    "AccessDenied",
    "AccessDecision",
    "AccessPolicy",
    "AccessRule",
    "AgentHandle",
    "PolicyWarning",
    "TraceStep",
    "UnknownPrincipal",
    "format_trace",
    "__version__",
]
