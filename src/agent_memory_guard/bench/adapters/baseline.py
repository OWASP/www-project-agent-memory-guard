"""Baseline adapters: the unguarded floor and two Agent Memory Guard configs.

These three are what the committed AMSB leaderboard is generated from. They
exist for two reasons: to prove the benchmark discriminates (an undefended
store must score at the floor, a hardened guard near the top), and to let AMG
grade itself honestly through the exact same contract every third-party system
uses.

The two AMG adapters are the configurations the project actually documents:

* ``AMGStrictAdapter`` — ``MemoryGuard(policy=Policy.strict())`` with the
  default detector suite. This is the recommended out-of-the-box enforcing
  setup from the README. It deliberately does **not** load the opt-in
  persistence detector, so its result shows what a standard install stops.
* ``AMGHardenedAdapter`` — the strict configuration plus the opt-in
  ``MemoryPersistenceInjectionDetector`` and protected/immutable identity
  keys. This is the configuration for deployments that care about
  delayed-activation attacks.

Reporting both, side by side, is the honest version of "how good is AMG": the
gap between them is real and is the reason the persistence detector exists.
"""
from __future__ import annotations

from typing import Any

from agent_memory_guard.bench.adapter import MemorySystemAdapter, RememberOutcome
from agent_memory_guard.events import Action, SourceClass
from agent_memory_guard.exceptions import PolicyViolation

_ACTION_TO_OUTCOME = {
    Action.ALLOW: RememberOutcome.STORED,
    Action.REDACT: RememberOutcome.REDACTED,
    Action.QUARANTINE: RememberOutcome.QUARANTINED,
    Action.BLOCK: RememberOutcome.BLOCKED,
}


def _coerce_source_class(value: str) -> SourceClass:
    try:
        return SourceClass(value)
    except ValueError:
        return SourceClass.UNKNOWN


class UnguardedDictAdapter(MemorySystemAdapter):
    """A plain dictionary with no defenses — the resilience floor.

    Every write is stored verbatim and read back intact, so every attack's
    canary survives. This is the control that shows an unprotected agent memory
    is graded F, and the value a real system must beat.
    """

    name = "unguarded-dict"
    version = "n/a"
    self_submission = False

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}

    def remember(
        self, key: str, value: Any, *, source_class: str = "external_tool"
    ) -> RememberOutcome:
        self._data[key] = value
        return RememberOutcome.STORED

    def recall(self, key: str) -> Any | None:
        return self._data.get(key)


class _AMGAdapter(MemorySystemAdapter):
    """Shared plumbing for grading a :class:`MemoryGuard` configuration."""

    self_submission = True

    def __init__(self, guard: Any) -> None:
        self._guard = guard

    def remember(
        self, key: str, value: Any, *, source_class: str = "external_tool"
    ) -> RememberOutcome:
        try:
            action = self._guard.write(
                key, value, source_class=_coerce_source_class(source_class)
            )
        except PolicyViolation:
            return RememberOutcome.BLOCKED
        return _ACTION_TO_OUTCOME.get(action, RememberOutcome.STORED)

    def recall(self, key: str) -> Any | None:
        # Quarantined and blocked writes never reach the backing store, so a
        # later read returns None; redacted writes return the masked value.
        return self._guard.read(key)


class AMGStrictAdapter(_AMGAdapter):
    """Agent Memory Guard with ``Policy.strict()`` and the default suite."""

    name = "agent-memory-guard (strict)"

    def __init__(self) -> None:
        from agent_memory_guard import MemoryGuard, Policy, __version__

        super().__init__(MemoryGuard(policy=Policy.strict()))
        self.version = __version__


class AMGHardenedAdapter(_AMGAdapter):
    """Strict guard plus the opt-in persistence detector and protected keys."""

    name = "agent-memory-guard (hardened)"

    def __init__(self) -> None:
        from agent_memory_guard import MemoryGuard, __version__
        from agent_memory_guard.detectors import (
            Detector,
            MemoryPersistenceInjectionDetector,
            PromptInjectionDetector,
            RapidChangeDetector,
            SensitiveDataDetector,
            SizeAnomalyDetector,
        )
        from agent_memory_guard.events import Action
        from agent_memory_guard.policies.policy import Policy, PolicyRule

        policy = Policy(
            default_action=Action.ALLOW,
            protected_keys=("identity.*", "system.*", "agent.goal", "security.*"),
            immutable_keys=("identity.user_id",),
            rules=[
                PolicyRule("block_injection", "prompt_injection", Action.BLOCK),
                PolicyRule("redact_secrets", "sensitive_data", Action.REDACT),
                PolicyRule("block_protected_key", "protected_key", Action.BLOCK),
                PolicyRule("quarantine_size", "size_anomaly", Action.QUARANTINE),
                PolicyRule("quarantine_rapid", "rapid_change", Action.QUARANTINE),
                PolicyRule(
                    "block_persistence",
                    "memory_persistence_injection",
                    Action.BLOCK,
                ),
            ],
        )
        detectors: list[Detector] = [
            PromptInjectionDetector(),
            SensitiveDataDetector(),
            SizeAnomalyDetector(),
            RapidChangeDetector(),
            MemoryPersistenceInjectionDetector(),
        ]
        super().__init__(MemoryGuard(policy=policy, detectors=detectors))
        self.version = __version__


def baseline_adapters() -> list[type[MemorySystemAdapter]]:
    """The adapter classes the committed leaderboard is generated from."""
    return [UnguardedDictAdapter, AMGStrictAdapter, AMGHardenedAdapter]


__all__ = [
    "UnguardedDictAdapter",
    "AMGStrictAdapter",
    "AMGHardenedAdapter",
    "baseline_adapters",
]
