from __future__ import annotations

from collections.abc import Iterable

from agent_memory_guard.detectors.anomaly import RapidChangeDetector, SizeAnomalyDetector
from agent_memory_guard.detectors.base import Detector
from agent_memory_guard.detectors.injection import PromptInjectionDetector
from agent_memory_guard.detectors.leakage import SensitiveDataDetector
from agent_memory_guard.detectors.self_reinforcement import SelfReinforcementDetector
from agent_memory_guard.detectors.source_risk import SourceRiskDetector, SourceRiskEvaluator
from agent_memory_guard.events import Action
from agent_memory_guard.guard import EventHandler, MemoryGuard
from agent_memory_guard.policies.policy import Policy, PolicyRule
from agent_memory_guard.storage.memory_store import MemoryStore
from agent_memory_guard.storage.snapshots import SnapshotStore


class SourceAwareMemoryGuard(MemoryGuard):
    """MemoryGuard variant that adds source-aware poisoning detection.

    This keeps the existing detector pipeline intact and appends a
    ``SourceRiskDetector`` that evaluates whether a given source is allowed to
    make the semantic claim being written to a particular memory namespace.
    """

    def __init__(
        self,
        store: MemoryStore | None = None,
        *,
        evaluator: SourceRiskEvaluator,
        policy: Policy | None = None,
        detectors: Iterable[Detector] | None = None,
        snapshots: SnapshotStore | None = None,
        event_handlers: Iterable[EventHandler] = (),
        snapshot_on_block: bool = True,
        promotion_rules=None,
        current_task: str | None = None,
        risk_threshold: float = 0.6,
        min_confidence: float = 0.0,
    ) -> None:
        effective_policy = _ensure_source_risk_policy(policy or Policy.strict())
        effective_detectors = list(detectors) if detectors is not None else _default_detectors()
        if not any(isinstance(d, SourceRiskDetector) for d in effective_detectors):
            effective_detectors.append(
                SourceRiskDetector(
                    evaluator,
                    risk_threshold=risk_threshold,
                    min_confidence=min_confidence,
                )
            )

        super().__init__(
            store,
            policy=effective_policy,
            detectors=effective_detectors,
            snapshots=snapshots,
            event_handlers=event_handlers,
            snapshot_on_block=snapshot_on_block,
            promotion_rules=promotion_rules,
            current_task=current_task,
        )


def _default_detectors() -> list[Detector]:
    return [
        PromptInjectionDetector(),
        SensitiveDataDetector(),
        SizeAnomalyDetector(),
        RapidChangeDetector(),
        SelfReinforcementDetector(),
    ]


def _ensure_source_risk_policy(policy: Policy) -> Policy:
    if any(rule.on == "source_risk" for rule in policy.rules):
        return policy
    rules = list(policy.rules)
    rules.append(PolicyRule("block_source_risk", "source_risk", Action.BLOCK))
    return Policy(
        default_action=policy.default_action,
        protected_keys=policy.protected_keys,
        immutable_keys=policy.immutable_keys,
        rules=rules,
        version=policy.version,
    )
