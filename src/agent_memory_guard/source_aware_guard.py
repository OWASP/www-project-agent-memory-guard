from __future__ import annotations

from collections.abc import Iterable

from agent_memory_guard.detectors.anomaly import RapidChangeDetector, SizeAnomalyDetector
from agent_memory_guard.detectors.base import Detector
from agent_memory_guard.detectors.injection import PromptInjectionDetector
from agent_memory_guard.detectors.leakage import SensitiveDataDetector
from agent_memory_guard.detectors.self_reinforcement import SelfReinforcementDetector
from agent_memory_guard.detectors.source_risk import (
    OpenAICompatibleEvaluator,
    SourceRiskDetector,
    SourceRiskEvaluator,
)
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
        evaluator: SourceRiskEvaluator | None = None,
        policy: Policy | None = None,
        detectors: Iterable[Detector] | None = None,
        snapshots: SnapshotStore | None = None,
        event_handlers: Iterable[EventHandler] = (),
        snapshot_on_block: bool = True,
        promotion_rules=None,
        current_task: str | None = None,
        risk_threshold: float = 0.6,
        min_confidence: float = 0.0,
        api_key: str | None = None,
        model: str | None = None,
        provider: str | None = None,
        base_url: str = "https://api.openai.com/v1",
        site_url: str | None = None,
        app_name: str | None = None,
        dotenv_path: str | None = ".env",
        timeout_seconds: float = 15.0,
    ) -> None:
        resolved_evaluator = _resolve_evaluator(
            evaluator=evaluator,
            api_key=api_key,
            model=model,
            provider=provider,
            base_url=base_url,
            site_url=site_url,
            app_name=app_name,
            dotenv_path=dotenv_path,
            timeout_seconds=timeout_seconds,
        )
        effective_policy = _ensure_source_risk_policy(policy or Policy.strict())
        effective_detectors = list(detectors) if detectors is not None else _default_detectors()
        if not any(isinstance(d, SourceRiskDetector) for d in effective_detectors):
            effective_detectors.append(
                SourceRiskDetector(
                    resolved_evaluator,
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

    @classmethod
    def from_openai(
        cls,
        store: MemoryStore | None = None,
        *,
        model: str,
        api_key: str | None = None,
        base_url: str = "https://api.openai.com/v1",
        timeout_seconds: float = 15.0,
        **kwargs,
    ) -> "SourceAwareMemoryGuard":
        """Construct a source-aware guard backed by an OpenAI-compatible API."""
        return cls(
            store,
            api_key=api_key,
            model=model,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
            **kwargs,
        )

    @classmethod
    def from_openrouter(
        cls,
        store: MemoryStore | None = None,
        *,
        model: str,
        api_key: str | None = None,
        site_url: str | None = None,
        app_name: str | None = None,
        base_url: str = "https://openrouter.ai/api/v1",
        timeout_seconds: float = 15.0,
        **kwargs,
    ) -> "SourceAwareMemoryGuard":
        """Construct a source-aware guard backed by OpenRouter."""
        return cls(
            store,
            api_key=api_key,
            model=model,
            provider="openrouter",
            base_url=base_url,
            site_url=site_url,
            app_name=app_name,
            timeout_seconds=timeout_seconds,
            **kwargs,
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


def _resolve_evaluator(
    *,
    evaluator: SourceRiskEvaluator | None,
    api_key: str | None,
    model: str | None,
    provider: str | None,
    base_url: str,
    site_url: str | None,
    app_name: str | None,
    dotenv_path: str | None,
    timeout_seconds: float,
) -> SourceRiskEvaluator:
    if evaluator is not None:
        return evaluator
    resolved = OpenAICompatibleEvaluator(
        api_key=api_key,
        model=model,
        provider=provider,
        base_url=base_url,
        site_url=site_url,
        app_name=app_name,
        dotenv_path=dotenv_path,
        timeout_seconds=timeout_seconds,
    )
    if not resolved.api_key or not resolved.model:
        raise ValueError(
            "SourceAwareMemoryGuard requires either an explicit evaluator or "
            "OpenAI-compatible API configuration (model/api_key or "
            "AMG_SOURCE_RISK_MODEL / AMG_SOURCE_RISK_API_KEY)."
        )
    return resolved
