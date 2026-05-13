"""MemoryGuard — runtime checkpoint between an agent and its memory store."""
from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any, Callable

from agent_memory_guard.classification import (
    ClassificationRegistry,
    MemoryClass,
    PromotionRules,
)
from agent_memory_guard.detectors.anomaly import (
    RapidChangeDetector,
    SizeAnomalyDetector,
)
from agent_memory_guard.detectors.base import DetectionResult, Detector
from agent_memory_guard.detectors.cross_task import CrossTaskContaminationDetector
from agent_memory_guard.detectors.injection import PromptInjectionDetector
from agent_memory_guard.detectors.leakage import SensitiveDataDetector
from agent_memory_guard.detectors.protected_keys import ProtectedKeyDetector
from agent_memory_guard.events import Action, SecurityEvent, Severity
from agent_memory_guard.exceptions import (
    ClassificationError,
    IntegrityError,
    PolicyViolation,
)
from agent_memory_guard.integrity import IntegrityRegistry, hash_value
from agent_memory_guard.policies.policy import Policy, merge_protected_keys
from agent_memory_guard.storage.memory_store import InMemoryStore, MemoryStore
from agent_memory_guard.storage.snapshots import Snapshot, SnapshotStore

log = logging.getLogger("agent_memory_guard")

EventHandler = Callable[[SecurityEvent], None]


class MemoryGuard:
    """Wraps a memory store and screens every read/write through detectors+policy.

    The guard is intentionally permissive by default: instantiating with no
    arguments yields a working `MemoryGuard()` that detects threats and emits
    events but does not block writes. Pass `policy=Policy.strict()` (or load
    from YAML) to enable enforcement actions.
    """

    def __init__(
        self,
        store: MemoryStore | None = None,
        *,
        policy: Policy | None = None,
        detectors: Iterable[Detector] | None = None,
        snapshots: SnapshotStore | None = None,
        event_handlers: Iterable[EventHandler] = (),
        snapshot_on_block: bool = True,
        promotion_rules: PromotionRules | None = None,
        current_task: str | None = None,
    ) -> None:
        self._store: MemoryStore = store if store is not None else InMemoryStore()
        self._policy = policy or Policy.permissive()
        self._integrity = IntegrityRegistry()
        self._snapshots = snapshots if snapshots is not None else SnapshotStore()
        self._handlers: list[EventHandler] = list(event_handlers)
        self._events: list[SecurityEvent] = []
        self._snapshot_on_block = snapshot_on_block
        self._quarantine: dict[str, Any] = {}
        self._classification = ClassificationRegistry()
        self._promotion_rules = promotion_rules or PromotionRules()
        self._current_task = current_task

        protected = merge_protected_keys(self._policy)
        self._protected_detector = ProtectedKeyDetector(protected)
        self._cross_task_detector = CrossTaskContaminationDetector(
            self._classification, current_task=current_task
        )

        if detectors is None:
            self._detectors: list[Detector] = [
                PromptInjectionDetector(),
                SensitiveDataDetector(),
                SizeAnomalyDetector(),
                RapidChangeDetector(),
                self._protected_detector,
                self._cross_task_detector,
            ]
        else:
            self._detectors = list(detectors)
            if not any(isinstance(d, ProtectedKeyDetector) for d in self._detectors):
                self._detectors.append(self._protected_detector)
            if not any(
                isinstance(d, CrossTaskContaminationDetector) for d in self._detectors
            ):
                self._detectors.append(self._cross_task_detector)

        for key in self._policy.immutable_keys:
            if key in self._store:
                self._integrity.baseline(key, self._store.get(key))

    # ---- public API ---------------------------------------------------

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def events(self) -> list[SecurityEvent]:
        return list(self._events)

    @property
    def quarantine(self) -> dict[str, Any]:
        return dict(self._quarantine)

    def add_event_handler(self, handler: EventHandler) -> None:
        self._handlers.append(handler)

    def baseline(self, key: str, value: Any | None = None) -> str:
        """Record a SHA-256 baseline for `key`. Uses current stored value if omitted."""
        if value is None:
            if key not in self._store:
                raise KeyError(f"Cannot baseline missing key '{key}'")
            value = self._store.get(key)
        return self._integrity.baseline(key, value)

    def verify(self, key: str) -> None:
        """Raise IntegrityError if `key` no longer matches its baseline."""
        if key in self._store:
            self._integrity.verify(key, self._store.get(key))

    def verify_all(self) -> list[str]:
        """Return the list of keys whose stored value drifted from baseline."""
        drifted: list[str] = []
        for key in list(self._store.keys()):
            try:
                self._integrity.verify(key, self._store.get(key))
            except IntegrityError:
                drifted.append(key)
        return drifted

    @property
    def current_task(self) -> str | None:
        return self._current_task

    def set_current_task(self, task_id: str | None) -> None:
        """Switch the task context used for cross-task contamination checks."""
        self._current_task = task_id
        self._cross_task_detector.set_current_task(task_id)

    def classify(self, key: str) -> MemoryClass | None:
        return self._classification.get(key)

    def origin_task(self, key: str) -> str | None:
        return self._classification.task_of(key)

    def promote(
        self,
        key: str,
        target: MemoryClass,
        *,
        verified: bool = False,
        verified_by: str | None = None,
    ) -> None:
        """Move `key` to a new class. Enforces the promotion graph.

        Promotions that `requires_verification` (e.g. user_preference_candidate
        -> verified_preference) must pass `verified=True`. This is the user
        opt-in step that prevents an ephemeral request from silently becoming
        a durable preference.
        """
        current = self._classification.get(key)
        if current is None:
            raise ClassificationError(
                f"Cannot promote unclassified key '{key}'",
                key=key,
                target_class=target.value,
            )
        if current == target:
            return
        edge = self._promotion_rules.edge(current, target)
        if edge is None:
            self._emit(
                detector="classification",
                severity=Severity.HIGH,
                action=Action.BLOCK,
                operation="promote",
                key=key,
                message=(
                    f"Illegal promotion {current.value} -> {target.value} on '{key}'"
                ),
                metadata={"from": current.value, "to": target.value},
            )
            raise ClassificationError(
                f"Promotion {current.value} -> {target.value} is not allowed",
                key=key,
                source_class=current.value,
                target_class=target.value,
            )
        if edge.requires_verification and not verified:
            self._emit(
                detector="classification",
                severity=Severity.HIGH,
                action=Action.BLOCK,
                operation="promote",
                key=key,
                message=(
                    f"Promotion {current.value} -> {target.value} requires verification"
                ),
                metadata={"from": current.value, "to": target.value},
            )
            raise ClassificationError(
                f"Promotion {current.value} -> {target.value} requires verified=True",
                key=key,
                source_class=current.value,
                target_class=target.value,
            )
        self._classification.set(
            key, target, task_id=self._classification.task_of(key)
        )
        self._emit(
            detector="classification",
            severity=Severity.INFO,
            action=Action.ALLOW,
            operation="promote",
            key=key,
            message=f"Promoted {current.value} -> {target.value}",
            metadata={
                "from": current.value,
                "to": target.value,
                "verified": verified,
                "verified_by": verified_by,
            },
        )

    def write(
        self,
        key: str,
        value: Any,
        *,
        source: str = "agent",
        cls: MemoryClass | str | None = None,
        task_id: str | None = None,
    ) -> Action:
        """Inspect and (if policy allows) commit a write. Returns the action taken.

        Pass `cls=MemoryClass.X` to label the entry with a provenance class.
        Re-writes to an already-classified key must keep the same class —
        promotion is only available through :meth:`promote`. This prevents an
        untrusted source (e.g. a tool result) from silently overwriting a
        trusted entry (e.g. verified_preference or policy).
        """
        if cls is not None:
            target_class = MemoryClass(cls) if not isinstance(cls, MemoryClass) else cls
            existing = self._classification.get(key)
            if existing is not None and existing != target_class:
                self._emit(
                    detector="classification",
                    severity=Severity.HIGH,
                    action=Action.BLOCK,
                    operation="write",
                    key=key,
                    message=(
                        f"Write would reclassify '{key}': {existing.value} -> "
                        f"{target_class.value}; use promote() instead"
                    ),
                    metadata={"from": existing.value, "to": target_class.value},
                )
                raise ClassificationError(
                    f"Cannot reclassify '{key}' on write; use promote()",
                    key=key,
                    source_class=existing.value,
                    target_class=target_class.value,
                )
        else:
            target_class = self._classification.get(key)

        committed_value = value
        verdicts = self._run_detectors(key, value, operation="write")
        worst = _highest_severity(verdicts)
        decision = self._decide(verdicts, key=key)

        if decision == Action.BLOCK:
            self._emit(
                detector=_blocking_detector(verdicts),
                severity=worst,
                action=Action.BLOCK,
                operation="write",
                key=key,
                message=_combined_message(verdicts) or "Write blocked by policy",
                metadata={"source": source},
            )
            if self._snapshot_on_block:
                self._snapshots.capture(
                    self._dump_store(), label="pre-block", metadata={"key": key}
                )
            raise PolicyViolation(
                f"Write to '{key}' blocked by policy", rule=_blocking_detector(verdicts), key=key
            )

        if decision == Action.QUARANTINE:
            self._quarantine[key] = value
            self._emit(
                detector=_blocking_detector(verdicts),
                severity=worst,
                action=Action.QUARANTINE,
                operation="write",
                key=key,
                message="Write quarantined for review",
                metadata={"source": source},
            )
            return Action.QUARANTINE

        if decision == Action.REDACT:
            committed_value = self._redact(value)
            self._emit(
                detector="sensitive_data",
                severity=worst,
                action=Action.REDACT,
                operation="write",
                key=key,
                message="Sensitive content redacted before write",
                metadata={"source": source},
            )

        self._store.set(key, committed_value)

        if target_class is not None:
            existing_task = self._classification.task_of(key)
            self._classification.set(
                key,
                target_class,
                task_id=task_id if task_id is not None else existing_task or self._current_task,
            )

        if key in self._policy.immutable_keys and not self._integrity.has_baseline(key):
            self._integrity.baseline(key, committed_value)

        if any(v.matched for v in verdicts) and decision == Action.ALLOW:
            self._emit(
                detector=_blocking_detector(verdicts),
                severity=worst,
                action=Action.ALLOW,
                operation="write",
                key=key,
                message=_combined_message(verdicts) or "Write allowed with findings",
                metadata={"source": source, **_merged_metadata(verdicts)},
            )
        return decision

    def read(self, key: str, default: Any = None, *, sink: str = "agent") -> Any:
        """Read with integrity verification and outbound leakage screening."""
        if key not in self._store:
            return default

        try:
            self.verify(key)
        except IntegrityError as exc:
            self._emit(
                detector="integrity",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                operation="read",
                key=key,
                message="Integrity verification failed on read",
                metadata={"expected": exc.expected, "actual": exc.actual},
            )
            raise

        value = self._store.get(key, default)
        verdicts = self._run_detectors(key, value, operation="read")
        decision = self._decide(verdicts, key=key)
        worst = _highest_severity(verdicts)

        if decision == Action.BLOCK:
            self._emit(
                detector=_blocking_detector(verdicts),
                severity=worst,
                action=Action.BLOCK,
                operation="read",
                key=key,
                message="Read blocked by policy",
                metadata={"sink": sink},
            )
            raise PolicyViolation(f"Read of '{key}' blocked by policy", key=key)

        if decision == Action.REDACT:
            value = self._redact(value)
            self._emit(
                detector="sensitive_data",
                severity=worst,
                action=Action.REDACT,
                operation="read",
                key=key,
                message="Sensitive content redacted on read",
                metadata={"sink": sink},
            )
        elif any(v.matched for v in verdicts):
            self._emit(
                detector=_blocking_detector(verdicts),
                severity=worst,
                action=Action.ALLOW,
                operation="read",
                key=key,
                message=_combined_message(verdicts) or "Read allowed with findings",
                metadata={"sink": sink, **_merged_metadata(verdicts)},
            )
        return value

    def delete(self, key: str) -> None:
        if self._protected_detector.matches(key):
            self._emit(
                detector="protected_key",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                operation="delete",
                key=key,
                message=f"Delete of protected key '{key}' blocked",
            )
            raise PolicyViolation(f"Delete of '{key}' blocked", key=key)
        self._store.delete(key)
        self._integrity.clear(key)
        self._classification.clear(key)

    # ---- snapshots ----------------------------------------------------

    def snapshot(self, label: str = "manual") -> Snapshot:
        return self._snapshots.capture(self._dump_store(), label=label)

    def list_snapshots(self) -> list[Snapshot]:
        return self._snapshots.list()

    def rollback(self, snapshot_id: str | None = None) -> Snapshot:
        """Restore the store to a known-good snapshot (latest if id omitted)."""
        snap = (
            self._snapshots.get(snapshot_id)
            if snapshot_id
            else self._snapshots.latest()
        )
        if snap is None:
            raise LookupError("No snapshot available for rollback")

        for key in list(self._store.keys()):
            self._store.delete(key)
        for key, value in snap.data.items():
            self._store.set(key, value)

        self._emit(
            detector="rollback",
            severity=Severity.HIGH,
            action=Action.ALLOW,
            operation="rollback",
            key="*",
            message=f"Rolled back to snapshot {snap.snapshot_id} ({snap.label})",
            metadata={"snapshot_id": snap.snapshot_id, "digest": snap.digest},
        )
        return snap

    # ---- internals ----------------------------------------------------

    def _run_detectors(
        self, key: str, value: Any, *, operation: str
    ) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        for detector in self._detectors:
            try:
                result = detector.inspect(key, value, operation=operation)
            except Exception:  # detectors must never break the agent
                log.exception("Detector %s raised", getattr(detector, "name", detector))
                continue
            if result.matched:
                results.append(result)
        return results

    def _decide(self, verdicts: list[DetectionResult], *, key: str) -> Action:
        if not verdicts:
            return Action.ALLOW
        chosen = Action.ALLOW
        for verdict in verdicts:
            action = self._policy.decide(verdict.detector, verdict.severity, key)
            chosen = _escalate(chosen, action)
        return chosen

    def _redact(self, value: Any) -> Any:
        for detector in self._detectors:
            if isinstance(detector, SensitiveDataDetector):
                return detector.redact(value)
        return value

    def _emit(
        self,
        *,
        detector: str,
        severity: Severity,
        action: Action,
        operation: str,
        key: str,
        message: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        event = SecurityEvent(
            detector=detector,
            severity=severity,
            action=action,
            operation=operation,
            key=key,
            message=message,
            metadata=dict(metadata or {}),
        )
        self._events.append(event)
        for handler in self._handlers:
            try:
                handler(event)
            except Exception:
                log.exception("Event handler raised")

    def _dump_store(self) -> dict[str, Any]:
        if hasattr(self._store, "snapshot"):
            return self._store.snapshot()  # type: ignore[no-any-return]
        return {k: v for k, v in self._store.items()}


_ACTION_RANK = {
    Action.ALLOW: 0,
    Action.REDACT: 1,
    Action.QUARANTINE: 2,
    Action.BLOCK: 3,
}


def _escalate(current: Action, candidate: Action) -> Action:
    return candidate if _ACTION_RANK[candidate] > _ACTION_RANK[current] else current


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _highest_severity(verdicts: list[DetectionResult]) -> Severity:
    if not verdicts:
        return Severity.INFO
    return max(verdicts, key=lambda v: _SEVERITY_RANK[v.severity]).severity


def _blocking_detector(verdicts: list[DetectionResult]) -> str:
    if not verdicts:
        return "policy"
    return max(verdicts, key=lambda v: _SEVERITY_RANK[v.severity]).detector


def _combined_message(verdicts: list[DetectionResult]) -> str:
    return "; ".join(v.message for v in verdicts if v.message)


def _merged_metadata(verdicts: list[DetectionResult]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for v in verdicts:
        if v.metadata:
            merged.update(v.metadata)
    return merged


__all__ = ["MemoryGuard", "hash_value"]
