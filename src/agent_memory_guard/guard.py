"""MemoryGuard — runtime checkpoint between an agent and its memory store."""
from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any, Callable

from agent_memory_guard.classification import (
    ClassificationRegistry,
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
from agent_memory_guard.detectors.self_reinforcement import SelfReinforcementDetector
from agent_memory_guard.events import Action, SecurityEvent, Severity, SourceClass, SourceType
from agent_memory_guard.exceptions import (
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
    """Wraps a memory store and screens every read/write through detectors and policies.

    The guard acts as an intermediary runtime defense layer. It is intentionally permissive
    by default: instantiating with no arguments yields a guard that detects threats and
    emits events but does not block writes. Pass `policy=Policy.strict()` (or load from YAML)
    to enable active enforcement.

    Args:
        store: The backing MemoryStore instance. If None, InMemoryStore is used.
        policy: The active security Policy to enforce. If None, Policy.permissive() is used.
        detectors: Optional collection of Detector instances. If None, a default suite is initialized.
        snapshots: Store to manage memory state snapshots. If None, SnapshotStore is initialized.
        event_handlers: Callbacks triggered whenever security events are emitted.
        snapshot_on_block: If True, captures a snapshot when a write is blocked. Defaults to True.
        promotion_rules: Rules dictating valid class transitions. Defaults to PromotionRules().
        current_task: Optional initial task ID for cross-task contamination checks.

    Example:
        >>> from agent_memory_guard import MemoryGuard, Policy
        >>> guard = MemoryGuard(policy=Policy.strict())
        >>> guard.write("session.notes", "Safe memory content")
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
        self._self_reinforcement_detector = SelfReinforcementDetector()

        if detectors is None:
            self._detectors: list[Detector] = [
                PromptInjectionDetector(),
                SensitiveDataDetector(),
                SizeAnomalyDetector(),
                RapidChangeDetector(),
                self._protected_detector,
                self._cross_task_detector,
                self._self_reinforcement_detector,
            ]
        else:
            self._detectors = list(detectors)
            if not any(isinstance(d, ProtectedKeyDetector) for d in self._detectors):
                self._detectors.append(self._protected_detector)
            if not any(
                isinstance(d, CrossTaskContaminationDetector) for d in self._detectors
            ):
                self._detectors.append(self._cross_task_detector)
            user_self_reinf = next(
                (d for d in self._detectors if isinstance(d, SelfReinforcementDetector)),
                None,
            )
            if user_self_reinf is None:
                self._detectors.append(self._self_reinforcement_detector)
            else:
                # Reassign the canonical reference so `_pending_source_class`
                # and `note_independent_write` operate on the detector that
                # actually runs.
                self._self_reinforcement_detector = user_self_reinf

        for key in self._policy.immutable_keys:
            if key in self._store:
                self._integrity.baseline(key, self._store.get(key))

    # ---- public API ---------------------------------------------------

    @property
    def policy(self) -> Policy:
        """Get the active security policy configuration.

        Returns:
            Policy: The policy engine instance currently enforced by this guard.

        Example:
            >>> guard = MemoryGuard(policy=Policy.strict())
            >>> print(guard.policy.default_action)
        """
        return self._policy

    @property
    def events(self) -> list[SecurityEvent]:
        """Get the log of security events emitted during operations.

        Returns:
            list[SecurityEvent]: A copy of the list of recorded security events.

        Example:
            >>> guard = MemoryGuard()
            >>> print(len(guard.events))
        """
        return list(self._events)

    @property
    def quarantine(self) -> dict[str, Any]:
        """Get the dictionary of quarantined memory writes.

        Returns:
            dict[str, Any]: A copy of the dictionary holding quarantined keys and their values.

        Example:
            >>> guard = MemoryGuard()
            >>> print(guard.quarantine)
        """
        return dict(self._quarantine)

    def add_event_handler(self, handler: EventHandler) -> None:
        """Register a callback to handle emitted security events.

        Args:
            handler: A callable that accepts a single SecurityEvent object
                and performs custom handling (e.g. logging, SIEM forwarding).

        Example:
            >>> guard = MemoryGuard()
            >>> guard.add_event_handler(lambda ev: print(ev.message))
        """
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

    def write(
        self,
        key: str,
        value: Any,
        *,
        source: str = "agent",
        source_type: SourceType = SourceType.UNKNOWN,
    ) -> Action:
        """Inspect and (if policy allows) commit a write. Returns the action taken."""
        committed_value = value
        # Map SourceType to SourceClass for self-reinforcement detection
        _source_type_to_class = {
            SourceType.USER_INPUT: SourceClass.USER_INPUT,
            SourceType.TOOL_OUTPUT: SourceClass.EXTERNAL_TOOL,
            SourceType.MODEL_INFERENCE: SourceClass.AGENT_AUTHORED,
            SourceType.SYSTEM: SourceClass.SYSTEM,
            SourceType.UNKNOWN: SourceClass.UNKNOWN,
        }
        normalised_source_class = _source_type_to_class.get(source_type, SourceClass.UNKNOWN)
        self._self_reinforcement_detector._pending_source_class = normalised_source_class
        try:
            verdicts = self._run_detectors(key, value, operation="write")
        finally:
            self._self_reinforcement_detector._pending_source_class = SourceClass.UNKNOWN
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
                source_type=source_type,
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
                source_type=source_type,
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
                source_type=source_type,
            )

        self._store.set(key, committed_value)

        # Independent (non-agent-authored) writes reset the self-reinforcement
        # cool-down: arrival of new external/user evidence is what breaks a
        # self-poisoning loop.
        if normalised_source_class != SourceClass.AGENT_AUTHORED:
            self._self_reinforcement_detector.note_independent_write(key)

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
                metadata={"source": source},
                source_type=source_type,
            )
        return decision

    def read(self, key: str, default: Any = None, *, sink: str = "agent") -> Any:
        """Read a value from the guarded memory store.

        The read triggers integrity verification checks on baseline-monitored keys
        and runs outbound leakage screening before returning the value.

        Args:
            key: The memory key to read from.
            default: The default value to return if the key is not found. Defaults to None.
            sink: The destination/consumer of the read data. Defaults to 'agent'.

        Returns:
            Any: The stored memory value, which may be redacted or modified by detectors,
                or the default value if the key does not exist.

        Raises:
            PolicyViolation: If the policy blocks the read.
            IntegrityError: If the key baseline check fails on read.
        """
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
                source_type=SourceType.UNKNOWN,
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
                source_type=SourceType.UNKNOWN,
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
                source_type=SourceType.UNKNOWN,
            )
        elif any(v.matched for v in verdicts):
            self._emit(
                detector=_blocking_detector(verdicts),
                severity=worst,
                action=Action.ALLOW,
                operation="read",
                key=key,
                message=_combined_message(verdicts) or "Read allowed with findings",
                metadata={"sink": sink},
                source_type=SourceType.UNKNOWN,
            )
        return value

    def delete(self, key: str) -> None:
        """Delete a key and its associated metadata from the memory store.

        This clears the value from storage and resets any associated integrity baselines,
        classification metadata, and detector historical states. Protected keys cannot
        be deleted.

        Args:
            key: The memory key to delete.

        Raises:
            PolicyViolation: If the key matches protected key patterns, blocking deletion.

        Example:
            >>> guard = MemoryGuard()
            >>> guard.write("session.scratch", "temporary data")
            >>> guard.delete("session.scratch")
        """
        if self._protected_detector.matches(key):
            self._emit(
                detector="protected_key",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                operation="delete",
                key=key,
                message=f"Delete of protected key '{key}' blocked",
                source_type=SourceType.UNKNOWN,
            )
            raise PolicyViolation(f"Delete of '{key}' blocked", key=key)
        self._store.delete(key)
        self._integrity.clear(key)
        self._classification.clear(key)
        self._self_reinforcement_detector.reset(key)

    # ---- lifecycle governance ----------------------------------------

    def retire_if(
        self,
        predicate: Callable[[str, Any], bool],
        *,
        reason: str = "lifecycle",
    ) -> list[str]:
        """Remove entries whose `predicate(key, value)` returns True.

        Implements the lifecycle-governance pattern from the
        microsoft/autogen#7683 thread: rather than silently expiring
        memory on a wall-clock schedule, callers describe the condition
        ("retire any `tool_observation` older than 1 hour", "retire any
        entry tagged as low-confidence on next snapshot") and the guard
        captures a forensic snapshot before removing them, so an operator
        can roll back if the retirement turns out to have been premature.

        Returns the list of keys that were retired. Skips protected keys
        (raises no error — they remain in place).
        """
        snap = self._snapshots.capture(
            self._dump_store(), label=f"pre-retire:{reason}"
        )
        retired: list[str] = []
        for key, value in list(self._store.items()):
            if self._protected_detector.matches(key):
                continue
            try:
                should_retire = bool(predicate(key, value))
            except Exception:
                log.exception("retire_if predicate raised on key=%s", key)
                continue
            if not should_retire:
                continue
            self._store.delete(key)
            self._integrity.clear(key)
            self._classification.clear(key)
            self._self_reinforcement_detector.reset(key)
            retired.append(key)
            self._emit(
                detector="lifecycle",
                severity=Severity.INFO,
                action=Action.ALLOW,
                operation="retire",
                key=key,
                message=f"Retired by lifecycle rule '{reason}'",
                metadata={"reason": reason, "pre_snapshot_id": snap.snapshot_id},
                source_class=SourceClass.SYSTEM,
            )
        return retired

    # ---- snapshots ----------------------------------------------------

    def snapshot(self, label: str = "manual") -> Snapshot:
        """Capture a point-in-time snapshot of the guarded memory store.

        This creates a forensic snapshot of the current state of the memory store,
        calculates an integrity digest, and stores it in the snapshot history
        for audit or rollback capability.

        Args:
            label: A descriptive tag for the snapshot (e.g. 'manual', 'pre-block').
                Defaults to 'manual'.

        Returns:
            Snapshot: The captured snapshot instance containing ID, timestamp,
                label, copy of data, and SHA-256 digest.

        Example:
            >>> guard = MemoryGuard()
            >>> guard.write("session.user", "Alice")
            >>> snap = guard.snapshot(label="user_session_init")
            >>> print(snap.snapshot_id)
        """
        return self._snapshots.capture(self._dump_store(), label=label)

    def list_snapshots(self) -> list[Snapshot]:
        """List all captured snapshots in the snapshot store.

        Returns:
            list[Snapshot]: A list of all historical snapshots, ordered from
                oldest to newest.

        Example:
            >>> guard = MemoryGuard()
            >>> guard.snapshot(label="backup_1")
            >>> print(len(guard.list_snapshots()))
        """
        return self._snapshots.list()

    def rollback(self, snapshot_id: str | None = None) -> Snapshot:
        """Restore the memory store to a known-good snapshot state.

        This method clears current stored data and restores all keys and values
        from the specified snapshot. If no snapshot ID is provided, the latest
        captured snapshot is used.

        Args:
            snapshot_id: The unique identifier of the snapshot to restore.
                If None, the latest snapshot is used. Defaults to None.

        Returns:
            Snapshot: The restored snapshot instance.

        Raises:
            LookupError: If no snapshot is found in the snapshot store.
        """
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
            source_type=SourceType.UNKNOWN,
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
        source_type: SourceType = SourceType.UNKNOWN,
    ) -> None:
        event = SecurityEvent(
            detector=detector,
            severity=severity,
            action=action,
            operation=operation,
            key=key,
            message=message,
            source_type=source_type,
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


__all__ = ["MemoryGuard", "hash_value"]
