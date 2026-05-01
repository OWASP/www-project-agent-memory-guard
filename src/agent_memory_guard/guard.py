"""MemoryGuard — runtime checkpoint between an agent and its memory store."""
from __future__ import annotations

import logging
from typing import Any, Callable, Iterable

from agent_memory_guard.detectors.base import Detector, DetectionResult
from agent_memory_guard.detectors.anomaly import (
    RapidChangeDetector,
    SizeAnomalyDetector,
)
from agent_memory_guard.detectors.injection import PromptInjectionDetector
from agent_memory_guard.detectors.leakage import SensitiveDataDetector
from agent_memory_guard.detectors.protected_keys import ProtectedKeyDetector
from agent_memory_guard.events import Action, SecurityEvent, Severity
from agent_memory_guard.exceptions import IntegrityError, PolicyViolation
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
    ) -> None:
        self._store: MemoryStore = store if store is not None else InMemoryStore()
        self._policy = policy or Policy.permissive()
        self._integrity = IntegrityRegistry()
        self._snapshots = snapshots if snapshots is not None else SnapshotStore()
        self._handlers: list[EventHandler] = list(event_handlers)
        self._events: list[SecurityEvent] = []
        self._snapshot_on_block = snapshot_on_block
        self._quarantine: dict[str, Any] = {}

        protected = merge_protected_keys(self._policy)
        self._protected_detector = ProtectedKeyDetector(protected)

        if detectors is None:
            self._detectors: list[Detector] = [
                PromptInjectionDetector(),
                SensitiveDataDetector(),
                SizeAnomalyDetector(),
                RapidChangeDetector(),
                self._protected_detector,
            ]
        else:
            self._detectors = list(detectors)
            if not any(isinstance(d, ProtectedKeyDetector) for d in self._detectors):
                self._detectors.append(self._protected_detector)

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

    def write(self, key: str, value: Any, *, source: str = "agent") -> Action:
        """Inspect and (if policy allows) commit a write. Returns the action taken."""
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
