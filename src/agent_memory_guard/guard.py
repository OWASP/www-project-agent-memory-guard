"""OWASP Agent Memory Guard — core runtime guard."""
from __future__ import annotations

import copy
import dataclasses
import itertools
import logging
import threading
import weakref
from collections.abc import Container, Iterable
from typing import Any, Callable, NoReturn

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
from agent_memory_guard.detectors.injection import (
    MAX_STRINGIFY_DEPTH,
    PromptInjectionDetector,
    exceeds_max_depth,
)
from agent_memory_guard.detectors.leakage import SensitiveDataDetector
from agent_memory_guard.detectors.protected_keys import ProtectedKeyDetector
from agent_memory_guard.detectors.self_reinforcement import SelfReinforcementDetector
from agent_memory_guard.events import Action, SecurityEvent, Severity, SourceClass, SourceType
from agent_memory_guard.exceptions import (
    AccessDenied,
    ClassificationError,
    IntegrityError,
    PolicyViolation,
    UnknownPrincipal,
)
from agent_memory_guard.identity import (
    _AMBIENT,
    _ANCHORED,
    _LAST_TRACE,
    _OP,
    ActingContext,
    AgentHandle,
    _HandleId,
    _OpState,
    ambient_for,
    ambient_identity_possible,
    check_id,
)
from agent_memory_guard.integrity import IntegrityRegistry, hash_value
from agent_memory_guard.policies.access import ADMIN_OPS, AccessDecision, AccessPolicy
from agent_memory_guard.policies.policy import Policy, merge_protected_keys
from agent_memory_guard.storage.memory_store import InMemoryStore, MemoryStore
from agent_memory_guard.storage.snapshots import Snapshot, SnapshotStore
from agent_memory_guard.trace import TraceStep

log = logging.getLogger("agent_memory_guard")

EventHandler = Callable[[SecurityEvent], None]

_GUARD_IDS = itertools.count(1)
# Ids of guards created with trace=True that are still alive; last_trace()
# entries of other guards are dropped.
_LIVE_TRACED: set[int] = set()
# Snapshot.metadata key holding labels, origin tasks and last writers.
_STATE_KEY = "amg_state"
# Operations that run under the guard's lock when the policy has access rules,
# so the class gate and the commit see the same labels.
_LOCKED_OPS = frozenset({"write", "delete", "promote", "rollback", "retire", "snapshot"})
# Traces name the deciding policy rule only while Policy.decide is in use.
_STOCK_DECIDE = Policy.decide


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
        trace: If True, record every step of each decision. ``last_trace()`` returns
            the steps of the last operation and every event carries them in
            ``metadata["trace"]``. Roughly doubles the cost of an operation; meant
            for demos, debugging and incident review.

    Multi-agent use:
        Give the policy access rules with :meth:`Policy.with_access`, then give each
        agent its own handle from :meth:`as_agent`. The guard checks who may read and
        write each key before any detector runs, and every event names the agent.

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
        trace: bool = False,
    ) -> None:
        self._guard_id = next(_GUARD_IDS)
        self._trace_on = bool(trace)
        self._track_trace()
        self._lock = threading.RLock()
        self._written_by: dict[str, str | None] = {}
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

        for key in list(self._store.keys()):
            if self._policy.is_immutable(key):
                self._integrity.baseline(key, self._store.get(key))

    def _track_trace(self) -> None:
        if self._trace_on:
            _LIVE_TRACED.add(self._guard_id)
            weakref.finalize(self, _LIVE_TRACED.discard, self._guard_id)

    def __getstate__(self) -> dict[str, Any]:
        state = self.__dict__.copy()
        state.pop("_lock", None)
        return state

    def __setstate__(self, state: dict[str, Any]) -> None:
        # Copies and unpickled guards are new guards: they get their own id, so
        # with-blocks and last_trace() of the original never apply to them.
        self.__dict__.update(state)
        self.__dict__.setdefault("_trace_on", False)
        self.__dict__.setdefault("_written_by", {})
        self._guard_id = next(_GUARD_IDS)
        self._lock = threading.RLock()
        self._track_trace()

    # ---- identity and access ------------------------------------------

    def as_agent(self, principal: str) -> AgentHandle:
        """Return a handle that acts as ``principal`` on this guard.

        Give the handle, not the guard, to agent and tool code: every call it makes
        runs as that agent, and it cannot claim to be anyone else. Used as a context
        manager (``with guard.as_agent("writer"):``) it also attributes plain
        ``guard.write()``/``read()`` calls inside the block to the agent, on this
        guard only.

        Raises:
            UnknownPrincipal: the policy declares a principals registry without this id.
        """
        pid = check_id(principal)
        access = self._access_policy()
        if access is not None and not access.is_declared(pid):
            raise UnknownPrincipal(
                f"{pid!r} is not declared in the policy's principals registry"
            )
        return AgentHandle(self, pid)

    def explain(
        self,
        operation: str,
        key: str = "*",
        *,
        principal: str | None = None,
        cls: MemoryClass | str | None = None,
        target: MemoryClass | str | None = None,
        verified: bool = False,
        snapshot_id: str | None = None,
    ) -> AccessDecision:
        """Show how access would be decided, without doing anything.

        Runs the same checks, in the same order, as the real operation, but emits
        no events, runs no detectors and changes nothing. ``operation`` is one of
        ``read``, ``write``, ``delete``, ``promote`` (pass ``target=``), ``rollback``
        (pass ``snapshot_id=`` for a snapshot other than the latest), ``retire`` or
        ``snapshot``. Print ``.explain()`` on the result for the steps.

        Content detectors are not part of this answer: an allowed write can still
        be blocked, redacted or quarantined for what it contains.
        """
        ctx = self._resolve(principal)
        access = self._access_policy()
        if access is None:
            return AccessDecision(
                True, operation, key, ctx.principal, ctx.via, None, None, None,
                "the policy has no access rules, so access is not checked (as in 0.3)",
                "none",
            )
        all_rules = not isinstance(principal, _HandleId)
        current, wanted = self._classes_for(operation, key, cls, target)
        if operation == "promote":
            if wanted is None:
                raise ValueError("explain('promote', key) needs target=")
            decision = self._promote_decision(
                ctx, key, current, wanted, verified=verified, all_rules=all_rules
            )
        else:
            decision = access.decide(
                ctx.principal, operation, key, current_class=current, target_class=wanted,
                via=ctx.via, all_rules=all_rules,
            )
            if operation == "rollback" and decision.allowed:
                snap = self._snapshots.get(snapshot_id) if snapshot_id else self._snapshots.latest()
                if snap is None and snapshot_id:
                    raise LookupError(f"No snapshot {snapshot_id!r}")
                if snap is not None:
                    decision = self._rollback_class_check(ctx, snap, decision)
        # Who last wrote a key is read-level information: show it only to agents
        # that may read the key, and to admins.
        if (
            operation not in ADMIN_OPS
            and key in self._written_by
            and (
                access.allows(ctx.principal, "read", key)
                or access.is_admin(ctx.principal)
            )
        ):
            writer = self._written_by[key] or "<anonymous>"
            decision = dataclasses.replace(
                decision,
                steps=(*decision.steps, TraceStep("provenance", f"last committed write by {writer}")),
            )
        return decision

    def written_by(self, key: str) -> str | None:
        """The agent whose write last committed ``key`` (None if anonymous or unknown)."""
        return self._written_by.get(key)

    def last_trace(self) -> tuple[TraceStep, ...] | None:
        """Steps of this guard's last operation in the current context.

        None unless the guard was created with ``trace=True``. Render with
        :func:`agent_memory_guard.format_trace`.
        """
        if not self._trace_on:
            return None
        return _LAST_TRACE.get().get(self._guard_id)

    def _access_policy(self) -> AccessPolicy | None:
        return getattr(self._policy, "access", None)

    def _resolve(self, explicit: str | None) -> ActingContext:
        if explicit is not None:
            via = "handle" if isinstance(explicit, _HandleId) else "explicit"
            return ActingContext(self._guard_id, check_id(explicit), via)
        ambient = ambient_for(self._guard_id) if ambient_identity_possible(self._guard_id) else None
        if ambient is not None:
            access = self._access_policy()
            if access is None or access.ambient_identity:
                return ambient
        return ActingContext(self._guard_id, None, "anonymous")

    def _op_state(self) -> _OpState | None:
        state = _OP.get()
        return state if state is not None and state.guard_id == self._guard_id else None

    def _tracing(self) -> bool:
        if not self._trace_on:
            return False
        state = self._op_state()
        return state is not None and state.steps is not None

    def _step(self, stage: str, detail: str, outcome: str = "") -> None:
        if not self._trace_on:
            return
        state = self._op_state()
        if state is not None and state.steps is not None:
            state.steps.append(TraceStep(stage, detail, outcome))

    def _run(
        self,
        operation: str,
        key: str,
        explicit: str | None,
        gate: Callable[[ActingContext], None] | None,
        body: Callable[[ActingContext], Any],
    ) -> Any:
        """Run one public operation: resolve identity, check access, record the trace."""
        ctx = self._resolve(explicit)
        if (
            ctx.principal is None
            and not self._trace_on
            and self._access_policy() is None
            and self._op_state() is None
        ):
            return body(ctx)  # the 0.3 path: nothing to check, attribute or record
        steps: list[TraceStep] | None = [] if self._trace_on else None
        state = _OpState(self._guard_id, ctx, steps)
        token = _OP.set(state)
        access = self._access_policy()
        lock = self._lock if access is not None and operation in _LOCKED_OPS else None
        try:
            if steps is not None:
                steps.append(TraceStep("identity", ctx.principal or "<anonymous>", f"via {ctx.via}"))
                steps.append(TraceStep("operation", f"{operation} {key!r}"))
            if lock is not None:
                # Another thread must not relabel the key between the class gate
                # and the commit.
                with lock:
                    if gate is not None:
                        gate(ctx)
                    state.mark_checked()
                    result = body(ctx)
            else:
                if gate is not None and access is not None:
                    gate(ctx)
                state.mark_checked()
                result = body(ctx)
            if steps is not None:
                steps.append(TraceStep("result", _describe(operation, result), "done"))
            return result
        except BaseException as exc:
            if steps is not None:
                steps.append(TraceStep("result", f"raised {type(exc).__name__}", "stopped"))
            raise
        finally:
            _OP.reset(token)
            if steps is not None:
                traces = {g: t for g, t in _LAST_TRACE.get().items() if g in _LIVE_TRACED}
                traces[self._guard_id] = tuple(steps)
                _LAST_TRACE.set(traces)

    def _classes_for(
        self,
        operation: str,
        key: str,
        cls: MemoryClass | str | None,
        target: MemoryClass | str | None,
    ) -> tuple[MemoryClass | None, MemoryClass | None]:
        """(current label, requested class) that the class gate checks for an operation."""
        if operation == "write":
            return self._classification.get(key), (MemoryClass(cls) if cls is not None else None)
        if operation == "delete":
            return self._classification.get(key), None
        if operation == "promote":
            return self._classification.get(key), (
                MemoryClass(target) if target is not None else None
            )
        return None, None

    def _enforce(
        self,
        ctx: ActingContext,
        operation: str,
        key: str,
        *,
        current_class: MemoryClass | None = None,
        target_class: MemoryClass | None = None,
    ) -> None:
        access = self._access_policy()
        if access is None:
            return
        tracing = self._tracing()
        if not tracing and access.allows(
            ctx.principal, operation, key, current_class=current_class, target_class=target_class
        ):
            return
        decision = access.decide(
            ctx.principal, operation, key, current_class=current_class,
            target_class=target_class, via=ctx.via, all_rules=ctx.via != "handle",
        )
        self._record(decision)
        if not decision.allowed:
            self._deny(decision)

    def _record(self, decision: AccessDecision) -> None:
        if self._tracing():
            for step in decision.steps:
                self._step(step.stage, step.detail, step.outcome)
            self._step("access", decision.reason, "allow" if decision.allowed else "DENY")

    def _deny(self, decision: AccessDecision) -> NoReturn:
        self._step("skipped", "detectors not run, store untouched, no snapshot")
        self._emit(
            detector="access_control",
            severity=Severity.HIGH,
            action=Action.BLOCK,
            operation=decision.operation,
            key=decision.key,
            message=decision.reason,
            metadata=decision.as_metadata(),
        )
        raise AccessDenied(decision)

    def _promotion_problem(
        self, key: str, current: MemoryClass | None, target: MemoryClass, verified: bool
    ) -> str | None:
        """Why the promotion graph refuses this promotion, or None (mirrors promote())."""
        if current is None:
            return f"cannot promote unclassified key {key!r}"
        if current == target:
            return None
        edge = self._promotion_rules.edge(current, target)
        if edge is None:
            return f"promotion {current.value} -> {target.value} is not allowed"
        if edge.requires_verification and not verified:
            return f"promotion {current.value} -> {target.value} requires verified=True"
        return None

    def _promote_decision(
        self,
        ctx: ActingContext,
        key: str,
        current: MemoryClass | None,
        target: MemoryClass,
        *,
        verified: bool,
        all_rules: bool = True,
    ) -> AccessDecision:
        """The promote stages in the order promote() runs them: rule, graph, class."""
        access = self._access_policy()
        assert access is not None
        acl = access.decide(ctx.principal, "promote", key, via=ctx.via, all_rules=all_rules)
        if not acl.allowed:
            return acl
        edge = f"{current.value if current else 'unclassified'} -> {target.value}"
        problem = self._promotion_problem(key, current, target, verified)
        if problem is not None:
            return dataclasses.replace(
                acl, allowed=False, stage="classification", reason=problem, rule=None,
                pattern=None, owner=None,
                steps=(*acl.steps, TraceStep("graph", edge, "refused")),
            )
        if current == target:
            return dataclasses.replace(
                acl, reason=f"already {target.value}; nothing to do",
                steps=(*acl.steps, TraceStep("graph", edge, "no change")),
            )
        full = access.decide(
            ctx.principal, "promote", key, current_class=current, target_class=target,
            via=ctx.via, all_rules=all_rules,
        )
        class_steps = tuple(s for s in full.steps if s.stage == "class")
        return dataclasses.replace(
            full, steps=(*acl.steps, TraceStep("graph", edge, "allowed"), *class_steps)
        )

    def _security_state(self, keys: Container[str]) -> dict[str, Any]:
        """Labels, origin tasks and last writers of ``keys`` (the captured keys)."""
        written_by = dict(self._written_by)
        return {
            **self._classification.export_state(keys),
            "written_by": {k: v for k, v in written_by.items() if k in keys},
        }

    def _capture(self, label: str, metadata: dict[str, Any] | None = None) -> Snapshot:
        data = self._dump_store()
        meta = dict(metadata or {})
        meta[_STATE_KEY] = self._security_state(data)
        snap = self._snapshots.capture(data, label=label, metadata=meta)
        self._step("snapshot", label, snap.snapshot_id)
        return snap

    # ---- public API ---------------------------------------------------

    @property
    def policy(self) -> Policy:
        """Get the active security policy configuration."""
        return self._policy

    @property
    def events(self) -> list[SecurityEvent]:
        """Get the log of security events emitted during operations."""
        return list(self._events)

    @property
    def quarantine(self) -> dict[str, Any]:
        """Get the dictionary of quarantined memory writes."""
        return dict(self._quarantine)

    @property
    def current_task(self) -> str | None:
        """Get the current task context ID."""
        return self._current_task

    def set_current_task(self, task_id: str | None) -> None:
        """Switch the task context used for cross-task contamination checks."""
        self._current_task = task_id
        self._cross_task_detector.set_current_task(task_id)

    def classify(self, key: str) -> MemoryClass | None:
        """Return the current classification of a key, or None if unclassified."""
        return self._classification.get(key)

    def origin_task(self, key: str) -> str | None:
        """Return the task ID that originally wrote this key."""
        return self._classification.task_of(key)

    def promote(
        self,
        key: str,
        target: MemoryClass,
        *,
        verified: bool = False,
        verified_by: str | None = None,
        principal: str | None = None,
    ) -> None:
        """Move `key` to a new class. Enforces the promotion graph.

        Promotions that `requires_verification` (e.g. user_preference_candidate
        -> verified_preference) must pass `verified=True`. This is the user
        opt-in step that prevents an ephemeral request from silently becoming
        a durable preference.

        With access rules, the caller must be a writer of the key, and a promotion
        into or out of a gated class (POLICY, VERIFIED_PREFERENCE by default) also
        needs ``class_writers``. ``verified_by`` defaults to the acting principal.
        """

        def gate(ctx: ActingContext) -> None:
            self._enforce(ctx, "promote", key)  # the key rule; the class gate runs after the graph

        def body(ctx: ActingContext) -> None:
            by = verified_by if verified_by is not None else ctx.principal
            self._promote_impl(key, target, verified=verified, verified_by=by, ctx=ctx)

        self._run("promote", key, principal, gate, body)

    def _promote_impl(
        self,
        key: str,
        target: MemoryClass,
        *,
        verified: bool,
        verified_by: str | None,
        ctx: ActingContext,
    ) -> None:
        if self._access_policy() is not None:
            target = MemoryClass(target)
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
        if self._access_policy() is not None:
            # The rule check ran before the graph checks; now the class gate,
            # on both the current and the target class.
            decision = self._promote_decision(
                ctx, key, current, target, verified=verified, all_rules=ctx.via != "handle"
            )
            # The gate already traced the rule steps; add the graph and class steps.
            self._record(dataclasses.replace(
                decision, steps=tuple(s for s in decision.steps if s.stage in ("graph", "class"))
            ))
            if not decision.allowed:
                self._deny(decision)
        self._step("commit", f"{key} {current.value} -> {target.value}", "promoted")
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

    def add_event_handler(self, handler: EventHandler) -> None:
        """Register a callback to handle emitted security events."""
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
        source_class: SourceClass | str | None = None,
        source_type: SourceType = SourceType.UNKNOWN,
        receipt_uri: str | None = None,
        cls: MemoryClass | str | None = None,
        task_id: str | None = None,
        principal: str | None = None,
    ) -> Action:
        """Inspect and (if policy allows) commit a write. Returns the action taken.

        Parameters
        ----------
        source_class
            Provenance of this write — drives the self-reinforcement detector
            and per-class telemetry. Use :class:`SourceClass.AGENT_AUTHORED`
            for writes the agent generates from its own reasoning;
            :class:`SourceClass.EXTERNAL_TOOL` for tool outputs;
            :class:`SourceClass.USER_INPUT` for direct user content.
        source_type
            Legacy provenance type. If source_class is not provided, source_type
            is mapped to source_class automatically.
        receipt_uri
            Optional pointer into an external audit / receipt chain (e.g.
            an Ed25519 co-signed receipt URI). Stored on the emitted
            ``SecurityEvent`` so downstream SOC tooling can correlate
            guard decisions with execution receipts.
        cls
            Provenance class for the entry (see :class:`MemoryClass`).
        task_id
            Override the task scope for this entry (defaults to the guard's
            current task).
        principal
            The agent making the write. Defaults to the ambient agent of a
            ``with guard.as_agent(...)`` block, else anonymous. When the policy has
            access rules they are checked first, and a denial raises
            :class:`AccessDenied` before any detector runs. When set and ``source``
            is left at ``"agent"``, events record the principal as the source.
        """

        if (
            principal is None
            and not self._trace_on
            and _OP.get() is None
            and not _AMBIENT.get()
            and self._guard_id not in _ANCHORED
            and getattr(self._policy, "access", None) is None
        ):  # the 0.3 path: nothing to check, attribute or record
            action = self._write_impl(
                key, value, source=source, source_class=source_class, source_type=source_type,
                receipt_uri=receipt_uri, cls=cls, task_id=task_id,
            )
            if self._written_by and action in (Action.ALLOW, Action.REDACT):
                self._written_by.pop(key, None)  # the last write was anonymous
            return action

        def gate(ctx: ActingContext) -> None:
            current, wanted = self._classes_for("write", key, cls, None)
            self._enforce(ctx, "write", key, current_class=current, target_class=wanted)

        def body(ctx: ActingContext) -> Action:
            src = ctx.principal if ctx.principal is not None and source == "agent" else source
            stored = _detach(value) if self._access_policy() is not None else value
            action = self._write_impl(
                key, stored, source=src, source_class=source_class, source_type=source_type,
                receipt_uri=receipt_uri, cls=cls, task_id=task_id,
            )
            if action in (Action.ALLOW, Action.REDACT):
                self._written_by[key] = ctx.principal
            return action

        return self._run("write", key, principal, gate, body)  # type: ignore[no-any-return]

    def _write_impl(
        self,
        key: str,
        value: Any,
        *,
        source: str,
        source_class: SourceClass | str | None,
        source_type: SourceType,
        receipt_uri: str | None,
        cls: MemoryClass | str | None,
        task_id: str | None,
    ) -> Action:
        # Resolve source_class: explicit source_class takes priority,
        # otherwise map from source_type for backward compatibility
        if source_class is not None:
            normalised_source_class: SourceClass = _coerce_source_class(source_class)
        else:
            _source_type_to_class = {
                SourceType.USER_INPUT: SourceClass.USER_INPUT,
                SourceType.TOOL_OUTPUT: SourceClass.EXTERNAL_TOOL,
                SourceType.MODEL_INFERENCE: SourceClass.AGENT_AUTHORED,
                SourceType.SYSTEM: SourceClass.SYSTEM,
                SourceType.UNKNOWN: SourceClass.UNKNOWN,
            }
            normalised_source_class = _source_type_to_class.get(source_type, SourceClass.UNKNOWN)

        # Classification: handle cls parameter
        target_class: MemoryClass | None
        if cls is not None:
            requested = MemoryClass(cls) if not isinstance(cls, MemoryClass) else cls
            target_class = requested
            existing = self._classification.get(key)
            if existing is not None and existing != requested:
                self._emit(
                    detector="classification",
                    severity=Severity.HIGH,
                    action=Action.BLOCK,
                    operation="write",
                    key=key,
                    message=(
                        f"Write would reclassify '{key}': {existing.value} -> "
                        f"{requested.value}; use promote() instead"
                    ),
                    metadata={"from": existing.value, "to": requested.value},
                    source_class=normalised_source_class,
                    receipt_uri=receipt_uri,
                )
                raise ClassificationError(
                    f"Cannot reclassify '{key}' on write; use promote()",
                    key=key,
                    source_class=existing.value,
                    target_class=requested.value,
                )
        else:
            target_class = self._classification.get(key)

        committed_value = value
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
                source_class=normalised_source_class,
                receipt_uri=receipt_uri,
            )
            if self._snapshot_on_block:
                self._capture("pre-block", metadata={"key": key})
            raise PolicyViolation(
                f"Write to '{key}' blocked by policy", rule=_blocking_detector(verdicts), key=key
            )

        if decision == Action.QUARANTINE:
            self._quarantine[key] = value
            self._step("quarantine", key, "held for review, not stored")
            self._emit(
                detector=_blocking_detector(verdicts),
                severity=worst,
                action=Action.QUARANTINE,
                operation="write",
                key=key,
                message="Write quarantined for review",
                metadata={"source": source},
                source_class=normalised_source_class,
                receipt_uri=receipt_uri,
            )
            return Action.QUARANTINE

        if decision == Action.REDACT:
            committed_value = self._redact(value)
            self._step("redact", "sensitive_data", "secrets masked")
            self._emit(
                detector="sensitive_data",
                severity=worst,
                action=Action.REDACT,
                operation="write",
                key=key,
                message="Sensitive content redacted before write",
                metadata={"source": source},
                source_class=normalised_source_class,
                receipt_uri=receipt_uri,
            )

        self._store.set(key, committed_value)
        if self._trace_on:
            self._step("commit", key, "stored redacted" if decision == Action.REDACT else "stored")

        # Committed non-agent writes may decay self-reinforcement history only
        # when their provenance class is configured as trusted corroboration.
        if normalised_source_class != SourceClass.AGENT_AUTHORED:
            self._self_reinforcement_detector.note_independent_write(
                key, normalised_source_class
            )

        if target_class is not None:
            existing_task = self._classification.task_of(key)
            self._classification.set(
                key,
                target_class,
                task_id=task_id if task_id is not None else existing_task or self._current_task,
            )

        if self._policy.is_immutable(key) and not self._integrity.has_baseline(key):
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
                source_class=normalised_source_class,
                receipt_uri=receipt_uri,
            )
        return decision

    def read(
        self,
        key: str,
        default: Any = None,
        *,
        sink: str = "agent",
        principal: str | None = None,
    ) -> Any:
        """Read with integrity verification and outbound leakage screening.

        With access rules, the reader is checked first, before the guard looks for
        the key, so a denied reader cannot tell a missing key from a forbidden one.
        """

        if (
            principal is None
            and not self._trace_on
            and _OP.get() is None
            and not _AMBIENT.get()
            and self._guard_id not in _ANCHORED
            and getattr(self._policy, "access", None) is None
        ):  # the 0.3 path: nothing to check, attribute or record
            return self._read_impl(key, default, sink=sink)

        def gate(ctx: ActingContext) -> None:
            self._enforce(ctx, "read", key)

        detach = self._access_policy() is not None
        return self._run(
            "read", key, principal, gate,
            lambda ctx: self._read_impl(key, default, sink=sink, detach=detach),
        )

    def _read_impl(self, key: str, default: Any, *, sink: str, detach: bool = False) -> Any:
        if key not in self._store:
            self._step("lookup", key, "not found; default returned")
            return default

        tracing = self._trace_on and self._tracing()
        has_baseline = tracing and self._integrity.has_baseline(key)
        try:
            self.verify(key)
        except IntegrityError as exc:
            self._step("integrity", "sha-256 baseline", "MISMATCH")
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
        if tracing:
            self._step("integrity", "sha-256 baseline", "match" if has_baseline else "no baseline")

        value = self._store.get(key, default)
        if detach:
            # A reader gets its own copy: changing it must not change the stored
            # value, which only the key's writers may do.
            value = _detach(value)
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
            self._step("redact", "sensitive_data", "secrets masked in the returned value")
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

    def delete(self, key: str, *, principal: str | None = None) -> None:
        """Delete a key and its associated metadata from the memory store.

        With access rules the caller must be a writer of the key, and deleting a
        key labelled with a gated class also needs ``class_writers``. Protected
        keys cannot be deleted by anyone.
        """

        if (
            principal is None
            and not self._trace_on
            and _OP.get() is None
            and not _AMBIENT.get()
            and self._guard_id not in _ANCHORED
            and getattr(self._policy, "access", None) is None
        ):  # the 0.3 path: nothing to check, attribute or record
            self._delete_impl(key)
            if self._written_by:
                self._written_by.pop(key, None)
            return

        def gate(ctx: ActingContext) -> None:
            current, _ = self._classes_for("delete", key, None, None)
            self._enforce(ctx, "delete", key, current_class=current)

        def body(ctx: ActingContext) -> None:
            self._delete_impl(key)
            self._written_by.pop(key, None)

        self._run("delete", key, principal, gate, body)

    def _delete_impl(self, key: str) -> None:
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
        self._self_reinforcement_detector.reset(key)

    # ---- lifecycle governance ----------------------------------------

    def retire_if(
        self,
        predicate: Callable[[str, Any], bool],
        *,
        reason: str = "lifecycle",
        principal: str | None = None,
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

        With access rules, only an admin may call it, and it also skips keys
        labelled with a class the caller may not change (POLICY and
        VERIFIED_PREFERENCE by default; see ``class_writers``). The predicate is
        not called for skipped keys.
        """

        def gate(ctx: ActingContext) -> None:
            self._enforce(ctx, "retire", "*")

        return self._run(  # type: ignore[no-any-return]
            "retire", "*", principal, gate,
            lambda ctx: self._retire_if_impl(predicate, reason, ctx.principal),
        )

    def _retire_if_impl(
        self, predicate: Callable[[str, Any], bool], reason: str, principal: str | None = None
    ) -> list[str]:
        access = self._access_policy()
        snap = self._capture(f"pre-retire:{reason}")
        retired: list[str] = []
        for key, value in list(self._store.items()):
            if self._protected_detector.matches(key):
                continue
            if access is not None and not access.may_change_class(
                principal, self._classification.get(key)
            ):
                self._step("class", key, "kept: caller may not change its class")
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
            self._written_by.pop(key, None)
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

    def snapshot(self, label: str = "manual", *, principal: str | None = None) -> Snapshot:
        """Capture a point-in-time snapshot of the guarded memory store.

        The snapshot also records each key's class label, origin task and last
        writer, so :meth:`rollback` restores them with the data. With access rules,
        only one of the policy's ``admins`` may call it; if the rules name no admins,
        nobody may (add ``"<anonymous>"`` to ``admins`` for the 0.3 behaviour).
        """

        def gate(ctx: ActingContext) -> None:
            self._enforce(ctx, "snapshot", "*")

        return self._run(  # type: ignore[no-any-return]
            "snapshot", "*", principal, gate, lambda ctx: self._capture(label)
        )

    def list_snapshots(self) -> list[Snapshot]:
        """List all captured snapshots in the snapshot store."""
        return self._snapshots.list()

    def rollback(self, snapshot_id: str | None = None, *, principal: str | None = None) -> Snapshot:
        """Restore the store to a known-good snapshot (latest if id omitted).

        Class labels, origin tasks and last writers are restored too, for snapshots
        that recorded them. With access rules, only an admin may call it, and an
        admin who may not change a gated class (see ``class_writers``) may not roll
        back a snapshot that would add, remove, change or relabel memory of that
        class.
        """

        def gate(ctx: ActingContext) -> None:
            self._enforce(ctx, "rollback", "*")

        return self._run(  # type: ignore[no-any-return]
            "rollback", "*", principal, gate, lambda ctx: self._rollback_impl(snapshot_id, ctx)
        )

    def _rollback_class_check(
        self, ctx: ActingContext, snap: Snapshot, decision: AccessDecision
    ) -> AccessDecision:
        """Deny the rollback if it would change memory of a class the caller may not change."""
        access = self._access_policy()
        if access is None:
            return decision
        principal = ctx.principal
        now = self._classification.export_state()["classes"]
        state = _snapshot_state(snap)
        # A snapshot from before 0.4 leaves labels as they are.
        then = dict(state.get("classes") or {}) if isinstance(state, dict) else now
        def locked(label: str | None) -> MemoryClass | None:
            if label is None:
                return None
            cls = MemoryClass(label)
            return None if access.may_change_class(principal, cls) else cls

        keys = {k for k, c in now.items() if locked(c)} | {k for k, c in then.items() if locked(c)}
        if not keys:
            return decision
        for key in sorted(keys):
            in_now, in_then = key in self._store, key in snap.data
            changed = (
                now.get(key) != then.get(key)
                or in_now != in_then
                or (in_now and not _same_value(self._store.get(key), snap.data[key]))
            )
            if not changed:
                continue
            cls = locked(now.get(key)) or locked(then.get(key))
            assert cls is not None
            who = principal or "<anonymous>"
            sels = [sel.raw for sel in access._class_sel.get(cls, ())]
            why = (f"{who} may not roll back to snapshot {snap.snapshot_id}: it would change "
                   f"{key!r}, which is class {cls.value} (class_writers {sels or 'none named'})")
            return dataclasses.replace(
                decision, allowed=False, stage="class", reason=why,
                rule=f"class_writers[{cls.value}]", pattern=None, owner=None,
                steps=(*decision.steps, TraceStep("class", f"{key} {cls.value}", "changed; no match")),
            )
        return dataclasses.replace(
            decision,
            steps=(*decision.steps, TraceStep("class", "gated memory", "unchanged by this snapshot")),
        )

    def _rollback_impl(self, snapshot_id: str | None, ctx: ActingContext | None = None) -> Snapshot:
        snap = (
            self._snapshots.get(snapshot_id)
            if snapshot_id
            else self._snapshots.latest()
        )
        if snap is None:
            raise LookupError("No snapshot available for rollback")
        access = self._access_policy()
        if access is not None and ctx is not None:
            gated = {c for c in access.gated_classes()
                     if not access.may_change_class(ctx.principal, c)}
            if gated:
                allowed = access.decide(ctx.principal, "rollback", "*", via=ctx.via,
                                        all_rules=ctx.via != "handle")
                decision = self._rollback_class_check(ctx, snap, allowed)
                if not decision.allowed:
                    self._record(dataclasses.replace(
                        decision, steps=tuple(s for s in decision.steps if s.stage == "class")
                    ))
                    self._deny(decision)

        if hasattr(self._store, "restore"):
            self._store.restore(snap.data)
        else:
            for key in list(self._store.keys()):
                self._store.delete(key)
            # Restore copies, so that editing a restored value cannot change the snapshot.
            for key, value in snap.data.items():
                self._store.set(key, _copy_or_share(value))

        state = _snapshot_state(snap)
        if isinstance(state, dict):
            self._classification.import_state(state)  # copies into new dicts
            self._written_by = dict(state.get("written_by") or {})
        else:  # a snapshot from before 0.4: labels stay as they are, last writers are unknown
            self._written_by = {}
        self._step("restore", f"snapshot {snap.snapshot_id} ({snap.label})", "restored")

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
        tracing = self._trace_on and self._tracing()
        for detector in self._detectors:
            try:
                result = detector.inspect(key, value, operation=operation)
            except Exception as exc:  # detectors must never break the agent
                name = getattr(detector, "name", type(detector).__name__)
                log.exception("Detector %s raised", name)
                self._step("detector", name, f"raised {type(exc).__name__}; skipped")
                # The verdict is dropped so a broken detector can't stop the
                # agent, but that fail-open must not be silent: without an event
                # here, guard.events looks clean even though this detector never
                # ran. Emit a low-severity operational event an operator can see.
                self._emit(
                    detector=name,
                    severity=Severity.LOW,
                    action=Action.ALLOW,
                    operation=operation,
                    key=key,
                    message=f"Detector {name} raised {type(exc).__name__}; verdict skipped",
                    metadata={
                        "detector_error": True,
                        "error_type": type(exc).__name__,
                    },
                )
                continue
            if tracing:
                name = getattr(detector, "name", None) or result.detector
                self._step("detector", name, result.severity.value if result.matched else "clear")
            if result.matched:
                results.append(result)
        # Content below MAX_STRINGIFY_DEPTH is truncated before any detector reads
        # it, so a payload nested deeper than that would otherwise be allowed with
        # no event. Content that could not be inspected is a finding, not silence:
        # report it as a size anomaly so the policy decides (strict quarantines;
        # permissive allows it but records the event).
        if exceeds_max_depth(value):
            self._step("detector", "size_anomaly", "high (nested too deep to inspect)")
            results.append(
                DetectionResult(
                    detector="size_anomaly",
                    matched=True,
                    severity=Severity.HIGH,
                    message=(
                        f"Value for '{key}' nests deeper than {MAX_STRINGIFY_DEPTH} levels; "
                        "content below that depth could not be inspected"
                    ),
                    metadata={"max_depth": MAX_STRINGIFY_DEPTH, "uninspected_content": True},
                )
            )
        return results

    def _decide(self, verdicts: list[DetectionResult], *, key: str) -> Action:
        tracing = self._trace_on and self._tracing()
        if not verdicts:
            if tracing:
                self._step("policy", "no findings", "allow")
            return Action.ALLOW
        chosen = Action.ALLOW
        for verdict in verdicts:
            # The verdict always comes from decide(), so tracing never changes it.
            action = self._policy.decide(verdict.detector, verdict.severity, key)
            if tracing:
                detail = f"decide() -> {action.value}"
                if getattr(self._policy.decide, "__func__", None) is _STOCK_DECIDE:
                    named, rule = self._policy.evaluate(verdict.detector, verdict.severity, key)
                    if named == action:
                        detail = f"rule {rule or 'default_action'} -> {action.value}"
                self._step("policy", f"{verdict.detector}/{verdict.severity.value}", detail)
            chosen = _escalate(chosen, action)
        if tracing:
            self._step("decision", "most severe action wins", chosen.value)
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
        source_class: SourceClass = SourceClass.UNKNOWN,
        receipt_uri: str | None = None,
    ) -> None:
        principal: str | None = None
        state = _OP.get()
        if state is not None and state.guard_id != self._guard_id:
            state = None
        if state is not None:
            principal = state.ctx.principal
            if state.steps is not None:
                state.steps.append(TraceStep("event", f"{detector} logged", action.value))
                metadata = {**(metadata or {}), "trace": [s.as_dict() for s in state.event_steps()]}
        event = SecurityEvent(
            principal=principal,
            detector=detector,
            severity=severity,
            action=action,
            operation=operation,
            key=key,
            message=message,
            source_class=source_class,
            receipt_uri=receipt_uri,
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


def _describe(operation: str, result: Any) -> str:
    """A short, value-free description of an operation's result, for traces."""
    if isinstance(result, Action):
        return f"returned {result.value}"
    if isinstance(result, Snapshot):
        return f"snapshot {result.snapshot_id}"
    if operation == "retire":
        return f"retired {len(result)} key(s)"
    if operation == "read":
        return "value returned"
    return "completed"


def _snapshot_state(snap: Snapshot) -> Any:
    """The guard state a snapshot recorded (None for snapshots from before 0.4)."""
    meta = getattr(snap, "metadata", None)
    return meta.get(_STATE_KEY) if isinstance(meta, dict) else None


def _copy_or_share(value: Any) -> Any:
    """A deep copy of ``value``, or ``value`` itself if it cannot be copied (as in 0.3)."""
    try:
        try:
            return copy.deepcopy(value)
        except RecursionError:
            return _copy_nested(value)
    except Exception:
        return value


def _detach(value: Any) -> Any:
    """A private deep copy of ``value``, so no two agents share a mutable object."""
    try:
        try:
            return copy.deepcopy(value)
        except RecursionError:
            return _copy_nested(value)  # nested deeper than deepcopy can recurse
    except Exception as exc:
        raise TypeError(
            "With access rules, memory values must be deep-copyable, so that an agent "
            "cannot change memory it may only read by changing a shared object: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


_MUTABLE = (list, dict, set)
_IMMUTABLE = (tuple, frozenset)


def _children(value: Any) -> Iterable[Any]:
    if type(value) is dict:
        return [x for kv in value.items() for x in kv]
    return value  # type: ignore[no-any-return]


def _copy_nested(root: Any) -> Any:
    """Deep-copy plain lists, dicts, sets, tuples and frozensets without recursion.

    Other objects are copied with copy.deepcopy. Shared and cyclic references
    are preserved, as deepcopy would.
    """
    containers: dict[int, Any] = {}  # id -> original container
    stack = [root]
    while stack:  # find every plain container
        value = stack.pop()
        if type(value) in _MUTABLE + _IMMUTABLE and id(value) not in containers:
            containers[id(value)] = value
            stack.extend(_children(value))
    copies: dict[int, Any] = {i: type(v)() for i, v in containers.items() if type(v) in _MUTABLE}
    leaf_memo: dict[int, Any] = {}

    def get(value: Any) -> Any:
        if id(value) in containers:
            return copies[id(value)]
        return copy.deepcopy(value, leaf_memo)

    for original in containers.values():  # tuples and frozensets, children first
        if type(original) not in _IMMUTABLE or id(original) in copies:
            continue
        todo: list[tuple[Any, bool]] = [(original, False)]
        while todo:
            node, ready = todo.pop()
            if id(node) in copies:
                continue
            if ready:
                copies[id(node)] = type(node)(get(c) for c in node)
                continue
            todo.append((node, True))
            todo.extend(
                (c, False) for c in node if type(c) in _IMMUTABLE and id(c) not in copies
            )
    for i, original in containers.items():  # then fill the mutable containers
        shell = copies[i]
        if type(original) is dict:
            for k, v in original.items():
                shell[get(k)] = get(v)
        elif type(original) is list:
            shell.extend(get(c) for c in original)
        elif type(original) is set:
            shell.update(get(c) for c in original)
    return get(root)


def _same_value(a: Any, b: Any) -> bool:
    try:
        return bool(a == b)
    except Exception:  # values that cannot be compared count as changed
        return False


def _coerce_source_class(value: SourceClass | str | None) -> SourceClass:
    if value is None:
        return SourceClass.UNKNOWN
    if isinstance(value, SourceClass):
        return value
    return SourceClass(str(value))


__all__ = ["MemoryGuard", "hash_value"]
