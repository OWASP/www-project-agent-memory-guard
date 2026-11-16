"""Pending writes stay outside committed memory until trusted resolution."""

from __future__ import annotations

import copy
import dataclasses
import json
import pickle
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from agent_memory_guard import (
    AccessRule,
    Action,
    MemoryClass,
    MemoryGuard,
    PendingWriteError,
    Policy,
    PolicyViolation,
    SourceClass,
    WriteGateRule,
)
from agent_memory_guard.detectors.base import DetectionResult
from agent_memory_guard.events import Severity
from agent_memory_guard.policies.policy import PolicyRule, load_policy
from agent_memory_guard.storage.memory_store import InMemoryStore


def gate(action=Action.REQUIRE_APPROVAL, **kwargs):
    return WriteGateRule("high_impact", ("settings.*",), action=action, **kwargs)


def policy(action=Action.REQUIRE_APPROVAL, **kwargs):
    return Policy(write_gates=(gate(action, **kwargs),))


@pytest.mark.parametrize("path", ["legacy", "principal", "handle", "ambient", "trace"])
def test_pending_is_not_committed_and_approval_uses_the_original_actor(path):
    store = InMemoryStore({"settings.delivery": {"enabled": False}})
    p = policy()
    if path in ("principal", "handle", "ambient"):
        p = p.with_access(
            AccessRule("writer", keys=["*"], writers=["agent"], readers=["*"]),
            principals={"agent": ()},
            admins=["agent"],
        )
    guard = MemoryGuard(store, policy=p, trace=path == "trace", detectors=[])
    value = {"enabled": True, "channels": ["synthetic"]}
    if path == "principal":
        action = guard.write("settings.delivery", value, principal="agent")
    elif path == "handle":
        action = guard.as_agent("agent").write("settings.delivery", value)
    elif path == "ambient":
        with guard.as_agent("agent"):
            action = guard.write("settings.delivery", value)
    else:
        action = guard.write("settings.delivery", value)
    assert action == Action.REQUIRE_APPROVAL
    (proposal,) = guard.pending_writes
    value["channels"].append("caller-mutated")
    detached = proposal.value
    detached["channels"].append("view-mutated")
    assert proposal.value["channels"] == ["synthetic"]
    assert store.get("settings.delivery") == {"enabled": False}
    reader = guard.as_agent("agent") if path in ("principal", "handle", "ambient") else guard
    assert reader.read("settings.delivery") == {"enabled": False}
    snap = guard.snapshot(principal="agent" if path in ("principal", "handle", "ambient") else None)
    assert snap.data == {"settings.delivery": {"enabled": False}}
    assert "synthetic" not in json.dumps([event.to_dict() for event in guard.events])
    assert "synthetic" not in repr(guard.last_trace())
    assert "synthetic" not in repr(proposal)
    with pytest.raises(dataclasses.FrozenInstanceError):
        proposal.key = "settings.other"
    assert guard.approve(proposal.write_id, digest=proposal.digest) == Action.ALLOW
    assert store.get("settings.delivery") == {"enabled": True, "channels": ["synthetic"]}
    assert guard.written_by("settings.delivery") == proposal.principal
    assert not guard.pending_writes
    with pytest.raises(PendingWriteError):
        guard.approve(proposal.write_id, digest=proposal.digest)


@pytest.mark.parametrize("path", ["legacy", "principal", "handle", "ambient", "trace"])
@pytest.mark.parametrize("action", [Action.REQUIRE_APPROVAL, Action.REQUIRE_CORROBORATION])
def test_gated_reads_cannot_mutate_committed_values_before_or_after_resolution(path, action):
    shared = {"names": ["original"]}
    store = InMemoryStore({"settings.delivery": {"first": shared, "second": shared}})
    # Write gates are sufficient on their own; no access policy is required.
    guard = MemoryGuard(store, policy=policy(action), trace=path == "trace", detectors=[])
    handle = guard.as_agent("agent")

    def read():
        if path == "principal":
            return guard.read("settings.delivery", principal="agent")
        if path == "handle":
            return handle.read("settings.delivery")
        if path == "ambient":
            with handle:
                return guard.read("settings.delivery")
        return guard.read("settings.delivery")

    proposed = {"first": {"names": ["approved"]}, "second": {"names": ["approved"]}}
    assert guard.write("settings.delivery", proposed) == action
    (proposal,) = guard.pending_writes
    original_view = read()
    original_view["first"]["names"].append("unapproved")
    original_view["second"]["names"].append("also-unapproved")
    original = {"first": {"names": ["original"]}, "second": {"names": ["original"]}}
    assert store.get("settings.delivery") == original
    assert read() == original
    assert len(guard.pending_writes) == 1

    if action == Action.REQUIRE_APPROVAL:
        assert guard.approve(proposal.write_id, digest=proposal.digest) == Action.ALLOW
    else:
        assert guard.corroborate(
            proposal.write_id, digest=proposal.digest, source_domain="document:one"
        ) == Action.REQUIRE_CORROBORATION
        assert guard.corroborate(
            proposal.write_id, digest=proposal.digest, source_domain="document:two"
        ) == Action.ALLOW
    committed_view = read()
    committed_view["first"]["names"].append("unapproved")
    committed_view["second"]["names"].append("also-unapproved")
    assert store.get("settings.delivery") == proposed
    assert read() == proposed
    assert not guard.pending_writes


def test_gated_reads_fail_closed_for_preexisting_custom_values_without_changing_ungated_reads():
    class Mutable:
        def __init__(self):
            self.names = []

        def __deepcopy__(self, memo):
            return self

    value = Mutable()
    store = InMemoryStore({"settings.custom": value, "ordinary.custom": value})
    guard = MemoryGuard(store, policy=policy(), detectors=[])
    assert guard.read("ordinary.custom") is value
    with pytest.raises(ValueError, match="finite JSON values"):
        guard.read("settings.custom")
    with pytest.raises(ValueError, match="finite JSON values"):
        guard.as_agent("agent").read("settings.custom")
    assert value.names == []


def test_pending_new_key_is_absent_from_reads_keys_and_snapshots():
    store = InMemoryStore()
    guard = MemoryGuard(store, policy=policy(), detectors=[])
    guard.write("settings.send", "a synthetic private draft")
    assert guard.read("settings.send", "missing") == "missing"
    assert list(store.keys()) == []
    assert guard.snapshot().data == {}
    handle = guard.as_agent("agent")
    for name in ("pending_writes", "approve", "reject", "corroborate", "expire_pending"):
        assert not hasattr(handle, name)


def test_approval_digest_cannot_be_reused_for_another_value_key_or_actor():
    guard = MemoryGuard(policy=policy(), detectors=[])
    guard.write("settings.first", "a", principal="agent1")
    guard.write("settings.first", "b", principal="agent1")
    guard.write("settings.second", "a", principal="agent1")
    guard.write("settings.first", "a", principal="agent2")
    proposals = guard.pending_writes
    assert len({proposal.digest for proposal in proposals}) == 4
    for other in proposals[1:]:
        with pytest.raises(PendingWriteError, match="digest"):
            guard.approve(other.write_id, digest=proposals[0].digest)
    assert len(guard.pending_writes) == 4


def test_reject_and_expiry_never_commit(monkeypatch):
    import agent_memory_guard.guard as guard_module

    now = [1000.0]
    monkeypatch.setattr(guard_module.time, "time", lambda: now[0])
    guard = MemoryGuard(policy=policy(ttl_seconds=10), detectors=[])
    guard.write("settings.a", "a")
    (rejected,) = guard.pending_writes
    guard.reject(rejected.write_id, digest=rejected.digest)
    with pytest.raises(PendingWriteError):
        guard.approve(rejected.write_id, digest=rejected.digest)
    guard.write("settings.b", "b")
    (expired,) = guard.pending_writes
    now[0] = 1010.0
    assert guard.expire_pending() == (expired.write_id,)
    assert guard.read("settings.a") is None
    assert guard.read("settings.b") is None
    assert {event.metadata.get("status") for event in guard.events} >= {"rejected", "expired"}


@pytest.mark.parametrize("action", [Action.REQUIRE_APPROVAL, Action.REQUIRE_CORROBORATION])
def test_copies_and_pickles_do_not_transfer_pending_authority(action):
    guard = MemoryGuard(policy=policy(action), detectors=[])
    guard.write("settings.a", "new")
    (proposal,) = guard.pending_writes
    for duplicate in (copy.copy(guard), copy.deepcopy(guard), pickle.loads(pickle.dumps(guard))):
        assert duplicate.pending_writes == ()
        with pytest.raises(PendingWriteError):
            duplicate.approve(proposal.write_id, digest=proposal.digest)
    assert len(guard.pending_writes) == 1


def test_corroboration_counts_distinct_trusted_domains_not_write_metadata():
    guard = MemoryGuard(policy=policy(Action.REQUIRE_CORROBORATION), detectors=[])
    guard.write("settings.scope", "approved-scope", source_class=SourceClass.SYSTEM)
    (proposal,) = guard.pending_writes
    assert proposal.corroborations == 0
    assert proposal.required_corroborations == 2
    with pytest.raises(PendingWriteError, match="not approval"):
        guard.approve(proposal.write_id, digest=proposal.digest)
    for untrusted in (
        SourceClass.USER_INPUT,
        SourceClass.EXTERNAL_TOOL,
        SourceClass.AGENT_AUTHORED,
    ):
        with pytest.raises(PendingWriteError, match="not trusted"):
            guard.corroborate(
                proposal.write_id,
                digest=proposal.digest,
                source_domain="attacker",
                source_class=untrusted,
            )
    with pytest.raises(ValueError):
        guard.corroborate(
            proposal.write_id,
            digest=proposal.digest,
            source_domain="attacker",
            source_class="pretend-admin",
        )
    for _ in range(3):
        assert (
            guard.corroborate(
                proposal.write_id, digest=proposal.digest, source_domain="document:one"
            )
            == Action.REQUIRE_CORROBORATION
        )
    assert guard.pending_writes[0].corroborations == 1
    assert guard.read(proposal.key) is None
    assert (
        guard.corroborate(proposal.write_id, digest=proposal.digest, source_domain="document:two")
        == Action.ALLOW
    )
    assert guard.read(proposal.key) == "approved-scope"
    with pytest.raises(PendingWriteError):
        guard.corroborate(proposal.write_id, digest=proposal.digest, source_domain="document:three")


def test_trusted_source_configuration_is_explicit_and_validated():
    p = policy(
        Action.REQUIRE_CORROBORATION,
        corroborations=1,
        trusted_source_classes=(SourceClass.EXTERNAL_TOOL,),
    )
    guard = MemoryGuard(policy=p, detectors=[])
    guard.write("settings.scope", "scoped")
    (proposal,) = guard.pending_writes
    with pytest.raises(PendingWriteError):
        guard.corroborate(proposal.write_id, digest=proposal.digest, source_domain="system")
    assert (
        guard.corroborate(
            proposal.write_id,
            digest=proposal.digest,
            source_domain="verified-tool",
            source_class="external_tool",
        )
        == Action.ALLOW
    )


@pytest.mark.parametrize("mutation", ["write", "delete", "retire", "rollback", "promote", "task"])
def test_guard_mutations_invalidate_pending_even_if_value_later_returns(mutation):
    p = policy()
    guard = MemoryGuard(policy=p, detectors=[])
    p = guard.policy  # allow-all compatibility mode may derive an access policy
    # Prepopulate through the guard before enabling this policy's gate.
    p.write_gates = ()
    guard.write("settings.a", "original", cls=MemoryClass.EPHEMERAL)
    snap = guard.snapshot()
    p.write_gates = (gate(),)
    guard.write("settings.a", "new")
    (proposal,) = guard.pending_writes
    if mutation == "write":
        p.write_gates = ()
        guard.write("settings.a", "intermediate")
        guard.write("settings.a", "original")
    elif mutation == "delete":
        guard.delete("settings.a")
    elif mutation == "retire":
        guard.retire_if(lambda key, value: True)
    elif mutation == "rollback":
        guard.rollback(snap.snapshot_id)
    elif mutation == "promote":
        guard.promote("settings.a", MemoryClass.USER_PREFERENCE_CANDIDATE)
    else:
        guard.set_current_task("a-different-task")
    assert guard.pending_writes == ()
    with pytest.raises(PendingWriteError):
        guard.approve(proposal.write_id, digest=proposal.digest)


def test_target_mutation_outside_guard_fails_closed():
    store = InMemoryStore({"settings.a": {"x": [1]}})
    guard = MemoryGuard(store, policy=policy(), detectors=[])
    guard.write("settings.a", {"x": [2]})
    (proposal,) = guard.pending_writes
    store.get("settings.a")["x"].append(3)
    with pytest.raises(PendingWriteError, match="target"):
        guard.approve(proposal.write_id, digest=proposal.digest)
    assert store.get("settings.a") == {"x": [1, 3]}


def test_policy_change_requires_a_new_proposal():
    p = policy()
    guard = MemoryGuard(policy=p, detectors=[])
    guard.write("settings.a", "new")
    (proposal,) = guard.pending_writes
    guard.policy.rules.append(PolicyRule("new-rule", "*", Action.BLOCK))
    with pytest.raises(PendingWriteError, match="policy"):
        guard.approve(proposal.write_id, digest=proposal.digest)
    assert not guard.pending_writes
    assert guard.read("settings.a") is None


def test_access_revocation_never_becomes_approval_of_another_principal():
    p = policy().with_access(
        AccessRule("writer", keys=["*"], writers=["agent"], readers=["*"]),
        principals={"agent": (), "other": ()},
    )
    guard = MemoryGuard(policy=p, detectors=[])
    guard.as_agent("agent").write("settings.a", "new")
    (proposal,) = guard.pending_writes
    guard.policy.access = dataclasses.replace(p.access, rules=(), default="deny")
    with pytest.raises(PendingWriteError):
        guard.approve(proposal.write_id, digest=proposal.digest)
    assert guard._store.get("settings.a") is None


class WriteFinding:
    name = "synthetic"

    def inspect(self, key, value, *, operation):
        return DetectionResult(self.name, operation == "write", Severity.HIGH)


@pytest.mark.parametrize("content_action", [Action.BLOCK, Action.QUARANTINE])
def test_content_denial_takes_precedence_over_a_write_gate(content_action):
    p = policy()
    p.rules.append(PolicyRule("deny", "synthetic", content_action))
    guard = MemoryGuard(policy=p, detectors=[WriteFinding()])
    if content_action == Action.BLOCK:
        with pytest.raises(PolicyViolation):
            guard.write("settings.a", "new")
    else:
        assert guard.write("settings.a", "new") == content_action
    assert guard.pending_writes == ()
    assert guard._store.get("settings.a") is None


def test_resolution_reruns_detectors_without_consuming_a_failed_attempt():
    class ChangedFinding(WriteFinding):
        triggered = False

        def inspect(self, key, value, *, operation):
            return DetectionResult(
                self.name, self.triggered and operation == "write", Severity.HIGH
            )

    detector = ChangedFinding()
    p = policy()
    p.rules.append(PolicyRule("deny", "synthetic", Action.BLOCK))
    guard = MemoryGuard(policy=p, detectors=[detector])
    guard.write("settings.a", "new")
    (proposal,) = guard.pending_writes
    detector.triggered = True
    with pytest.raises(PolicyViolation):
        guard.approve(proposal.write_id, digest=proposal.digest)
    assert guard.pending_writes[0].write_id == proposal.write_id
    assert guard._store.get("settings.a") is None
    detector.triggered = False
    assert guard.approve(proposal.write_id, digest=proposal.digest) == Action.ALLOW


def test_redaction_happens_before_proposal_and_commit():
    p = Policy.strict()
    p.write_gates = (gate(),)
    guard = MemoryGuard(policy=p)
    assert guard.write("settings.a", "api_key=sk-" + "x" * 35) == Action.REQUIRE_APPROVAL
    (proposal,) = guard.pending_writes
    assert "x" * 35 not in str(proposal.value)
    assert guard.approve(proposal.write_id, digest=proposal.digest) in (Action.ALLOW, Action.REDACT)
    assert "x" * 35 not in guard.read("settings.a")


class CountingStore(InMemoryStore):
    def __init__(self):
        super().__init__()
        self.commits = 0

    def set(self, key, value):
        super().set(key, value)
        self.commits += 1


def test_concurrent_approvals_commit_exactly_once():
    store = CountingStore()
    guard = MemoryGuard(store, policy=policy(), detectors=[])
    guard.write("settings.a", "new")
    (proposal,) = guard.pending_writes
    barrier = threading.Barrier(2)

    def resolve():
        barrier.wait(timeout=5)
        try:
            return guard.approve(proposal.write_id, digest=proposal.digest)
        except PendingWriteError:
            return "already-resolved"

    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda _: resolve(), range(2)))
    assert sorted(str(result) for result in results) == ["Action.ALLOW", "already-resolved"]
    assert store.commits == 1


def test_legacy_delete_cannot_interleave_between_resolution_check_and_commit():
    entered = threading.Event()
    release = threading.Event()

    class SlowStore(CountingStore):
        def set(self, key, value):
            entered.set()
            assert release.wait(timeout=5)
            super().set(key, value)

    store = SlowStore()
    guard = MemoryGuard(store, policy=policy(), detectors=[])
    guard.write("settings.a", "new")
    (proposal,) = guard.pending_writes
    with ThreadPoolExecutor(2) as pool:
        approval = pool.submit(guard.approve, proposal.write_id, digest=proposal.digest)
        assert entered.wait(timeout=5)
        deletion = pool.submit(guard.delete, "settings.a")
        assert not deletion.done()
        release.set()
        assert approval.result(timeout=5) == Action.ALLOW
        deletion.result(timeout=5)
    assert store.get("settings.a") is None
    assert store.commits == 1


def test_resolution_from_an_event_handler_cannot_reenter_a_write():
    attempts = []
    guard = MemoryGuard(policy=policy(), detectors=[])

    def resolve_inline(event):
        if event.detector == "write_gate" and event.metadata["status"] == "pending":
            proposal = guard.pending_writes[0]
            try:
                guard.approve(proposal.write_id, digest=proposal.digest)
            except PendingWriteError:
                attempts.append("deferred")

    guard.add_event_handler(resolve_inline)
    assert guard.write("settings.a", "new") == Action.REQUIRE_APPROVAL
    assert attempts == ["deferred"]
    assert guard.read("settings.a") is None
    (proposal,) = guard.pending_writes
    assert guard.approve(proposal.write_id, digest=proposal.digest) == Action.ALLOW


@pytest.mark.parametrize("value", [float("nan"), float("inf"), {1: "value"}, (1, 2), object()])
def test_unsupported_gated_values_fail_without_committing(value):
    guard = MemoryGuard(policy=policy(), detectors=[])
    with pytest.raises(ValueError):
        guard.write("settings.a", value)
    assert guard.pending_writes == ()
    assert guard._store.get("settings.a") is None


def test_pending_capacity_is_bounded_and_explicit():
    guard = MemoryGuard(policy=policy(), detectors=[], max_pending_writes=1)
    guard.write("settings.a", "one")
    with pytest.raises(PendingWriteError, match="capacity"):
        guard.write("settings.b", "two")
    (proposal,) = guard.pending_writes
    guard.reject(proposal.write_id, digest=proposal.digest)
    assert guard.write("settings.b", "two") == Action.REQUIRE_APPROVAL


def test_yaml_write_gates_are_separate_from_read_content_rules():
    p = load_policy("""
write_gates:
  - name: approve_settings
    keys: settings.*
    action: require_approval
  - name: verify_scope
    keys: scope.*
    action: require_corroboration
    corroborations: 3
    trusted_source_classes: [system]
    ttl_seconds: 60
""")
    guard = MemoryGuard(policy=p, detectors=[])
    assert guard.write("settings.a", "new") == Action.REQUIRE_APPROVAL
    assert guard.write("scope.a", "new") == Action.REQUIRE_CORROBORATION
    assert guard.read("settings.a", "missing") == "missing"
    assert p.write_gate("other") is None
    assert guard.write("other", "normal") == Action.ALLOW


@pytest.mark.parametrize(
    "document",
    [
        {"default_action": "require_approval"},
        {"rules": [{"name": "r", "action": "require_corroboration"}]},
        {"write_gates": [{"name": "r", "keys": "*", "action": "allow"}]},
        {"write_gates": [{"name": "r", "keys": "*", "corroborations": True}]},
        {"write_gates": [{"name": "r", "keys": "*", "ttl_seconds": float("nan")}]},
        {"write_gates": [{"name": "r", "keys": "*", "trusted_source_classes": ["not-trusted"]}]},
        {"write_gates": [{"name": "r", "keys": "*", "corroboratons": 2}]},
    ],
)
def test_invalid_gate_policy_fails_closed(document):
    with pytest.raises((ValueError, TypeError)):
        load_policy(document)


def test_new_actions_are_rejected_in_programmatic_content_policy():
    with pytest.raises(ValueError, match="write_gates"):
        Policy(default_action=Action.REQUIRE_APPROVAL)
    with pytest.raises(ValueError, match="write_gates"):
        PolicyRule("r", "*", Action.REQUIRE_CORROBORATION)


def test_host_ambient_identity_does_not_replace_the_original_anonymous_writer():
    guard = MemoryGuard(policy=policy(), detectors=[])
    guard.write("settings.a", "new")
    (proposal,) = guard.pending_writes
    with guard.as_agent("host-context"):
        assert guard.approve(proposal.write_id, digest=proposal.digest) == Action.ALLOW
    assert guard.written_by("settings.a") is None


def test_corroboration_event_cannot_reenter_and_commit_twice():
    store = CountingStore()
    guard = MemoryGuard(store, policy=policy(Action.REQUIRE_CORROBORATION), detectors=[])
    deferred = []

    def inline_vote(event):
        if event.detector == "write_gate" and event.metadata["status"] == "corroborated":
            proposal = guard.pending_writes[0]
            try:
                guard.corroborate(proposal.write_id, digest=proposal.digest, source_domain="inline")
            except PendingWriteError:
                deferred.append(True)

    guard.add_event_handler(inline_vote)
    guard.write("settings.a", "new")
    (proposal,) = guard.pending_writes
    assert (
        guard.corroborate(proposal.write_id, digest=proposal.digest, source_domain="first")
        == Action.REQUIRE_CORROBORATION
    )
    assert (
        guard.corroborate(proposal.write_id, digest=proposal.digest, source_domain="second")
        == Action.ALLOW
    )
    assert deferred == [True, True]
    assert store.commits == 1


def test_expiry_is_checked_again_after_slow_revalidation(monkeypatch):
    import agent_memory_guard.guard as guard_module

    now = [1000.0]
    monkeypatch.setattr(guard_module.time, "time", lambda: now[0])

    class SlowDetector(WriteFinding):
        slow = False

        def inspect(self, key, value, *, operation):
            if self.slow:
                now[0] += 11
            return DetectionResult(self.name, False)

    detector = SlowDetector()
    guard = MemoryGuard(policy=policy(ttl_seconds=10), detectors=[detector])
    guard.write("settings.a", "new")
    (proposal,) = guard.pending_writes
    detector.slow = True
    with pytest.raises(PendingWriteError, match="expired"):
        guard.approve(proposal.write_id, digest=proposal.digest)
    assert guard._store.get("settings.a") is None
    assert guard.pending_writes == ()


def test_failed_backend_write_does_not_consume_approval():
    class FailingStore(CountingStore):
        fail = True

        def set(self, key, value):
            if self.fail:
                raise OSError("synthetic failure before write")
            super().set(key, value)

    store = FailingStore()
    guard = MemoryGuard(store, policy=policy(), detectors=[])
    guard.write("settings.a", "new")
    (proposal,) = guard.pending_writes
    with pytest.raises(OSError):
        guard.approve(proposal.write_id, digest=proposal.digest)
    assert guard.pending_writes[0].write_id == proposal.write_id
    store.fail = False
    assert guard.approve(proposal.write_id, digest=proposal.digest) == Action.ALLOW
    assert store.commits == 1


@pytest.mark.parametrize("action", [Action.REQUIRE_APPROVAL, Action.REQUIRE_CORROBORATION])
def test_rest_write_reports_pending_without_storing_or_exposing_payload(action, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    import agent_memory_guard.server as server

    guard = MemoryGuard(policy=policy(action), detectors=[])
    monkeypatch.setattr(server, "_guard", guard)
    response = TestClient(server.app).post(
        "/write",
        json={
            "key": "settings.a",
            "value": "synthetic-unapproved-content",
        },
    )
    assert response.status_code == 200
    assert response.json()["stored"] is False
    assert response.json()["action"] == action.value
    assert "synthetic-unapproved-content" not in response.text
    assert guard.read("settings.a") is None
