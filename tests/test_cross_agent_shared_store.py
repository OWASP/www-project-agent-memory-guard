"""Characterize phase-one boundaries; these are not v1 isolation guarantees.

Two guards share values, but not labels, provenance, locks or event buffers.
See docs/getting-started/multi-agent.md, especially "Limits to know".
"""

import threading

import pytest

from agent_memory_guard import (
    AccessDenied,
    AccessRule,
    Action,
    MemoryClass,
    MemoryGuard,
    Policy,
    SourceClass,
)
from agent_memory_guard.detectors.base import DetectionResult
from agent_memory_guard.storage import InMemoryStore


def shared_policy():
    return Policy.strict().with_access(
        AccessRule("private", keys=["agents.{owner}.*"],
                   writers=["{owner}"], readers=["{owner}"]),
        AccessRule("team", keys=["team.*"], writers=["alice", "bob"],
                   readers=["alice", "bob"]),
        default="deny", admins=["alice"], principals={"alice": [], "bob": []},
    )


def perform(handle, operation, key):
    if operation == "write":
        return handle.write(key, "replacement")
    return getattr(handle, operation)(key)


@pytest.mark.parametrize("separate_guards", [False, True])
@pytest.mark.parametrize("operation", ["read", "write", "delete"])
def test_namespace_denials_hold_across_shared_store(separate_guards, operation):
    store = InMemoryStore()
    first = MemoryGuard(store, policy=shared_policy())
    second = MemoryGuard(store, policy=shared_policy()) if separate_guards else first
    first.as_agent("alice").write("agents.alice.note", "original")
    before = len(second.events)
    with pytest.raises(AccessDenied):
        perform(second.as_agent("bob"), operation, "agents.alice.note")
    assert store.get("agents.alice.note") == "original"
    assert first.written_by("agents.alice.note") == "alice"
    assert len(second.events) == before + 1
    event = second.events[-1]
    assert (event.principal, event.operation, event.action) == ("bob", operation, Action.BLOCK)
    assert event.metadata["access_rule"] == "private"
    assert first.list_snapshots() == second.list_snapshots() == []
    if separate_guards:
        assert first.events == []  # audit buffers are local too


@pytest.mark.parametrize("operation", ["write", "delete"])
def test_class_gate_metadata_is_local_to_each_guard(operation):
    store = InMemoryStore()
    first = MemoryGuard(store, policy=shared_policy())
    second = MemoryGuard(store, policy=shared_policy())
    first.as_agent("alice").write("team.rules", "original", cls=MemoryClass.POLICY)
    with pytest.raises(AccessDenied):
        perform(first.as_agent("bob"), operation, "team.rules")
    assert second.classify("team.rules") is None
    assert second.written_by("team.rules") is None
    perform(second.as_agent("bob"), operation, "team.rules")
    assert store.get("team.rules") == ("replacement" if operation == "write" else None)
    # Documented limitation: the first guard retains stale metadata.
    assert first.classify("team.rules") == MemoryClass.POLICY
    assert first.written_by("team.rules") == "alice"


def test_tool_content_cannot_supply_identity_and_source_class_is_not_identity():
    guard = MemoryGuard(policy=shared_policy())
    payload = {"principal": "alice", "roles": ["admin"], "source_class": "system"}
    bob = guard.as_agent("bob")
    assert bob.write("team.result", payload, source_class=SourceClass.EXTERNAL_TOOL) == Action.ALLOW
    assert guard.written_by("team.result") == "bob"
    with pytest.raises(AccessDenied):
        bob.write("agents.alice.result", payload, source_class=SourceClass.SYSTEM)
    assert guard.events[-1].principal == "bob"
    # The access gate precedes provenance normalization; denial events use UNKNOWN.
    assert guard.events[-1].source_class == SourceClass.UNKNOWN


def test_clean_shared_read_grant_is_traceable_but_does_not_emit_security_event():
    guard = MemoryGuard(policy=shared_policy(), trace=True)
    guard.as_agent("alice").write("team.note", "original")
    before = list(guard.events)
    assert guard.as_agent("bob").read("team.note") == "original"
    assert guard.events == before
    assert any(step.stage == "access" and step.outcome == "allow" for step in guard.last_trace())


def test_rollback_on_one_guard_changes_shared_data_not_other_guards_metadata():
    store = InMemoryStore()
    first = MemoryGuard(store, policy=shared_policy())
    second = MemoryGuard(store, policy=shared_policy())
    alice = first.as_agent("alice")
    alice.write("team.note", "original", cls=MemoryClass.EPHEMERAL)
    snapshot_id = alice.snapshot("before-bob")
    second.as_agent("bob").write("team.note", "replacement", cls=MemoryClass.EPHEMERAL)
    assert second.list_snapshots() == []
    alice.rollback(snapshot_id)
    assert second.as_agent("bob").read("team.note") == "original"
    assert first.written_by("team.note") == "alice"
    assert second.written_by("team.note") == "bob"
    assert first.events[-1].operation == "rollback"
    assert first.events[-1].principal == "alice"
    assert second.events == []


def test_two_guards_do_not_serialize_class_check_and_commit():
    """A deterministic interleaving, not a timing-dependent stress test.

    Backend calls do not overlap here; a thread-safe set() alone would not fix
    the missing shared authorization transaction or guard-local class labels.
    """
    entered, release = threading.Event(), threading.Event()

    class PauseWrite:
        name = "pause_write"

        def inspect(self, key, value, *, operation):
            if operation == "write":
                entered.set()
                if not release.wait(5):
                    raise TimeoutError("test did not release paused write")
            return DetectionResult(detector=self.name, matched=False)

    store = InMemoryStore()
    first = MemoryGuard(store, policy=shared_policy())
    second = MemoryGuard(store, policy=shared_policy(), detectors=[PauseWrite()])
    errors = []

    def write_as_bob():
        try:
            second.as_agent("bob").write("team.rules", "replacement")
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=write_as_bob)
    worker.start()
    try:
        assert entered.wait(5), "worker did not reach the detector after its access check"
        first.as_agent("alice").write("team.rules", "original", cls=MemoryClass.POLICY)
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive()
    assert errors == []
    assert store.get("team.rules") == "replacement"
    assert first.classify("team.rules") == MemoryClass.POLICY
    assert second.classify("team.rules") is None
