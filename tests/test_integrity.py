import pytest

from agent_memory_guard.exceptions import IntegrityError
from agent_memory_guard.integrity import IntegrityRegistry, hash_value


def test_hash_is_stable_across_dict_ordering():
    a = {"role": "admin", "user": "alice"}
    b = {"user": "alice", "role": "admin"}
    assert hash_value(a) == hash_value(b)


def test_hash_changes_when_value_changes():
    assert hash_value({"role": "user"}) != hash_value({"role": "admin"})


def test_registry_verifies_match():
    reg = IntegrityRegistry()
    reg.baseline("identity.role", "user")
    reg.verify("identity.role", "user")  # no raise


def test_registry_raises_on_drift():
    reg = IntegrityRegistry()
    reg.baseline("identity.role", "user")
    with pytest.raises(IntegrityError) as info:
        reg.verify("identity.role", "admin")
    assert info.value.key == "identity.role"
    assert info.value.expected != info.value.actual


def test_verify_without_baseline_is_noop():
    reg = IntegrityRegistry()
    reg.verify("missing", "anything")  # no raise
