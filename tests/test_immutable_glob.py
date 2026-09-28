"""`immutable_keys` is documented as glob patterns and must behave as such.

`merge_protected_keys` folds `immutable_keys` into the protected set, which is
fnmatch-matched, so a declaration like `identity.*` blocks deletes and looks to an
operator like it took effect. The integrity baseline used to match the same tuple
exactly, so no baseline was created and tampering went undetected.
"""

import pytest

from agent_memory_guard import MemoryGuard, Policy
from agent_memory_guard.exceptions import IntegrityError, PolicyViolation

KEY, TRUSTED, TAMPERED = "identity.role", "user", "superadmin"


@pytest.mark.parametrize("immutable", [(KEY,), ("identity.*",), ("identity.rol?",)])
def test_tampering_detected_for_exact_and_glob_declarations(immutable):
    guard = MemoryGuard(policy=Policy(immutable_keys=immutable))
    guard.write(KEY, TRUSTED, source_class="system")
    guard.write(KEY, TAMPERED, source_class="user_input")

    assert guard.verify_all() == [KEY]
    with pytest.raises(IntegrityError):
        guard.read(KEY)


@pytest.mark.parametrize("immutable", [(KEY,), ("identity.*",)])
def test_delete_blocked_for_exact_and_glob_declarations(immutable):
    guard = MemoryGuard(policy=Policy(immutable_keys=immutable))
    guard.write(KEY, TRUSTED, source_class="system")
    with pytest.raises(PolicyViolation):
        guard.delete(KEY)


def test_non_matching_key_is_not_baselined():
    guard = MemoryGuard(policy=Policy(immutable_keys=("identity.*",)))
    guard.write("session.notes", "a", source_class="user_input")
    guard.write("session.notes", "b", source_class="user_input")
    assert guard.verify_all() == []


def test_policy_is_immutable_matches_glob_case_sensitively():
    policy = Policy(immutable_keys=("identity.*",))
    assert policy.is_immutable("identity.role")
    assert not policy.is_immutable("IDENTITY.role")
    assert not policy.is_immutable("session.notes")
