"""Differential and regression coverage for the unified access-policy evaluator.

The reference implementation below is intentionally copied from the pre-refactor
algorithm rather than calling ``allows`` or ``decide``. This keeps the test useful
against accidental changes to the new evaluator itself.
"""
from __future__ import annotations

import random
import re

import pytest

from agent_memory_guard import (
    AccessDenied,
    AccessPolicy,
    AccessRule,
    MemoryClass,
    MemoryGuard,
    Policy,
    TraceStep,
)
from agent_memory_guard.policies.access import OPERATIONS, AccessDecision
from agent_memory_guard.storage import InMemoryStore

PRINCIPALS = ("alice", "bob", "carol", "ops")
ROLES = ("reader", "writer", "admin")
OPS = ("read", "write", "delete", "promote", "snapshot", "rollback", "retire")
KEYS = ("notes.alice.x", "notes.bob.x", "team.x", "misc.x", "data.carol.y")
CLASSES = (None, *MemoryClass)
_NO_ADMINS = (
    "the policy names no admins (pass admins=[...] with agent ids or roles, or "
    "'<anonymous>' for code that uses the guard without an agent identity)"
)


def reference_decide(
    policy: AccessPolicy,
    principal: str | None,
    operation: str,
    key: str,
    *,
    current_class: MemoryClass | None = None,
    target_class: MemoryClass | None = None,
    via: str = "explicit",
    all_rules: bool = True,
) -> AccessDecision:
    """The pre-refactor ``AccessPolicy.decide`` algorithm, kept independent."""
    if operation not in OPERATIONS:
        raise ValueError(f"Unknown operation {operation!r}; expected one of {sorted(OPERATIONS)}")
    steps: list[TraceStep] = []
    who = principal or "<anonymous>"

    def done(
        ok: bool,
        stage: str,
        why: str,
        rule: str | None = None,
        pattern: str | None = None,
        owner: str | None = None,
    ) -> AccessDecision:
        return AccessDecision(
            ok, operation, key, principal, via, rule, pattern, owner, why, stage, tuple(steps)
        )

    registry = policy._registry
    if principal is not None and registry and principal not in registry:
        steps.append(TraceStep("registry", f"{principal!r} is not declared", "unknown"))
        return done(False, "registry", f"unknown principal {principal!r}")
    roles = registry.get(principal, frozenset()) if principal is not None else frozenset()
    if principal is not None and registry:
        steps.append(TraceStep("registry", f"{principal} roles={sorted(roles)}", "declared"))

    if operation in {"snapshot", "rollback", "retire"}:
        selectors = policy._admin_sel
        allowed_by = policy._describe(selectors)
        allowed = any(s.matches(principal, roles, None) for s in selectors)
        steps.append(TraceStep("admin", f"admins {allowed_by}", "match" if allowed else "no match"))
        if not selectors:
            return done(False, "admin", f"nobody may {operation}: {_NO_ADMINS}")
        if allowed:
            return done(True, "admin", f"{who} is one of admins {allowed_by}")
        return done(False, "admin", f"{operation} requires one of admins {allowed_by}")

    writes = operation in {"write", "delete", "promote"}
    list_name = "writers" if writes else "readers"
    rule_result = None
    for rule in policy.rules:
        hit = rule.match(key)
        if hit is None:
            if all_rules:
                steps.append(TraceStep("rule", f"{rule.name} keys={list(rule.keys)}", "no match"))
            continue
        pattern, owner = hit
        selectors = rule._writers if writes else rule._readers
        raw = list(rule.writers if writes else rule.readers)
        bound = f" (owner={owner})" if owner is not None else ""
        steps.append(
            TraceStep("rule", f"{rule.name} keys={list(rule.keys)}", f"match {pattern!r}{bound}")
        )
        allowed = any(s.matches(principal, roles, owner) for s in selectors)
        steps.append(TraceStep(list_name, str(raw), "match" if allowed else "no match"))
        if allowed:
            rule_result = (True, "rule", f"{who} is in {list_name} of {rule.name!r}", rule.name, pattern, owner)
        else:
            why = f"{who} is not in {list_name} {raw} of {rule.name!r}"
            if owner is not None and not _valid_id(owner):
                why += f" ({owner!r} is not a valid agent id, so no agent owns it)"
            rule_result = (False, "rule", why, rule.name, pattern, owner)
        break
    else:
        allowed = policy.default == "allow"
        steps.append(TraceStep("default", f"no access rule matches {key!r}", policy.default))
        why = f"no access rule covers {key!r}; default {policy.default}"
        rule_result = (allowed, "default", why if allowed else why + " (add an AccessRule for it)", None, None, None)

    allowed, stage, why, rule, pattern, owner = rule_result
    if not allowed or not writes:
        return done(allowed, stage, why, rule, pattern, owner)

    for cls in dict.fromkeys(c for c in (current_class, target_class) if c is not None):
        selectors = policy._class_sel.get(cls)
        if selectors is None:
            continue
        allowed_by = policy._describe(selectors)
        class_allowed = any(s.matches(principal, roles, None) for s in selectors)
        steps.append(
            TraceStep("class", f"{cls.value} writers {allowed_by}", "match" if class_allowed else "no match")
        )
        if not class_allowed:
            if not selectors:
                why = (
                    f"{who} may not {operation} class {cls.value}: nobody may change it, "
                    f"because {_NO_ADMINS} and class_writers names nobody for it"
                )
            else:
                why = f"{who} may not {operation} class {cls.value} (class_writers {allowed_by})"
            return done(False, "class", why, f"class_writers[{cls.value}]", None, owner)
    return done(allowed, stage, why, rule, pattern, owner)


def _valid_id(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,63}", value))


def generated_policy(rng: random.Random) -> AccessPolicy:
    registry = {
        pid: tuple(rng.sample(ROLES, rng.randrange(0, len(ROLES) + 1)))
        for pid in PRINCIPALS
    }
    selectors = ["*", "{owner}", "role:reader", "role:writer", "alice", "bob"]
    rules = []
    for i in range(rng.randrange(0, 5)):
        def pick() -> list[str]:
            return rng.sample(selectors, rng.randrange(0, 3))

        writers, readers = pick(), pick()
        pool = ("notes.{owner}.x", "data.{owner}.*") if "{owner}" in writers + readers else ("team.*", "misc.*")
        patterns = rng.sample(pool, rng.randrange(1, len(pool) + 1))
        rules.append(AccessRule(f"rule-{i}", patterns, writers, readers))
    return AccessPolicy(
        rules=rules,
        default=rng.choice(("allow", "deny")),
        admins=rng.sample(("alice", "bob", "role:admin"), rng.randrange(0, 3)),
        principals=registry,
        class_writers={
            MemoryClass.POLICY: rng.sample(("*", "alice", "role:admin"), rng.randrange(0, 3)),
            MemoryClass.VERIFIED_PREFERENCE: rng.sample(
                ("*", "bob", "role:writer"), rng.randrange(0, 3)
            ),
        },
    )


@pytest.mark.parametrize("seed", [7, 23, 101, 404])
def test_generated_policies_match_independent_pre_refactor_oracle(seed: int) -> None:
    rng = random.Random(seed)
    checked = 0
    for _ in range(125):
        policy = generated_policy(rng)
        for _ in range(25):
            principal = rng.choice((*PRINCIPALS, "ghost", None))
            operation = rng.choice(OPS)
            key = rng.choice(KEYS)
            current = rng.choice(CLASSES)
            target = rng.choice(CLASSES)
            via = rng.choice(("explicit", "handle"))
            all_rules = rng.choice((True, False))
            expected = reference_decide(
                policy, principal, operation, key, current_class=current, target_class=target,
                via=via, all_rules=all_rules,
            )
            assert policy.allows(
                principal, operation, key, current_class=current, target_class=target
            ) is expected.allowed
            actual = policy.decide(
                principal, operation, key, current_class=current, target_class=target,
                via=via, all_rules=all_rules,
            )
            assert actual == expected
            checked += 1
    assert checked == 3_125


@pytest.mark.parametrize("operation", ["invalid", "READ", "", "snapshot-now"])
def test_allows_and_decide_preserve_invalid_operation_errors(operation: str) -> None:
    policy = generated_policy(random.Random(11))
    with pytest.raises(ValueError, match="Unknown operation") as allows_error:
        policy.allows("alice", operation, "team.x")
    with pytest.raises(ValueError, match="Unknown operation") as decide_error:
        policy.decide("alice", operation, "team.x")
    assert str(allows_error.value) == str(decide_error.value)


@pytest.mark.parametrize(
    ("principal", "operation", "key", "current", "target", "all_rules"),
    [
        ("ghost", "read", "team.x", None, None, True),
        (None, "read", "team.x", None, None, True),
        ("bob", "read", "notes.alice.x", None, None, False),
        ("bob", "write", "team.x", MemoryClass.POLICY, None, True),
        ("alice", "write", "unknown.x", None, None, True),
        ("bob", "snapshot", "*", None, None, True),
    ],
)
def test_decision_matches_reference_for_each_edge_case(
    principal, operation, key, current, target, all_rules
) -> None:
    policy = AccessPolicy(
        rules=(
            AccessRule("first", ("team.*",), ("alice",), ("alice",)),
            AccessRule("second", ("team.*",), ("*",), ("*",)),
            AccessRule("private", ("notes.{owner}.*",), ("{owner}",), ("{owner}",)),
        ),
        default="deny",
        admins=("alice",),
        principals={"alice": ("admin",), "bob": ("reader",)},
        class_writers={MemoryClass.POLICY: ("alice",)},
    )
    expected = reference_decide(
        policy, principal, operation, key, current_class=current, target_class=target,
        via="handle", all_rules=all_rules,
    )
    actual = policy.decide(
        principal, operation, key, current_class=current, target_class=target,
        via="handle", all_rules=all_rules,
    )
    assert actual == expected


def test_memory_guard_trace_on_and_off_have_same_enforcement_contract() -> None:
    policy = AccessPolicy(
        rules=(AccessRule("private", ("notes.{owner}.*",), ("{owner}",), ("{owner}",)),),
        default="deny",
        admins=("alice",),
        principals={"alice": (), "bob": ()},
    )
    results = []
    for trace in (False, True):
        store = InMemoryStore()
        guard = MemoryGuard(store, policy=Policy.strict().with_access(
            *policy.rules, default=policy.default, admins=policy.admins, principals=policy.principals
        ), trace=trace)
        guard.as_agent("alice").write("notes.alice.x", "safe")
        before = dict(store.items()) if hasattr(store, "items") else {k: store.get(k) for k in store.keys()}
        with pytest.raises(AccessDenied) as exc:
            guard.as_agent("bob").write("notes.alice.x", "blocked")
        results.append((type(exc.value), str(exc.value), dict(store.items()) if hasattr(store, "items") else {k: store.get(k) for k in store.keys()}, guard.last_trace()))
        assert results[-1][2] == before
        if trace:
            assert guard.last_trace() is not None
            assert [step.stage for step in guard.last_trace()] == [
                "identity", "operation", "registry", "rule", "writers", "access",
                "skipped", "event", "result",
            ]
        else:
            assert guard.last_trace() is None
    assert results[0][:3] == results[1][:3]


def test_denied_reads_do_not_disclose_existence_with_or_without_trace() -> None:
    policy = Policy.strict().with_access(
        AccessRule("private", ("private.*",), ("alice",), ("alice",)),
        default="deny", admins=("alice",), principals={"alice": (), "bob": ()},
    )
    for trace in (False, True):
        guard = MemoryGuard(policy=policy, trace=trace)
        guard.as_agent("alice").write("private.exists", "secret")
        existing = guard.as_agent("bob").explain("read", "private.exists")
        missing = guard.as_agent("bob").explain("read", "private.missing")
        assert existing.key != missing.key
        assert existing.operation == missing.operation
        assert existing.allowed == missing.allowed
        assert existing.principal == missing.principal
        assert existing.via == missing.via
        assert existing.rule == missing.rule
        assert existing.pattern == missing.pattern
        assert existing.owner == missing.owner
        assert existing.reason == missing.reason
        assert existing.stage == missing.stage
        assert existing.steps == missing.steps
        assert existing.allowed is False
        assert "secret" not in existing.explain()
