"""Per-agent access control: who may read and write which keys.

An :class:`AccessPolicy` is a list of :class:`AccessRule` objects plus a few
settings. The guard checks it as a hard gate *before* any detector runs, before
the existence check on read, and before the store is touched. A denial raises
:class:`~agent_memory_guard.exceptions.AccessDenied`, which is a
``PolicyViolation``, so code that already catches ``PolicyViolation`` keeps
working.

Example:
    >>> from agent_memory_guard import AccessRule, MemoryGuard, Policy
    >>> policy = Policy.strict().with_access(
    ...     AccessRule("plan", keys=["plan.*"], writers=["supervisor"], readers=["*"]),
    ...     default="allow",
    ...     admins=["supervisor"],
    ... )
    >>> guard = MemoryGuard(policy=policy)
    >>> guard.as_agent("supervisor").write("plan.step1", "collect Q3 numbers")
    <Action.ALLOW: 'allow'>

The decision runs in a fixed order, and every stage must pass:

1. **registry**: with a ``principals`` registry declared, an undeclared id is denied;
2. **admin**: ``rollback``, ``retire`` and ``snapshot`` need one of ``admins``;
3. **rule**: the first rule whose ``keys`` match decides, using ``writers`` for
   write, delete and promote and ``readers`` for read;
4. **default**: keys no rule covers get ``default`` (``"allow"`` or ``"deny"``);
5. **class**: writing, deleting or promoting into or out of a gated class (POLICY
   and VERIFIED_PREFERENCE by default) needs ``class_writers``.

The class gate runs after the key rules, so an agent that may not touch a key
learns nothing about its label. When ``admins`` is empty, admin operations and
the default class gate are open only to anonymous callers (code that uses the
guard directly, as in 0.3); agents are refused.
"""
from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from agent_memory_guard.classification import MemoryClass
from agent_memory_guard.identity import check_id, is_valid_id
from agent_memory_guard.trace import TraceStep

OWNER = "{owner}"
_GLOB_CHARS = re.compile(r"[*?\[]")

READ_OPS = frozenset({"read"})
WRITE_OPS = frozenset({"write", "delete", "promote"})
ADMIN_OPS = frozenset({"rollback", "retire", "snapshot"})
OPERATIONS = READ_OPS | WRITE_OPS | ADMIN_OPS
_GATED_BY_DEFAULT = (MemoryClass.POLICY, MemoryClass.VERIFIED_PREFERENCE)
_NO_ROLES: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Selector:
    """Who a writers/readers/admins entry matches.

    ``"*"`` matches anyone, including anonymous callers; ``"<id>"`` one agent;
    ``"role:<name>"`` every agent the registry gives that role; ``"{owner}"`` the
    agent named by the key's ``{owner}`` segment.
    """

    raw: str
    kind: str  # "any" | "id" | "role" | "owner" | "anonymous" (internal)
    value: str | None = None

    @classmethod
    def parse(cls, raw: Any) -> Selector:
        if not isinstance(raw, str):
            raise TypeError(f"Selector must be a str, not {type(raw).__name__}: {raw!r}")
        text = raw.strip()
        if text == "*":
            return cls(text, "any")
        if text == OWNER:
            return cls(text, "owner")
        if text.startswith("role:"):
            role = text[5:]
            if not is_valid_id(role):
                raise ValueError(f"Bad role name in selector {raw!r}")
            return cls(text, "role", role)
        if not is_valid_id(text):
            raise ValueError(
                f"Bad selector {raw!r}: expected '*', an agent id, 'role:<name>' or '{OWNER}'"
            )
        return cls(text, "id", text)

    def matches(self, pid: str | None, roles: frozenset[str], owner: str | None) -> bool:
        if self.kind == "any":
            return True
        if self.kind == "anonymous":
            return pid is None
        if pid is None:  # an anonymous caller only ever matches "*"
            return False
        if self.kind == "id":
            return pid == self.value
        if self.kind == "role":
            return self.value in roles
        return owner is not None and pid == owner


def _selectors(raw: Iterable[str] | str, where: str) -> tuple[Selector, ...]:
    if isinstance(raw, str):
        raw = (raw,)
    try:
        return tuple(Selector.parse(r) for r in raw)
    except (TypeError, ValueError) as exc:
        raise type(exc)(f"{where}: {exc}") from None


def _strip_fnmatch(pattern: str) -> str:
    """Return the body of ``fnmatch.translate(pattern)`` without its wrapper.

    The wrapper is ``(?s:...)\\Z`` up to Python 3.13 and ``(?s:...)\\z`` from 3.14.
    """
    translated = fnmatch.translate(pattern)
    m = re.fullmatch(r"\(\?s:(.*)\)\\[Zz]", translated, re.DOTALL)
    if m is None:  # pragma: no cover - a future fnmatch change
        raise RuntimeError(f"Unexpected fnmatch.translate output: {translated!r}")
    return m.group(1)


def _compile_key(pattern: str, rule: str) -> tuple[str, re.Pattern[str], bool]:
    """Compile one key glob. Returns (literal prefix, regex, binds_owner).

    Globs mean the same as ``PolicyRule.keys`` (``*`` also crosses dots).
    ``{owner}`` stands for exactly one key segment: whatever is between two dots.
    """
    count = pattern.count(OWNER)
    if count == 0:
        prefix = _GLOB_CHARS.split(pattern, maxsplit=1)[0]
        return prefix, re.compile(r"(?s:" + _strip_fnmatch(pattern) + r")\Z"), False
    if count > 1:
        raise ValueError(f"Access rule {rule!r}: key {pattern!r} has more than one {OWNER}")
    left, right = pattern.split(OWNER)
    if not left:
        raise ValueError(
            f"Access rule {rule!r}: key {pattern!r} starts with {OWNER}; put a literal "
            f"prefix before it, e.g. 'agents.{OWNER}.*'"
        )
    if _GLOB_CHARS.search(left) or "{" in left or "}" in left:
        raise ValueError(
            f"Access rule {rule!r}: key {pattern!r} has a wildcard before {OWNER}; "
            f"everything before {OWNER} must be literal, e.g. 'agents.{OWNER}.*'"
        )
    if not left.endswith(".") or (right and not right.startswith(".")):
        raise ValueError(
            f"Access rule {rule!r}: {OWNER} in {pattern!r} must be a whole key segment, "
            f"e.g. 'agents.{OWNER}.*'"
        )
    body = re.escape(left) + r"(?P<owner>[^.]+)" + (_strip_fnmatch(right) if right else "")
    return left, re.compile(r"(?s:" + body + r")\Z"), True


@dataclass(frozen=True)
class AccessRule:
    """Who may write (and delete and promote) and who may read keys matching ``keys``.

    Args:
        name: Rule name, shown in events, errors and traces.
        keys: Key globs. ``{owner}`` binds one key segment to the agent that owns it.
        writers: Selectors allowed to write, delete and promote. Required; ``()``
            means nobody.
        readers: Selectors allowed to read. Required; ``()`` means nobody.

    Rules are first-match: the first rule whose ``keys`` match a key decides.
    """

    name: str
    keys: Sequence[str]
    writers: Sequence[str]
    readers: Sequence[str]
    # Compiled in __post_init__.
    _compiled: tuple[tuple[str, re.Pattern[str], bool, str], ...] = field(
        init=False, repr=False, compare=False
    )
    _writers: tuple[Selector, ...] = field(init=False, repr=False, compare=False)
    _readers: tuple[Selector, ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("Access rule needs a non-empty name")
        for attr in ("keys", "writers", "readers"):
            value = getattr(self, attr)
            object.__setattr__(self, attr, (value,) if isinstance(value, str) else tuple(value))
        if not self.keys:
            raise ValueError(f"Access rule {self.name!r} needs at least one key pattern")
        compiled = tuple((*_compile_key(k, self.name), k) for k in self.keys)
        object.__setattr__(self, "_compiled", compiled)
        object.__setattr__(self, "_writers", _selectors(self.writers, f"rule {self.name!r} writers"))
        object.__setattr__(self, "_readers", _selectors(self.readers, f"rule {self.name!r} readers"))
        uses_owner = any(
            s.kind == "owner" for s in (*self._writers, *self._readers)
        )
        if uses_owner and not all(binds for _, _, binds, _ in compiled):
            raise ValueError(
                f"Access rule {self.name!r} uses {OWNER} in writers or readers, so every "
                f"key pattern must contain {OWNER}"
            )

    def match(self, key: str) -> tuple[str, str | None] | None:
        """Return (matching pattern, bound owner) or None."""
        for prefix, regex, _, pattern in self._compiled:
            if key.startswith(prefix):
                m = regex.match(key)
                if m is not None:
                    return pattern, m.groupdict().get("owner")
        return None


@dataclass(frozen=True)
class AccessDecision:
    """The result of an access check, with the steps that led to it."""

    allowed: bool
    operation: str
    key: str
    principal: str | None
    via: str
    rule: str | None
    pattern: str | None
    owner: str | None
    reason: str
    stage: str = ""  # registry | admin | class | rule | default | classification | none
    steps: tuple[TraceStep, ...] = ()

    def as_metadata(self) -> dict[str, Any]:
        return {
            "principal_via": self.via,
            "access_stage": self.stage,
            "access_rule": self.rule,
            "access_pattern": self.pattern,
            "owner": self.owner,
            "reason": self.reason,
        }

    def explain(self) -> str:
        who = self.principal or "<anonymous>"
        lines = [f"{self.operation} {self.key!r} as {who} (via {self.via})"]
        lines += [f"    {step}" for step in self.steps]
        lines.append(f"    => {'ALLOW' if self.allowed else 'DENY'}: {self.reason}")
        return "\n".join(lines)


def _coerce_class(value: Any) -> MemoryClass:
    return value if isinstance(value, MemoryClass) else MemoryClass(str(value))


# Stands in for admins and the default class gate when no admins are named:
# only anonymous callers (code using the guard directly) pass, as in 0.3.
_ANONYMOUS_ONLY = (Selector("<anonymous>", "anonymous"),)
_NO_ADMINS = "the policy names no admins, so only code using the guard without an agent identity may"


@dataclass(frozen=True)
class AccessPolicy:
    """Access rules plus the settings that apply to every rule.

    Args:
        rules: Ordered access rules; the first match wins.
        default: ``"allow"`` or ``"deny"`` for keys no rule covers.
        admins: Selectors allowed to ``rollback()``, ``retire_if()`` and
            ``snapshot()``. When empty, only anonymous callers (code using the
            guard directly, as in 0.3) may; agents may not.
        principals: The registry, ``{id: [roles]}``. When given, undeclared ids
            are denied and every id named in a rule must be declared.
        class_writers: ``{MemoryClass: selectors}`` for classes only some agents
            may write, delete or promote into or out of. When omitted, POLICY and
            VERIFIED_PREFERENCE are gated to ``admins`` (to anonymous callers only
            when ``admins`` is empty).
        ambient_identity: When False, ``with guard.as_agent(...)`` blocks are
            ignored and only ``principal=`` and handles carry identity.

    The policy is immutable; use ``dataclasses.replace()`` to derive a new one.
    """

    rules: Sequence[AccessRule] = ()
    default: str = "deny"
    admins: Sequence[str] = ()
    principals: Mapping[str, Iterable[str]] = field(default_factory=dict)
    class_writers: Mapping[Any, Iterable[str]] | None = None
    ambient_identity: bool = True
    # Compiled in __post_init__.
    _admin_sel: tuple[Selector, ...] = field(init=False, repr=False, compare=False)
    _registry: dict[str, frozenset[str]] = field(init=False, repr=False, compare=False)
    _class_sel: dict[MemoryClass, tuple[Selector, ...]] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        def put(name: str, value: Any) -> None:
            object.__setattr__(self, name, value)

        if self.default not in ("allow", "deny"):
            raise ValueError(f"access default must be 'allow' or 'deny', not {self.default!r}")
        put("rules", tuple(self.rules))
        for rule in self.rules:
            if not isinstance(rule, AccessRule):
                raise TypeError(f"access rules must be AccessRule objects, not {type(rule).__name__}")
        names = [r.name for r in self.rules]
        dupes = sorted({n for n in names if names.count(n) > 1})
        if dupes:
            raise ValueError(f"Duplicate access rule names: {dupes}")
        put("admins", (self.admins,) if isinstance(self.admins, str) else tuple(self.admins))
        put("_admin_sel", _selectors(self.admins, "admins") or _ANONYMOUS_ONLY)
        registry: dict[str, tuple[str, ...]] = {}
        for pid, roles in dict(self.principals).items():
            roles = (roles,) if isinstance(roles, str) else tuple(roles or ())
            registry[check_id(pid)] = tuple(check_id(r) for r in roles)
        put("principals", MappingProxyType(registry))
        put("_registry", {pid: frozenset(roles) for pid, roles in registry.items()})
        if self.class_writers is not None:
            gated = {
                _coerce_class(c): ((s,) if isinstance(s, str) else tuple(s))
                for c, s in dict(self.class_writers).items()
            }
            put("class_writers", MappingProxyType(gated))
            class_sel = {c: _selectors(s, f"class_writers[{c.value}]") for c, s in gated.items()}
        else:
            class_sel = {c: self._admin_sel for c in _GATED_BY_DEFAULT}
        put("_class_sel", class_sel)
        everything = [(f"rule {r.name!r}", s) for r in self.rules for s in (*r._writers, *r._readers)]
        everything += [("admins", s) for s in self._admin_sel]
        everything += [
            (f"class_writers[{c.value}]", s) for c, sels in class_sel.items() for s in sels
        ]
        for where, sel in everything:
            if sel.kind == "role" and not registry:
                raise ValueError(
                    f"{where}: {sel.raw!r} needs a principals registry "
                    "(roles are never taken from the caller)"
                )
            if sel.kind == "id" and registry and sel.value not in registry:
                raise ValueError(
                    f"{where} names unknown principal {sel.value!r}; declared: {sorted(registry)}"
                )
            if sel.kind == "owner" and not where.startswith("rule "):
                raise ValueError(f"{where}: {OWNER} is only valid in a rule's writers or readers")

    @staticmethod
    def _describe(sels: tuple[Selector, ...]) -> str:
        return "none named" if sels is _ANONYMOUS_ONLY else str([s.raw for s in sels])

    # ---- queries ------------------------------------------------------

    @property
    def registry(self) -> Mapping[str, frozenset[str]]:
        return dict(self._registry)

    def is_declared(self, pid: str) -> bool:
        reg = self._registry
        return not reg or pid in reg

    def is_admin(self, pid: str | None) -> bool:
        reg = self._registry
        roles = reg.get(pid, _NO_ROLES) if pid is not None else _NO_ROLES
        return any(s.matches(pid, roles, None) for s in self._admin_sel)

    def gated_classes(self) -> frozenset[MemoryClass]:
        return frozenset(self._class_sel)

    def may_change_class(self, principal: str | None, cls: MemoryClass | None) -> bool:
        """Whether ``principal`` passes the class gate for memory of class ``cls``."""
        sels = self._class_sel.get(cls) if cls is not None else None
        if sels is None:
            return True
        reg = self._registry
        roles = reg.get(principal, _NO_ROLES) if principal is not None else _NO_ROLES
        return any(s.matches(principal, roles, None) for s in sels)

    # ---- the decision -------------------------------------------------

    def allows(
        self,
        principal: str | None,
        operation: str,
        key: str,
        *,
        current_class: MemoryClass | None = None,
        target_class: MemoryClass | None = None,
    ) -> bool:
        """Fast path: the same answer as ``decide(...).allowed``, building nothing."""
        reg = self._registry
        if principal is not None and reg and principal not in reg:
            return False
        roles = reg.get(principal, _NO_ROLES) if principal is not None else _NO_ROLES
        if operation in ADMIN_OPS:
            return any(s.matches(principal, roles, None) for s in self._admin_sel)
        writes = operation in WRITE_OPS
        for rule in self.rules:
            hit = rule.match(key)
            if hit is not None:
                sels = rule._writers if writes else rule._readers
                if not any(s.matches(principal, roles, hit[1]) for s in sels):
                    return False
                break
        else:
            if self.default != "allow":
                return False
        if writes:
            class_sel = self._class_sel
            for cls in (current_class, target_class):
                if cls is not None and cls in class_sel:
                    if not any(s.matches(principal, roles, None) for s in class_sel[cls]):
                        return False
        return True

    def decide(
        self,
        principal: str | None,
        operation: str,
        key: str,
        *,
        current_class: MemoryClass | None = None,
        target_class: MemoryClass | None = None,
        via: str = "explicit",
        all_rules: bool = True,
    ) -> AccessDecision:
        """Decide one operation and record each step.

        ``all_rules=False`` leaves out the rules that did not match, which is
        what an agent's own handle shows.
        """
        if operation not in OPERATIONS:
            raise ValueError(f"Unknown operation {operation!r}; expected one of {sorted(OPERATIONS)}")
        steps: list[TraceStep] = []
        who = principal or "<anonymous>"

        def done(ok: bool, stage: str, why: str, rule: str | None = None,
                 pattern: str | None = None, owner: str | None = None) -> AccessDecision:
            return AccessDecision(ok, operation, key, principal, via, rule, pattern, owner,
                                  why, stage, tuple(steps))

        reg = self._registry
        if principal is not None and reg and principal not in reg:
            steps.append(TraceStep("registry", f"{principal!r} is not declared", "unknown"))
            return done(False, "registry", f"unknown principal {principal!r}")
        roles = reg.get(principal, _NO_ROLES) if principal is not None else _NO_ROLES
        if principal is not None and reg:
            steps.append(TraceStep("registry", f"{principal} roles={sorted(roles)}", "declared"))

        if operation in ADMIN_OPS:
            admin_sel = self._admin_sel
            allowed_by = self._describe(admin_sel)
            ok = any(s.matches(principal, roles, None) for s in admin_sel)
            steps.append(TraceStep("admin", f"admins {allowed_by}", "match" if ok else "no match"))
            if admin_sel is _ANONYMOUS_ONLY:
                why = f"{_NO_ADMINS} {operation} (pass admins=[...] to let agents)"
                return done(ok, "admin", why)
            if ok:
                return done(True, "admin", f"{who} is one of admins {allowed_by}")
            return done(False, "admin", f"{operation} requires one of admins {allowed_by}")

        writes = operation in WRITE_OPS
        acl = self._decide_rule(principal, roles, operation, key, writes, steps, all_rules)
        allowed, stage, why, rule, pattern, owner = acl
        if not allowed or not writes:
            return done(allowed, stage, why, rule, pattern, owner)

        class_sel = self._class_sel
        for cls in dict.fromkeys(c for c in (current_class, target_class) if c is not None):
            sels = class_sel.get(cls)
            if sels is None:
                continue
            allowed_by = self._describe(sels)
            ok = any(s.matches(principal, roles, None) for s in sels)
            steps.append(TraceStep("class", f"{cls.value} writers {allowed_by}", "match" if ok else "no match"))
            if not ok:
                if sels is _ANONYMOUS_ONLY:
                    why = (f"{who} may not {operation} class {cls.value}: the policy names no "
                           "admins or class_writers, so only code using the guard without an "
                           "agent identity may change it")
                else:
                    why = f"{who} may not {operation} class {cls.value} (class_writers {allowed_by})"
                return done(False, "class", why, rule, pattern, owner)
        return done(allowed, stage, why, rule, pattern, owner)

    def _decide_rule(
        self,
        principal: str | None,
        roles: frozenset[str],
        operation: str,
        key: str,
        writes: bool,
        steps: list[TraceStep],
        all_rules: bool,
    ) -> tuple[bool, str, str, str | None, str | None, str | None]:
        """The rule and default stages: (allowed, stage, reason, rule, pattern, owner)."""
        who = principal or "<anonymous>"
        list_name = "writers" if writes else "readers"
        for rule in self.rules:
            hit = rule.match(key)
            if hit is None:
                if all_rules:
                    steps.append(TraceStep("rule", f"{rule.name} keys={list(rule.keys)}", "no match"))
                continue
            pattern, owner = hit
            sels = rule._writers if writes else rule._readers
            raw = list(rule.writers if writes else rule.readers)
            bound = f" (owner={owner})" if owner is not None else ""
            steps.append(TraceStep("rule", f"{rule.name} keys={list(rule.keys)}", f"match {pattern!r}{bound}"))
            ok = any(s.matches(principal, roles, owner) for s in sels)
            steps.append(TraceStep(list_name, str(raw), "match" if ok else "no match"))
            if ok:
                return True, "rule", f"{who} is in {list_name} of {rule.name!r}", rule.name, pattern, owner
            why = f"{who} is not in {list_name} {raw} of {rule.name!r}"
            if owner is not None and not is_valid_id(owner):
                why += f" ({owner!r} is not a valid agent id, so no agent owns it)"
            return False, "rule", why, rule.name, pattern, owner

        ok = self.default == "allow"
        steps.append(TraceStep("default", f"no access rule matches {key!r}", self.default))
        why = f"no access rule covers {key!r}; default {self.default}"
        return ok, "default", why if ok else why + " (add an AccessRule for it)", None, None, None


__all__ = ["AccessDecision", "AccessPolicy", "AccessRule", "Selector"]
