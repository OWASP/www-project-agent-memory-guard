"""Declarative YAML policy engine.

Example policy:

    version: 1
    default_action: allow
    protected_keys:
      - system.*
      - identity.role
    immutable_keys:
      - identity.user_id
    rules:
      - name: block_injection
        on: prompt_injection
        action: block
      - name: redact_secrets
        on: sensitive_data
        action: redact
      - name: quarantine_size_anomaly
        on: size_anomaly
        action: quarantine
"""
from __future__ import annotations

import dataclasses
import fnmatch
import os
import sys
import warnings
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agent_memory_guard.events import Action, Severity
from agent_memory_guard.exceptions import PolicyWarning
from agent_memory_guard.policies.access import AccessPolicy, AccessRule

_VALID_ACTIONS = {a.value for a in Action}

# Detector whose events are gated on the policy's protected/immutable key lists.
_PROTECTED_KEY_DETECTOR = "protected_key"


@dataclass
class PolicyRule:
    name: str
    on: str
    action: Action
    min_severity: Severity = Severity.LOW
    keys: tuple[str, ...] = ()

    def applies_to(self, detector: str, severity: Severity, key: str) -> bool:
        if self.on != "*" and self.on != detector:
            return False
        if _severity_rank(severity) < _severity_rank(self.min_severity):
            return False
        if self.keys:
            import fnmatch

            return any(fnmatch.fnmatchcase(key, pat) for pat in self.keys)
        return True


@dataclass
class Policy:
    """Security policy configuration for MemoryGuard operations.

    A policy dictates the action to take (ALLOW, REDACT, QUARANTINE, or BLOCK)
    when detectors match security anomalies or prompt injections. It defines key rules,
    protected keys, and immutable baselines.

    Attributes:
        default_action: The fallback action when no rules match. Defaults to Action.ALLOW.
        protected_keys: Glob patterns for keys protected against deletion or modification.
        immutable_keys: Glob patterns for keys monitored with cryptographic integrity checks.
        rules: Ordered list of rules to evaluate when scanning keys.
        version: Policy syntax version. Defaults to 1.
        access: Per-agent access rules (see :meth:`with_access`). None, the
            default, means no access checks, exactly as in 0.3.

    Example:
        >>> policy = Policy.strict()
        >>> policy.decide("prompt_injection", Severity.HIGH, "session.notes")
        <Action.BLOCK: 'block'>
    """
    default_action: Action = Action.ALLOW
    protected_keys: tuple[str, ...] = ()
    immutable_keys: tuple[str, ...] = ()
    rules: list[PolicyRule] = field(default_factory=list)
    version: int = 1
    access: AccessPolicy | None = None

    def is_immutable(self, key: str) -> bool:
        """True if `key` matches any ``immutable_keys`` glob.

        ``immutable_keys`` is documented as glob patterns and is glob-matched by
        the deletion guard via :func:`merge_protected_keys`. Matching it exactly
        anywhere else would let a declaration such as ``identity.*`` block
        deletes while silently creating no integrity baseline.
        """
        return any(fnmatch.fnmatchcase(key, pattern) for pattern in self.immutable_keys)

    def decide(self, detector: str, severity: Severity, key: str) -> Action:
        for rule in self.rules:
            if rule.applies_to(detector, severity, key):
                return rule.action
        return self.default_action

    def evaluate(self, detector: str, severity: Severity, key: str) -> tuple[Action, str | None]:
        """Like :meth:`decide`, but also return the name of the deciding rule.

        The name is None when no rule matched and ``default_action`` applied.
        """
        for rule in self.rules:
            if rule.applies_to(detector, severity, key):
                return rule.action, rule.name
        return self.default_action, None

    def with_access(
        self,
        *rules: AccessRule,
        default: str = "deny",
        admins: Iterable[str] = (),
        principals: Mapping[str, Iterable[str]] | None = None,
        class_writers: Mapping[Any, Iterable[str]] | None = None,
        ambient_identity: bool = True,
    ) -> Policy:
        """Return a copy of this policy with per-agent access rules.

        The guard checks access before any detector runs. Content rules
        (``rules``) still apply to every operation that access allows.

        Example:
            >>> policy = Policy.strict().with_access(
            ...     AccessRule("plan", keys=["plan.*"], writers=["supervisor"], readers=["*"]),
            ...     default="allow",
            ...     admins=["supervisor"],
            ... )

        See :class:`~agent_memory_guard.policies.access.AccessPolicy` for the arguments.
        """
        access = AccessPolicy(
            list(rules),
            default=default,
            admins=(admins,) if isinstance(admins, str) else tuple(admins),
            principals=dict(principals or {}),
            class_writers=class_writers,
            ambient_identity=ambient_identity,
        )
        return dataclasses.replace(self, rules=list(self.rules), access=access)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        if not isinstance(data, Mapping):
            raise ValueError(f"A policy must be a mapping, not {type(data).__name__}")
        _check_fields(data)
        rules = [_parse_rule(r) for r in data.get("rules", [])]
        protected_keys = tuple(data.get("protected_keys", ()) or ())
        immutable_keys = tuple(data.get("immutable_keys", ()) or ())
        _check_key_rules_have_keys(rules, protected_keys, immutable_keys)
        return cls(
            version=int(data.get("version", 1)),
            default_action=_parse_action(data.get("default_action", "allow")),
            protected_keys=protected_keys,
            immutable_keys=immutable_keys,
            rules=rules,
        )

    @classmethod
    def permissive(cls) -> Policy:
        return cls(default_action=Action.ALLOW)

    @classmethod
    def strict(cls) -> Policy:
        """Pre-configured policy for the documented quickstart.

        ``protected_keys`` has to be populated for the ``block_protected_key``
        rule below to ever fire: ``ProtectedKeyDetector`` only reports a key
        that matches one of these patterns. The namespaces are the ones the
        examples and the README already treat as protected.
        """
        return cls(
            default_action=Action.ALLOW,
            protected_keys=("identity.*", "system.*", "agent.goal"),
            rules=[
                PolicyRule("block_injection", "prompt_injection", Action.BLOCK),
                PolicyRule("redact_secrets", "sensitive_data", Action.REDACT),
                PolicyRule("block_protected_key", "protected_key", Action.BLOCK),
                PolicyRule("quarantine_size_anomaly", "size_anomaly", Action.QUARANTINE),
                PolicyRule("quarantine_rapid_change", "rapid_change", Action.QUARANTINE),
            ],
        )


    @classmethod
    def tiered(cls) -> Policy:
        """Pre-configured policy with key-pattern-scoped detector rules.

        Maps memory-class key namespaces to detector-specific actions, so
        e.g. a ``prompt_injection`` finding inside ``credentials.*`` is blocked
        while the same finding inside ``facts.*`` is quarantined for review.

        Key namespaces (matched as ``fnmatch`` patterns):
        - ``credentials.*`` — block ``prompt_injection`` and ``sensitive_data``;
          also listed in ``protected_keys``.
        - ``permissions.*`` — block ``prompt_injection`` and ``sensitive_data``;
          also listed in ``protected_keys``.
        - ``policies.*`` — block ``prompt_injection``; also in ``protected_keys``.
        - ``facts.*`` — quarantine ``prompt_injection`` and ``size_anomaly``;
          also in ``protected_keys``.
        - ``preferences.*`` — redact ``sensitive_data``;
          also in ``protected_keys``.
        - ``tool_results.*`` — block ``prompt_injection``,
          quarantine ``size_anomaly``.
        - ``scratch.*`` — quarantine ``size_anomaly``.

        Global catch-all rules (block injection, redact secrets, block
        protected-key writes, quarantine size/rate anomalies) run after the
        pattern-scoped rules.

        Time-to-live, revalidation, session lifetime, and actor-role gating
        are NOT implemented here; that's a separate roadmap item.
        """
        return cls(
            default_action=Action.ALLOW,
            protected_keys=(
                "credentials.*",
                "permissions.*",
                "policies.*",
                "facts.*",
            ),  # preferences.*, tool_results.* and scratch.* are writable by design
            rules=[
                # credentials.* — locked, block
                PolicyRule(
                    "block_credential_injection",
                    "prompt_injection",
                    Action.BLOCK,
                    keys=("credentials.*",),
                ),
                PolicyRule(
                    "block_credential_sensitive",
                    "sensitive_data",
                    Action.BLOCK,
                    keys=("credentials.*",),
                ),
                # permissions.* — locked, block
                PolicyRule(
                    "block_permission_injection",
                    "prompt_injection",
                    Action.BLOCK,
                    keys=("permissions.*",),
                ),
                PolicyRule(
                    "block_permission_sensitive",
                    "sensitive_data",
                    Action.BLOCK,
                    keys=("permissions.*",),
                ),
                # policies.* — system-only, block
                PolicyRule(
                    "block_policy_injection",
                    "prompt_injection",
                    Action.BLOCK,
                    keys=("policies.*",),
                ),
                # facts.* — trusted, quarantine
                PolicyRule(
                    "quarantine_fact_injection",
                    "prompt_injection",
                    Action.QUARANTINE,
                    keys=("facts.*",),
                ),
                PolicyRule(
                    "quarantine_fact_anomaly",
                    "size_anomaly",
                    Action.QUARANTINE,
                    keys=("facts.*",),
                ),
                # preferences.* — user-only, redact
                PolicyRule(
                    "redact_preference_sensitive",
                    "sensitive_data",
                    Action.REDACT,
                    keys=("preferences.*",),
                ),
                # tool_results.* — untrusted, block + quarantine
                PolicyRule(
                    "block_tool_result_injection",
                    "prompt_injection",
                    Action.BLOCK,
                    keys=("tool_results.*",),
                ),
                PolicyRule(
                    "quarantine_tool_result_anomaly",
                    "size_anomaly",
                    Action.QUARANTINE,
                    keys=("tool_results.*",),
                ),
                # scratch.* — ephemeral, quarantine
                PolicyRule(
                    "quarantine_scratch_anomaly",
                    "size_anomaly",
                    Action.QUARANTINE,
                    keys=("scratch.*",),
                ),
                # Global catch-all rules
                PolicyRule("block_injection", "prompt_injection", Action.BLOCK),
                PolicyRule("redact_secrets", "sensitive_data", Action.REDACT),
                PolicyRule("block_protected_key", "protected_key", Action.BLOCK),
                PolicyRule("quarantine_size_anomaly", "size_anomaly", Action.QUARANTINE),
                PolicyRule("quarantine_rapid_change", "rapid_change", Action.QUARANTINE),
            ],
        )


def _parse_action(value: Any) -> Action:
    if isinstance(value, Action):
        return value
    text = str(value).lower()
    if text not in _VALID_ACTIONS:
        raise ValueError(f"Unknown policy action: {value!r}")
    return Action(text)


def _parse_rule(raw: dict[str | bool, Any]) -> PolicyRule:
    # YAML 1.1 parses unquoted `on` as the boolean True; remap it to the
    # intended string key so users can write natural policy files.
    if True in raw and "on" not in raw:
        raw_str: dict[str | bool, Any] = {**raw, "on": raw[True]}
        raw = raw_str
    if "name" not in raw or "action" not in raw:
        raise ValueError(f"Policy rule missing required fields: {raw!r}")
    keys = raw.get("keys") or ()
    if isinstance(keys, str):
        keys = (keys,)
    return PolicyRule(
        name=str(raw["name"]),
        on=str(raw.get("on", "*")),
        action=_parse_action(raw["action"]),
        min_severity=Severity(str(raw.get("min_severity", "low")).lower()),
        keys=tuple(keys),
    )


_SEVERITY_ORDER = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)


def _severity_rank(s: Severity) -> int:
    return _SEVERITY_ORDER.index(s)


def load_policy(source: str | Path | dict[str, Any]) -> Policy:
    """Load a security policy from a YAML string, a file path, or a dictionary.

    This function parses declarative policies that dictate the behavior of
    MemoryGuard when checking memory operations.

    Args:
        source: The YAML policy configuration. This can be a file path (Path object),
            a raw YAML string, or an already-parsed dictionary representation of the policy.

    Returns:
        Policy: The loaded Policy configuration instance.

    Example:
        >>> from pathlib import Path
        >>> policy = load_policy("version: 1\\ndefault_action: allow")
        >>> print(policy.default_action)
    """
    if isinstance(source, dict):
        return Policy.from_dict(source)
    if isinstance(source, Path):
        data = yaml.safe_load(source.read_text(encoding="utf-8"))
        return Policy.from_dict(data or {})
    text = str(source)
    candidate = Path(text)
    if candidate.exists() and candidate.is_file():
      data = yaml.safe_load(candidate.read_text(encoding="utf-8"))
    else:
        data = yaml.safe_load(text)
    return Policy.from_dict(data or {})



def _check_key_rules_have_keys(
    rules: Iterable[PolicyRule],
    protected_keys: tuple[str, ...],
    immutable_keys: tuple[str, ...],
) -> None:
    """Reject a policy whose protected-key rules can never fire.

    ProtectedKeyDetector only reports a key that matches one of the policy's
    protected or immutable patterns, so with neither list populated a rule on
    that detector is inert. A rule's own ``keys`` does not rescue it: that
    narrows which reported keys the rule handles, and nothing is reported.

    Loading such a policy without complaint is the part worth avoiding, since
    the guard still runs and still enforces its other rules, so there is no
    later symptom to notice.
    """
    dead = [r.name for r in rules if r.on == _PROTECTED_KEY_DETECTOR]
    if dead and not protected_keys and not immutable_keys:
        raise ValueError(
            "Policy rule(s) "
            + ", ".join(repr(n) for n in dead)
            + f" act on {_PROTECTED_KEY_DETECTOR!r}, but the policy declares no "
            "'protected_keys' and no 'immutable_keys', so they can never match. "
            "Declare the keys to guard, or drop the rule(s)."
        )


_KNOWN_TOP_FIELDS = {"version", "default_action", "protected_keys", "immutable_keys", "rules"}
_KNOWN_RULE_FIELDS = {"name", "on", True, "action", "min_severity", "keys"}
# Fields that can only mean per-agent permissions. 0.3 silently dropped them,
# which let every agent through, so they are now an error, in any letter case.
_ACCESS_TOP_FIELDS = {"access", "principals", "agents"}
_ACCESS_RULE_FIELDS = {
    "access", "agents", "agent", "writers", "writer", "readers", "reader", "principal",
    "principals",
}
_PACKAGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _is_access_field(key: Any, fields: set[str]) -> bool:
    return isinstance(key, str) and key.strip().lower() in fields


def _warn(message: str) -> None:
    """Emit a PolicyWarning that points at the first caller outside this package."""
    frame = sys._getframe(1)
    level = 2
    while frame.f_back is not None and frame.f_code.co_filename.startswith(_PACKAGE_DIR):
        frame = frame.f_back
        level += 1
    warnings.warn(message, PolicyWarning, stacklevel=level)


def _check_fields(data: dict[str, Any]) -> None:
    """Fail on per-agent fields this loader would ignore; warn on other unknown fields."""
    access_top = sorted(str(k) for k in data if _is_access_field(k, _ACCESS_TOP_FIELDS))
    if access_top:
        raise ValueError(
            f"Policy section(s) {access_top} are not read from YAML in this version, so "
            "they would grant nothing. Build per-agent access rules in Python with "
            "Policy.with_access(AccessRule(...)); YAML support for access rules is planned."
        )
    unknown_top = sorted(str(k) for k in data if k not in _KNOWN_TOP_FIELDS)
    for raw in data.get("rules", []) or []:
        if not isinstance(raw, dict):
            continue
        name = raw.get("name", "?")
        access_fields = sorted(str(k) for k in raw if _is_access_field(k, _ACCESS_RULE_FIELDS))
        if access_fields:
            raise ValueError(
                f"Rule {name!r} has per-agent field(s) {access_fields}. Detector rules "
                "cannot carry per-agent permissions (0.3 silently ignored them, which let "
                "every agent through). Use Policy.with_access(AccessRule(name, keys=..., "
                "writers=..., readers=...)) instead."
            )
        unknown = sorted(str(k) for k in raw if k not in _KNOWN_RULE_FIELDS)
        if unknown:
            _warn(f"Rule {name!r}: unknown field(s) {unknown} are ignored")
    if unknown_top:
        _warn(f"Unknown policy field(s) {unknown_top} are ignored")


def merge_protected_keys(policy: Policy, extra: Iterable[str] = ()) -> tuple[str, ...]:
    seen: list[str] = []
    for k in (*policy.protected_keys, *policy.immutable_keys, *extra):
        if k not in seen:
            seen.append(k)
    return tuple(seen)
