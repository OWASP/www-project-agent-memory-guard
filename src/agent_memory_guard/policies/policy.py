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

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agent_memory_guard.events import Action, Severity

_VALID_ACTIONS = {a.value for a in Action}


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
    default_action: Action = Action.ALLOW
    protected_keys: tuple[str, ...] = ()
    immutable_keys: tuple[str, ...] = ()
    rules: list[PolicyRule] = field(default_factory=list)
    version: int = 1

    def decide(self, detector: str, severity: Severity, key: str) -> Action:
        for rule in self.rules:
            if rule.applies_to(detector, severity, key):
                return rule.action
        return self.default_action

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        rules = [_parse_rule(r) for r in data.get("rules", [])]
        return cls(
            version=int(data.get("version", 1)),
            default_action=_parse_action(data.get("default_action", "allow")),
            protected_keys=tuple(data.get("protected_keys", ()) or ()),
            immutable_keys=tuple(data.get("immutable_keys", ()) or ()),
            rules=rules,
        )

    @classmethod
    def permissive(cls) -> Policy:
        return cls(default_action=Action.ALLOW)

    @classmethod
    def strict(cls) -> Policy:
        return cls(
            default_action=Action.ALLOW,
            rules=[
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
    """Load a policy from a YAML string, file path, or already-parsed dict."""
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


def merge_protected_keys(policy: Policy, extra: Iterable[str] = ()) -> tuple[str, ...]:
    seen: list[str] = []
    for k in (*policy.protected_keys, *policy.immutable_keys, *extra):
        if k not in seen:
            seen.append(k)
    return tuple(seen)
