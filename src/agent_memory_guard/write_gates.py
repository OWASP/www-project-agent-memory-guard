"""Write-only policy gates and detached pending proposals.

Resolution is a trusted application operation. Source classes and provenance
domains are assertions by that application, not authentication provided here.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Any

from agent_memory_guard.events import Action, SourceClass
from agent_memory_guard.exceptions import MemoryGuardError

GATE_ACTIONS = frozenset({Action.REQUIRE_APPROVAL, Action.REQUIRE_CORROBORATION})


class PendingWriteError(MemoryGuardError):
    """A pending proposal cannot be resolved with the supplied evidence."""


@dataclass(frozen=True)
class WriteGateRule:
    """Gate every write to matching keys, including benign content.

    Rules are ordered; the first matching key pattern wins. Corroboration
    requires distinct provenance domains supplied by trusted application code.
    ``trusted_source_classes`` does not authenticate those domains.
    """

    name: str
    keys: tuple[str, ...]
    action: Action = Action.REQUIRE_APPROVAL
    corroborations: int = 2
    trusted_source_classes: tuple[SourceClass, ...] = (SourceClass.SYSTEM,)
    ttl_seconds: float = 300.0

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("A write gate needs a nonempty name")
        keys = (self.keys,) if isinstance(self.keys, str) else tuple(self.keys)
        if not keys or any(not isinstance(key, str) or not key for key in keys):
            raise ValueError("A write gate needs nonempty key patterns")
        object.__setattr__(self, "keys", keys)
        action = Action(self.action)
        if action not in GATE_ACTIONS:
            raise ValueError("Write gates use require_approval or require_corroboration")
        object.__setattr__(self, "action", action)
        if type(self.corroborations) is not int or self.corroborations < 1:
            raise ValueError("corroborations must be a positive integer")
        classes = self.trusted_source_classes
        if isinstance(classes, str):
            classes = (classes,)
        classes = tuple(SourceClass(cls) for cls in classes)
        if not classes:
            raise ValueError("A write gate needs trusted source classes")
        object.__setattr__(self, "trusted_source_classes", classes)
        if (
            isinstance(self.ttl_seconds, bool)
            or not isinstance(self.ttl_seconds, (int, float))
            or not math.isfinite(self.ttl_seconds)
            or self.ttl_seconds <= 0
        ):
            raise ValueError("ttl_seconds must be a positive finite number")


@dataclass(frozen=True)
class PendingWrite:
    """Detached proposal visible only through the trusted host guard.

    ``digest`` binds the copied JSON value, key, principal and task. Reading
    ``value`` returns a fresh copy. Normal memory reads and snapshots contain
    committed memory only. Pending state is local to one live guard instance.
    """

    write_id: str
    key: str
    principal: str | None
    task_id: str | None
    action: Action
    rule: str
    digest: str
    created_at: float
    expires_at: float
    corroborations: int = 0
    required_corroborations: int = 0
    _value_json: str = field(default="null", repr=False)

    @property
    def value(self) -> Any:
        """Return a detached JSON value for trusted host inspection."""
        return json.loads(self._value_json)


@dataclass
class _PendingRecord:
    proposal: PendingWrite
    gate: WriteGateRule
    policy: Any
    target: Any
    source: str
    source_class: SourceClass
    source_type: Any
    receipt_uri: str | None
    cls: Any
    via: str = "anonymous"
    domains: set[str] = field(default_factory=set)
    resolving: bool = False


def encode_value(value: Any) -> str:
    """Encode only finite, unambiguous JSON values, rejecting custom objects."""
    active: set[int] = set()

    def check(item: Any, depth: int = 0) -> None:
        if depth > 64:
            raise ValueError("Gated values may nest at most 64 levels")
        if item is None or type(item) in (str, bool, int):
            return
        if type(item) is float and math.isfinite(item):
            return
        if type(item) not in (list, dict):
            raise ValueError("Gated values must contain only finite JSON values")
        if id(item) in active:
            raise ValueError("Gated values cannot contain cycles")
        active.add(id(item))
        try:
            if type(item) is dict:
                if any(type(key) is not str for key in item):
                    raise ValueError("Gated object keys must be strings")
                for child in item.values():
                    check(child, depth + 1)
            else:
                for child in item:
                    check(child, depth + 1)
        finally:
            active.remove(id(item))

    check(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def proposal_digest(value_json: str, key: str, principal: str | None, task_id: str | None) -> str:
    """Bind approval to the exact serialized value and its write context."""
    envelope = encode_value([key, principal, task_id, value_json])
    return hashlib.sha256(envelope.encode("utf-8")).hexdigest()
