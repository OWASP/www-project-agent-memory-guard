"""agno drop-in: a MemoryManager whose memory writes are screened by MemoryGuard.

Follows the same optional-dependency pattern as the LangChain integration.
Verified against agno 2.8.5: both public write paths (``add_user_memory``,
``replace_user_memory``) and the model-driven ``create_or_update_memories``
path route through ``MemoryManager._upsert_db_memory``, which is wrapped here
as the single screening choke point for synchronous writes. Async paths
(``acreate_user_memories`` etc.) are not yet covered.

Usage:
    from agno.agent import Agent
    from agno.db.sqlite import SqliteDb
    from agent_memory_guard import MemoryGuard, Policy
    from agent_memory_guard.integrations.agno import GuardedMemoryManager

    db = SqliteDb(db_file="tmp/agents.db")
    agent = Agent(
        db=db,
        memory_manager=GuardedMemoryManager(
            db=db,
            guard=MemoryGuard(policy=Policy.strict()),
        ),
        enable_agentic_memory=True,
    )
"""
from __future__ import annotations

from dataclasses import replace as _dc_replace
from typing import Any

from agent_memory_guard.events import Action, SourceClass
from agent_memory_guard.exceptions import PolicyViolation
from agent_memory_guard.guard import MemoryGuard

try:  # pragma: no cover - optional dependency
    from agno.db.schemas import UserMemory  # type: ignore
    from agno.memory.manager import MemoryManager  # type: ignore

    _HAS_AGNO = True
except Exception:  # pragma: no cover - optional dependency
    MemoryManager = object  # type: ignore[assignment, misc]
    UserMemory = Any  # type: ignore[assignment, misc]
    _HAS_AGNO = False


class GuardedMemoryManager(MemoryManager):  # type: ignore[misc, valid-type]
    """agno ``MemoryManager`` with every memory write screened by a MemoryGuard.

    Each user memory is written under the key
    ``user_memory.<user_id>.<memory_id>``, so injection / leakage / churn
    detectors apply per-memory. Policy decisions map as follows:

    - ``BLOCK``: the memory is dropped (or ``PolicyViolation`` is raised if
      ``drop_blocked=False``) and never reaches the agno database.
    - ``QUARANTINE``: the memory is held in ``guard.quarantine`` for review
      instead of being persisted.
    - ``REDACT``: the redacted text is what gets persisted.
    - ``ALLOW``: the memory is stored unchanged.

    The guard also keeps its own audit mirror of screened memories, so
    ``guard.events``, ``guard.snapshot()`` and ``guard.rollback()`` work as
    forensic tools alongside the agno store.
    """

    def __init__(
        self,
        *args: Any,
        guard: MemoryGuard | None = None,
        drop_blocked: bool = True,
        default_source_class: SourceClass = SourceClass.AGENT_AUTHORED,
        **kwargs: Any,
    ) -> None:
        if not _HAS_AGNO:  # pragma: no cover - optional dependency
            raise ImportError(
                "GuardedMemoryManager requires the 'agno' package: pip install agno"
            )
        super().__init__(*args, **kwargs)
        self.guard = guard or MemoryGuard()
        self._drop_blocked = drop_blocked
        self._default_source_class = default_source_class

    # Single sync write choke point in agno's MemoryManager (verified 2.8.5).
    def _upsert_db_memory(self, memory: UserMemory) -> str:  # type: ignore[override]
        screened = self._screen(memory)
        if screened is None:
            # Blocked or quarantined: skip the database write entirely.
            return getattr(memory, "memory_id", None) or ""
        return super()._upsert_db_memory(memory=screened)  # type: ignore[misc]

    def _screen(self, memory: UserMemory) -> UserMemory | None:
        key = (
            f"user_memory.{getattr(memory, 'user_id', None) or 'default'}"
            f".{getattr(memory, 'memory_id', None) or 'new'}"
        )
        try:
            action = self.guard.write(
                key,
                memory.memory,
                source="agno",
                source_class=self._default_source_class,
            )
        except PolicyViolation:
            if self._drop_blocked:
                return None
            raise
        if action == Action.QUARANTINE:
            return None
        if action == Action.REDACT:
            committed = self.guard._store.get(key)  # noqa: SLF001 - committed (redacted) value
            if committed is not None:
                return _dc_replace(memory, memory=committed)
        return memory


__all__ = ["GuardedMemoryManager"]
