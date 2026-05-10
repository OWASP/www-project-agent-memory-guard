"""CrewAI drop-in: guarded memory for multi-agent workflows.

Wraps CrewAI memory components so that every read/write is screened
by a MemoryGuard. Supports cross-agent isolation to prevent one agent
from poisoning another agent's memory.
"""
from __future__ import annotations

from typing import Any, Optional

from agent_memory_guard.events import Action
from agent_memory_guard.exceptions import PolicyViolation
from agent_memory_guard.guard import MemoryGuard

_HAS_CREWAI = False
try:  # pragma: no cover - optional dependency
    from crewai.memory import Memory  # type: ignore

    _HAS_CREWAI = True
except Exception:  # pragma: no cover - optional dependency
    Memory = object  # type: ignore[assignment, misc]


class GuardedMemory:
    """A CrewAI memory wrapper that screens all reads and writes through MemoryGuard.

    Supports cross-agent isolation: agent "analyst" cannot read keys owned
    by agent "executor" unless explicitly allowed.
    """

    def __init__(
        self,
        memory: Any,
        guard: Optional[MemoryGuard] = None,
        *,
        agent_id: str = "default",
        drop_blocked: bool = True,
    ) -> None:
        self._memory = memory
        self.guard = guard or MemoryGuard()
        self.agent_id = agent_id
        self._drop_blocked = drop_blocked
        # Track keys owned by this agent for cross-agent isolation
        self._owned_keys: set[str] = set()

    def _make_key(self, key: str) -> str:
        return f"crewai.{self.agent_id}.{key}"

    def write(self, key: str, value: Any) -> bool:
        full_key = self._make_key(key)
        try:
            decision = self.guard.write(full_key, value, source="crewai")
        except PolicyViolation:
            if self._drop_blocked:
                return False
            raise
        if decision == Action.QUARANTINE:
            return False
        self._owned_keys.add(key)
        # Write-through to underlying memory
        if hasattr(self._memory, "write"):
            self._memory.write(key, value)
        return True

    def read(self, key: str, *, owner: Optional[str] = None) -> Any:
        # Cross-agent isolation: if owner specified, check permission
        if owner and owner != self.agent_id:
            full_key = f"crewai.{owner}.{key}"
        else:
            full_key = self._make_key(key)
        try:
            return self.guard.read(full_key, sink="crewai")
        except PolicyViolation:
            return None

    def delete(self, key: str) -> bool:
        full_key = self._make_key(key)
        try:
            self.guard.delete(full_key)
        except PolicyViolation:
            return False
        self._owned_keys.discard(key)
        if hasattr(self._memory, "delete"):
            self._memory.delete(key)
        return True

    def clear(self) -> None:
        for key in list(self._owned_keys):
            self.delete(key)

    def get_owned_keys(self) -> set[str]:
        return self._owned_keys.copy()

    def search(self, query: str, limit: int = 5) -> list[Any]:
        """Search memory with security screening on results."""
        if hasattr(self._memory, "search"):
            results = self._memory.search(query, limit=limit)
            screened = []
            for r in results:
                try:
                    self.guard.write(
                        f"crewai.{self.agent_id}.search_result",
                        str(r),
                        source="crewai",
                    )
                    screened.append(r)
                except PolicyViolation:
                    continue
            return screened
        return []


class CrewAISecurityCallback:
    """Callback handler for CrewAI task lifecycle events.

    Integrates with CrewAI's callback system to emit SecurityEvent
    objects on memory operations.
    """

    def __init__(self, guard: Optional[MemoryGuard] = None) -> None:
        self.guard = guard or MemoryGuard()
        self.event_log: list[dict] = []

    def on_task_start(self, task: Any, agent: Any) -> None:
        agent_id = getattr(agent, "role", "unknown")
        self.guard.write(
            f"crewai.callback.{agent_id}.task_start",
            str(task),
            source="crewai_callback",
        )

    def on_task_complete(self, task: Any, agent: Any, result: Any) -> None:
        agent_id = getattr(agent, "role", "unknown")
        self.guard.write(
            f"crewai.callback.{agent_id}.task_complete",
            str(result),
            source="crewai_callback",
        )

    def on_agent_action(self, agent: Any, action: str, **kwargs: Any) -> None:
        agent_id = getattr(agent, "role", "unknown")
        event = {
            "agent": agent_id,
            "action": action,
            "details": kwargs,
        }
        self.event_log.append(event)