"""OpenAI Agents SDK drop-in: guarded context and state management.

Protects agent context, tool outputs, and handoff between agents
from memory poisoning attacks.
"""
from __future__ import annotations

from typing import Any, Optional

from agent_memory_guard.events import Action
from agent_memory_guard.exceptions import PolicyViolation
from agent_memory_guard.guard import MemoryGuard


class GuardedAgentContext:
    """Wraps OpenAI Agents SDK context with memory poisoning protection."""

    def __init__(
        self,
        context: Any,
        guard: Optional[MemoryGuard] = None,
        *,
        drop_blocked: bool = True,
    ) -> None:
        self._context = context
        self.guard = guard or MemoryGuard()
        self._drop_blocked = drop_blocked

    def __getattr__(self, name: str) -> Any:
        return getattr(self._context, name)

    def set_state(self, key: str, value: Any) -> bool:
        full_key = f"openai_agents.state.{key}"
        try:
            decision = self.guard.write(full_key, value, source="openai_agents")
        except PolicyViolation:
            if self._drop_blocked:
                return False
            raise
        if decision == Action.QUARANTINE:
            return False
        if hasattr(self._context, "set_state"):
            self._context.set_state(key, value)
        return True

    def get_state(self, key: str) -> Any:
        full_key = f"openai_agents.state.{key}"
        try:
            cached = self.guard.read(full_key, sink="openai_agents")
            if cached is not None:
                return cached
        except PolicyViolation:
            pass
        if hasattr(self._context, "get_state"):
            return self._context.get_state(key)
        return None


class GuardedToolOutput:
    """Screens tool outputs before they enter agent memory."""

    def __init__(
        self,
        guard: Optional[MemoryGuard] = None,
        *,
        drop_blocked: bool = True,
    ) -> None:
        self.guard = guard or MemoryGuard()
        self._drop_blocked = drop_blocked
        self._call_count = 0

    def screen_tool_output(self, tool_name: str, output: Any) -> bool:
        key = f"openai_agents.tool.{tool_name}.{self._call_count}"
        self._call_count += 1
        try:
            decision = self.guard.write(key, str(output), source="openai_agents_tool")
        except PolicyViolation:
            if self._drop_blocked:
                return False
            raise
        return decision != Action.QUARANTINE


class GuardedHandoff:
    """Protects handoff context between agents."""

    def __init__(
        self,
        guard: Optional[MemoryGuard] = None,
        *,
        from_agent: str = "unknown",
        to_agent: str = "unknown",
    ) -> None:
        self.guard = guard or MemoryGuard()
        self.from_agent = from_agent
        self.to_agent = to_agent

    def transfer(self, context: dict) -> bool:
        key = f"openai_agents.handoff.{self.from_agent}.{self.to_agent}"
        try:
            self.guard.write(key, str(context), source="openai_agents_handoff")
        except PolicyViolation:
            return False
        return True