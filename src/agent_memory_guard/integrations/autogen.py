"""Microsoft AutoGen drop-in: guarded message handling for multi-agent conversations.

Wraps AutoGen's ConversableAgent message send/receive to screen for memory
poisoning attacks in group chat scenarios.
"""
from __future__ import annotations

from typing import Any, Optional

from agent_memory_guard.events import Action
from agent_memory_guard.exceptions import PolicyViolation
from agent_memory_guard.guard import MemoryGuard

_HAS_AUTOGEN = False
try:  # pragma: no cover - optional dependency
    from autogen import ConversableAgent  # type: ignore

    _HAS_AUTOGEN = True
except Exception:  # pragma: no cover - optional dependency
    ConversableAgent = object  # type: ignore[assignment, misc]


class GuardedAutoGenAgent:
    """Wraps an AutoGen ConversableAgent with memory poisoning protection."""

    def __init__(
        self,
        agent: Any,
        guard: Optional[MemoryGuard] = None,
        *,
        drop_blocked: bool = True,
    ) -> None:
        self._agent = agent
        self.guard = guard or MemoryGuard()
        self._drop_blocked = drop_blocked
        self._message_count = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self._agent, name)

    def screen_message(self, message: dict, source: str) -> bool:
        """Screen a message before send/receive."""
        msg_id = f"autogen.{self._agent.name}.msg.{self._message_count}"
        payload = str(message)
        try:
            decision = self.guard.write(msg_id, payload, source=source)
        except PolicyViolation:
            if self._drop_blocked:
                return False
            raise
        if decision == Action.QUARANTINE:
            return False
        self._message_count += 1
        return True

    def send(
        self, message: str | dict, recipient: Any, request_reply: bool = False
    ) -> None:
        msg = message if isinstance(message, dict) else {"content": message}
        if self.screen_message(msg, "autogen_send"):
            self._agent.send(message, recipient, request_reply=request_reply)

    def receive(
        self, message: str | dict, sender: Any, request_reply: bool = False
    ) -> None:
        msg = message if isinstance(message, dict) else {"content": message}
        if self.screen_message(msg, "autogen_receive"):
            self._agent.receive(message, sender, request_reply=request_reply)


class GuardedGroupChatManager:
    """Protects group chat memory from cross-agent poisoning."""

    def __init__(
        self,
        group_chat: Any,
        guard: Optional[MemoryGuard] = None,
        *,
        agent_isolation: bool = True,
    ) -> None:
        self._group_chat = group_chat
        self.guard = guard or MemoryGuard()
        self._agent_isolation = agent_isolation
        self._agent_keys: dict[str, set[str]] = {}

    def __getattr__(self, name: str) -> Any:
        return getattr(self._group_chat, name)

    def record_message(self, agent_name: str, message: dict) -> bool:
        key = f"autogen.group.{agent_name}.{len(self._agent_keys.get(agent_name, set()))}"
        try:
            self.guard.write(key, str(message), source="autogen_group")
        except PolicyViolation:
            return False
        if agent_name not in self._agent_keys:
            self._agent_keys[agent_name] = set()
        self._agent_keys[agent_name].add(key)
        return True