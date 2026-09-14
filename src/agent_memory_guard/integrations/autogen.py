"""Microsoft AutoGen drop-in: guarded message handling for multi-agent conversations.

Wraps AutoGen's ConversableAgent message send/receive to screen for memory
poisoning attacks in group chat scenarios.
"""
from __future__ import annotations

from typing import Any

from agent_memory_guard.events import Action
from agent_memory_guard.exceptions import PolicyViolation
from agent_memory_guard.guard import MemoryGuard

_HAS_AUTOGEN = False
try:  # pragma: no cover - optional dependency
    from autogen import Agent, ConversableAgent  # type: ignore

    _HAS_AUTOGEN = True
except Exception:  # pragma: no cover - optional dependency
    Agent = object  # type: ignore[assignment, misc]
    ConversableAgent = object  # type: ignore[assignment, misc]


class GuardedAutoGenAgent:
    """Wraps an AutoGen ConversableAgent with memory poisoning protection.

    Note: This wrapper intercepts explicit .send() / .receive() calls.
    It does NOT hook into AutoGen's internal reply loop (register_reply,
    _process_received_message). For group chat scenarios, use
    install_guard() instead.
    """

    def __init__(
        self,
        agent: Any,
        guard: MemoryGuard | None = None,
        *,
        drop_blocked: bool = True,
    ) -> None:
        if not _HAS_AUTOGEN:
            raise ImportError(
                "agent-memory-guard[autogen] not installed; "
                "pip install agent-memory-guard[autogen]"
            )
        self._agent = agent
        self.guard = guard or MemoryGuard()
        self._drop_blocked = drop_blocked
        self._message_count = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self._agent, name)

    def screen_message(self, message: dict, source: str) -> bool:
        """Screen a message before send/receive."""
        msg_id = f"autogen.{self._agent.name}.msg.{self._message_count}"
        payload = (
            message.get("content", "") if isinstance(message, dict) else str(message)
        )
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


def install_guard(
    agent: Any,
    guard: MemoryGuard | None = None,
    *,
    drop_blocked: bool = True,
) -> Any:
    """Attach memory-poisoning screening to a live AutoGen agent's reply loop.

    Registers a ``register_reply`` hook (position 0, so it runs first) that
    screens each inbound message through ``guard``. Blocked content is
    swallowed — the hook consumes the turn with an empty reply instead of
    letting the poisoned message drive the agent's reasoning.

    Unlike :class:`GuardedAutoGenAgent` (which only intercepts explicit
    ``.send()`` / ``.receive()`` calls), this hook also covers messages
    flowing through group chats and internal reply dispatch.
    """
    if not _HAS_AUTOGEN:
        raise ImportError(
            "agent-memory-guard[autogen] not installed; "
            "pip install agent-memory-guard[autogen]"
        )
    guard = guard or MemoryGuard()

    def _screen_reply(
        recipient: Any, messages: list | None, sender: Any, config: Any
    ) -> tuple[bool, Any]:
        if not messages:
            return False, None
        last = messages[-1]
        content = last.get("content", "") if isinstance(last, dict) else str(last)
        sender_name = getattr(sender, "name", "unknown")
        key = f"autogen.hooked.{sender_name}.{id(last)}"
        try:
            decision = guard.write(key, content, source="autogen_hook")
        except PolicyViolation:
            if drop_blocked:
                return True, ""
            raise
        if decision != Action.ALLOW and drop_blocked:
            return True, ""
        return False, None

    agent.register_reply([Agent, None], _screen_reply, position=0)
    return agent


class GuardedGroupChatManager:
    """Protects group chat memory from cross-agent poisoning."""

    def __init__(
        self,
        group_chat: Any,
        guard: MemoryGuard | None = None,
    ) -> None:
        self._group_chat = group_chat
        self.guard = guard or MemoryGuard()
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
