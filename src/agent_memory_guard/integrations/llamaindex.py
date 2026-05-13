"""LlamaIndex drop-in: a chat store guarded by MemoryGuard.

Wraps any LlamaIndex ``BaseChatStore`` so that every message insertion is
screened by a MemoryGuard before it reaches the underlying store.
"""
from __future__ import annotations

from typing import Any, Optional

from agent_memory_guard.events import Action
from agent_memory_guard.exceptions import PolicyViolation
from agent_memory_guard.guard import MemoryGuard

_HAS_LLAMAINDEX = False
try:  # pragma: no cover - optional dependency
    from llama_index.core.chat_store.types import BaseChatStore  # type: ignore
    from llama_index.core.llms import ChatMessage  # type: ignore

    _HAS_LLAMAINDEX = True
except Exception:  # pragma: no cover - optional dependency
    BaseChatStore = object  # type: ignore[assignment, misc]
    ChatMessage = Any  # type: ignore[assignment, misc]


class GuardedChatStore(BaseChatStore):  # type: ignore[misc, valid-type]
    """A LlamaIndex chat store that passes every message through a MemoryGuard.

    Messages that violate policy can be silently dropped or raise an exception
    depending on *drop_blocked*.
    """

    store_key = "llamaindex_messages"

    def __init__(
        self,
        store: BaseChatStore,
        guard: Optional[MemoryGuard] = None,
        *,
        drop_blocked: bool = True,
    ) -> None:
        self._store = store
        self.guard = guard or MemoryGuard()
        self._drop_blocked = drop_blocked

    @classmethod
    def class_name(cls) -> str:
        return "GuardedChatStore"

    def set_messages(self, key: str, messages: list[ChatMessage]) -> None:
        screened: list[ChatMessage] = []
        for i, msg in enumerate(messages):
            msg_key = f"{self.store_key}.{key}.{i}"
            payload = msg.model_dump() if hasattr(msg, "model_dump") else str(msg)
            try:
                decision = self.guard.write(msg_key, payload, source="llamaindex")
            except PolicyViolation:
                if self._drop_blocked:
                    continue
                raise
            if decision == Action.QUARANTINE:
                continue
            screened.append(msg)
        # Store only messages that passed the guard
        if screened:
            self._store.set_messages(key, screened)

    def get_messages(self, key: str) -> list[ChatMessage]:
        raw = self._store.get_messages(key)
        if not raw:
            return []
        # Optionally re-screen on read
        return raw

    def add_message(self, key: str, message: ChatMessage, idx: Optional[int] = None) -> None:
        msg_key = f"{self.store_key}.{key}.add"
        payload = message.model_dump() if hasattr(message, "model_dump") else str(message)
        try:
            decision = self.guard.write(msg_key, payload, source="llamaindex")
        except PolicyViolation:
            if self._drop_blocked:
                return
            raise
        if decision == Action.QUARANTINE:
            return
        self._store.add_message(key, message, idx=idx)

    def delete_messages(self, key: str) -> Optional[list[ChatMessage]]:
        msg_key = f"{self.store_key}.{key}"
        try:
            self.guard.delete(msg_key)
        except PolicyViolation:
            pass
        return self._store.delete_messages(key)

    def delete_message(self, key: str, idx: int) -> Optional[ChatMessage]:
        msg_key = f"{self.store_key}.{key}.{idx}"
        try:
            self.guard.delete(msg_key)
        except PolicyViolation:
            pass
        return self._store.delete_message(key, idx)

    def delete_last_message(self, key: str) -> Optional[ChatMessage]:
        msgs = self._store.get_messages(key)
        if not msgs:
            return None
        return self.delete_message(key, len(msgs) - 1)

    def get_keys(self) -> list[str]:
        return self._store.get_keys()