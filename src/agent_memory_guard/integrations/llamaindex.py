"""LlamaIndex drop-in: a chat store guarded by MemoryGuard.

Wraps any LlamaIndex ``BaseChatStore`` so that every message insertion is
screened by a MemoryGuard before it reaches the underlying store.
"""
from __future__ import annotations

from typing import Any, ClassVar, cast

from agent_memory_guard.events import Action
from agent_memory_guard.exceptions import PolicyViolation
from agent_memory_guard.guard import MemoryGuard

_HAS_LLAMAINDEX = False
try:  # pragma: no cover - optional dependency
    try:
        # llama-index-core >= 0.10 keeps the chat store base here.
        from llama_index.core.storage.chat_store.base import BaseChatStore  # type: ignore
    except ImportError:
        from llama_index.core.chat_store.types import BaseChatStore  # type: ignore
    from llama_index.core.llms import ChatMessage  # type: ignore
    from pydantic import PrivateAttr

    _HAS_LLAMAINDEX = True
except Exception:  # pragma: no cover - optional dependency
    BaseChatStore = object  # type: ignore[assignment, misc]
    ChatMessage = Any  # type: ignore[assignment, misc]

    def PrivateAttr(default: Any = None) -> Any:  # type: ignore[no-redef]  # noqa: N802
        return default


class GuardedChatStore(BaseChatStore):  # type: ignore[misc, valid-type]
    """A LlamaIndex chat store that passes every message through a MemoryGuard.

    It subclasses LlamaIndex's ``BaseChatStore``, so it can be passed anywhere a
    chat store is expected (for example ``ChatMemoryBuffer.from_defaults``).
    Messages that violate policy can be silently dropped or raise an exception
    depending on *drop_blocked*.
    """

    store_key: ClassVar[str] = "llamaindex_messages"

    # BaseChatStore is a pydantic model, so per-instance state is private.
    _store: Any = PrivateAttr()
    _guard: Any = PrivateAttr()
    _drop_blocked: bool = PrivateAttr(default=True)

    def __init__(
        self,
        store: BaseChatStore,
        guard: MemoryGuard | None = None,
        *,
        drop_blocked: bool = True,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._store = store
        self._guard = guard or MemoryGuard()
        self._drop_blocked = drop_blocked

    @property
    def guard(self) -> MemoryGuard:
        return cast(MemoryGuard, self._guard)

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
        return list(raw)

    def add_message(self, key: str, message: ChatMessage, idx: int | None = None) -> None:
        # One guard key per position: reusing a single key for every message made
        # the rapid-change detector quarantine a long, fast conversation.
        position = idx if idx is not None else len(self._store.get_messages(key) or [])
        msg_key = f"{self.store_key}.{key}.{position}"
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

    def delete_messages(self, key: str) -> list[ChatMessage] | None:
        msg_key = f"{self.store_key}.{key}"
        try:
            self.guard.delete(msg_key)
        except PolicyViolation:
            pass
        return cast("list[ChatMessage] | None", self._store.delete_messages(key))

    def delete_message(self, key: str, idx: int) -> ChatMessage | None:
        msg_key = f"{self.store_key}.{key}.{idx}"
        try:
            self.guard.delete(msg_key)
        except PolicyViolation:
            pass
        return cast("ChatMessage | None", self._store.delete_message(key, idx))

    def delete_last_message(self, key: str) -> ChatMessage | None:
        msgs = self._store.get_messages(key)
        if not msgs:
            return None
        return self.delete_message(key, len(msgs) - 1)

    def get_keys(self) -> list[str]:
        return list(self._store.get_keys())
