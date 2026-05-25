"""LangChain drop-in: a chat message history guarded by MemoryGuard.

Usable with `langchain_core.chat_history.BaseChatMessageHistory` if installed,
otherwise as a standalone object exposing the same minimal contract.
"""
from __future__ import annotations

from typing import Any

from agent_memory_guard.events import Action
from agent_memory_guard.exceptions import PolicyViolation
from agent_memory_guard.guard import MemoryGuard

try:  # pragma: no cover - optional dependency
    from langchain_core.chat_history import BaseChatMessageHistory  # type: ignore
    from langchain_core.messages import (  # type: ignore
        BaseMessage,
        messages_from_dict,
        messages_to_dict,
    )

    _HAS_LANGCHAIN = True
except Exception:  # pragma: no cover - optional dependency
    BaseChatMessageHistory = object  # type: ignore[assignment, misc, unused-ignore]
    BaseMessage = Any  # type: ignore[assignment, misc, unused-ignore]
    _HAS_LANGCHAIN = False

    def messages_from_dict(d: list[dict[str, Any]]) -> list[Any]:  # type: ignore[no-redef, unused-ignore]
        return list(d)

    def messages_to_dict(m: list[Any]) -> list[dict[str, Any]]:  # type: ignore[no-redef, unused-ignore]
        return list(m)


class GuardedChatMessageHistory(BaseChatMessageHistory):  # type: ignore[misc, valid-type, unused-ignore]
    """Chat history whose messages are screened by a MemoryGuard before storage.

    Each message is written under the key ``messages.<session_id>.<index>``,
    so injection / leakage / size / churn detectors apply per-message.
    """

    def __init__(
        self,
        session_id: str,
        guard: MemoryGuard | None = None,
        *,
        drop_blocked: bool = True,
    ) -> None:
        self.session_id = session_id
        self.guard = guard or MemoryGuard()
        self._drop_blocked = drop_blocked
        self._index_key = f"messages.{session_id}.__count__"
        if self._index_key not in [k for k, _ in self._iter_store()]:
            self.guard.write(self._index_key, 0, source="langchain")

    @property
    def messages(self) -> list[Any]:
        count = self.guard.read(self._index_key, 0, sink="langchain") or 0
        out: list[Any] = []
        for i in range(int(count)):
            key = f"messages.{self.session_id}.{i}"
            try:
                raw = self.guard.read(key, sink="langchain")
            except PolicyViolation:
                continue
            if raw is None:
                continue
            out.extend(messages_from_dict([raw]))
        return out

    def add_message(self, message: Any) -> None:
        count = int(self.guard.read(self._index_key, 0, sink="langchain") or 0)
        key = f"messages.{self.session_id}.{count}"
        payload = messages_to_dict([message])[0]
        try:
            decision = self.guard.write(key, payload, source="langchain")
        except PolicyViolation:
            if self._drop_blocked:
                return
            raise
        if decision == Action.QUARANTINE:
            return
        self.guard.write(self._index_key, count + 1, source="langchain")

    def clear(self) -> None:
        count = int(self.guard.read(self._index_key, 0, sink="langchain") or 0)
        for i in range(count):
            try:
                self.guard.delete(f"messages.{self.session_id}.{i}")
            except PolicyViolation:
                pass
        self.guard.write(self._index_key, 0, source="langchain")

    def _iter_store(self) -> list[tuple[str, Any]]:
        store = self.guard._store  # noqa: SLF001 - intentional internal access
        return list(store.items())
