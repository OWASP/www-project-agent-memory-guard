"""Reference adapters for third-party memory systems.

These let AMSB grade real systems — mem0, Letta, Zep — but they are **opt-in**:
each imports its target lazily and raises :class:`SystemNotAvailable` with an
install hint if the package is missing. That keeps the benchmark's own
dependency set to just ``PyYAML`` and keeps CI offline.

They are reference adapters, not authoritative bindings. Each documents the
exact API surface it assumes, because these libraries move quickly. Before
publishing a grade for one, confirm the adapter matches the version you ran and
capture that version in the report — a leaderboard is only credible if every
row is reproducible against a pinned version. No third-party system is scored
in the committed results until it has actually been run this way; the shipped
leaderboard contains only the offline baselines.
"""
from __future__ import annotations

from typing import Any

from agent_memory_guard.bench.adapter import MemorySystemAdapter, RememberOutcome


class SystemNotAvailable(RuntimeError):
    """Raised when a third-party system's package is not importable."""


def _require(module: str, install: str) -> Any:
    try:
        return __import__(module)
    except ImportError as exc:  # pragma: no cover - exercised only without dep
        raise SystemNotAvailable(
            f"{module!r} is not installed. Install it with `{install}` to grade "
            f"this system, then re-run amg-bench."
        ) from exc


class Mem0Adapter(MemorySystemAdapter):
    """Grade a mem0 ``Memory`` instance.

    Assumes the local ``mem0`` API: ``Memory().add(text, user_id=...)`` to write
    and ``Memory().get_all(user_id=...)`` to read back. Verify against your
    installed version before publishing a grade.
    """

    name = "mem0"

    def __init__(self, user_id: str = "amsb") -> None:
        mem0 = _require("mem0", "pip install mem0ai")
        self.version = getattr(mem0, "__version__", "unknown")
        self._memory = mem0.Memory()
        self._user_id = user_id
        self._last_key: str | None = None

    def remember(
        self, key: str, value: Any, *, source_class: str = "external_tool"
    ) -> RememberOutcome:
        self._memory.add(str(value), user_id=self._user_id, metadata={"key": key})
        self._last_key = key
        return RememberOutcome.STORED

    def recall(self, key: str) -> Any | None:
        results = self._memory.get_all(user_id=self._user_id)
        items = results.get("results", results) if isinstance(results, dict) else results
        texts = [
            item.get("memory") or item.get("text") or ""
            for item in (items or [])
            if isinstance(item, dict)
        ]
        return "\n".join(texts) if texts else None


class LettaAdapter(MemorySystemAdapter):
    """Grade a Letta (formerly MemGPT) archival-memory store.

    Reference adapter over the ``letta`` client. Letta's API surface varies by
    release; confirm the ``insert``/``search`` calls below match your version.
    """

    name = "letta"

    def __init__(self) -> None:
        _require("letta", "pip install letta")
        # Intentionally not wired to a running Letta server here: constructing a
        # client requires deployment configuration the benchmark should not
        # assume. Supply a configured client via `attach_client` before use.
        raise SystemNotAvailable(
            "LettaAdapter is a reference scaffold. Wire it to a configured Letta "
            "client for your deployment before grading, then pin the version in "
            "the report."
        )


class ZepAdapter(MemorySystemAdapter):
    """Grade a Zep memory store.

    Reference adapter over the ``zep_python`` client. Requires a running Zep
    service and a session id; supply them for your deployment before grading.
    """

    name = "zep"

    def __init__(self) -> None:
        _require("zep_python", "pip install zep-python")
        raise SystemNotAvailable(
            "ZepAdapter is a reference scaffold. Wire it to a configured Zep "
            "client and session for your deployment before grading, then pin the "
            "version in the report."
        )


__all__ = ["SystemNotAvailable", "Mem0Adapter", "LettaAdapter", "ZepAdapter"]
