"""Who is acting: principal ids, the acting context, and agent handles.

A *principal* is an agent named by a string id. The id is all a caller can
state; roles come only from the policy's ``principals`` registry.

Identity reaches the guard in one of three ways, and the first one that is set
wins outright:

1. explicitly, with ``principal=`` or through an :class:`AgentHandle`;
2. ambiently, inside ``with guard.as_agent("id"):``. The ambient identity is
   bound to the guard that issued the handle, and every other guard ignores it.
   It covers the code that runs inside the block and the functions it calls,
   and is inherited by threads (through ``contextvars.copy_context()``) and
   asyncio tasks started there. It does not reach code that runs while the
   block is paused at a ``yield``: a generator's caller keeps its own identity;
3. otherwise the caller is anonymous.

In-process identity is asserted by the code that calls the guard. It is not
authentication: hand agents and tools an :class:`AgentHandle`, never the raw
guard, and never let model output choose the principal.
"""
from __future__ import annotations

import contextvars
import re
import sys
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from types import FrameType
from typing import TYPE_CHECKING, Any

from agent_memory_guard.trace import TraceStep

if TYPE_CHECKING:  # pragma: no cover
    from agent_memory_guard.classification import MemoryClass
    from agent_memory_guard.events import Action
    from agent_memory_guard.guard import MemoryGuard
    from agent_memory_guard.policies.access import AccessDecision

ID_PATTERN = r"[A-Za-z0-9_][A-Za-z0-9_-]{0,63}"
_ID_RE = re.compile(ID_PATTERN + r"\Z")


def check_id(pid: Any) -> str:
    """Return ``pid`` if it is a valid principal id, else raise.

    An id is 1-64 characters of ``[A-Za-z0-9_-]`` and cannot start with ``-``.
    It has no dots, so it is always exactly one key segment, and no glob
    characters, so substituting it into a key pattern can never widen it.
    """
    if not isinstance(pid, str):
        raise TypeError(
            f"principal must be a str id, not {type(pid).__name__}; roles come only "
            "from the policy's principals registry, never from the caller"
        )
    text: str = str.__str__(pid)  # the plain string value, whatever a subclass's __str__ says
    if not _ID_RE.match(text):
        raise ValueError(
            f"Invalid principal id {text!r}: use 1-64 characters of [A-Za-z0-9_-], "
            "not starting with '-'"
        )
    return text


def is_valid_id(text: str) -> bool:
    return bool(_ID_RE.match(text))


@dataclass(frozen=True)
class ActingContext:
    """The identity an operation runs as, and how it was established."""

    guard_id: int
    principal: str | None
    via: str  # "explicit" | "handle" | "context" | "anonymous"


class _HandleId(str):
    """A principal id passed by an AgentHandle (marks ``via="handle"``)."""

    __slots__ = ()


# Code flags of frames that can pause mid-block: generators, coroutines and
# async generators (inspect.CO_GENERATOR, CO_COROUTINE, CO_ITERABLE_COROUTINE,
# CO_ASYNC_GENERATOR).
_GENERATOR_FLAGS = 0x20 | 0x100 | 0x200
_COROUTINE_FLAGS = 0x80


class _Entry:
    """One active ``with handle:`` block.

    ``anchor`` is the innermost frame at or above the block that can pause (a
    generator or coroutine), or None if the block runs in plain functions all the
    way down. While the anchor is paused, the block is paused too, so its identity
    must not apply to whatever runs in the meantime.
    """

    __slots__ = ("handle", "ctx", "anchor", "kind", "thread", "task")

    def __init__(self, handle: AgentHandle, ctx: ActingContext, anchor: FrameType | None) -> None:
        self.handle = handle
        self.ctx = ctx
        self.anchor = anchor  # cleared when the block exits
        if anchor is None:
            self.kind = "plain"
        elif anchor.f_code.co_flags & _GENERATOR_FLAGS:
            self.kind = "generator"
        else:
            self.kind = "coroutine"
        self.thread = threading.get_ident()
        self.task = _current_task()


# guard id -> active blocks, oldest first. Replaced, never mutated in place.
_AMBIENT: contextvars.ContextVar[Mapping[int, tuple[_Entry, ...]]] = contextvars.ContextVar(
    "amg_ambient", default={}
)


def _current_task() -> object | None:
    asyncio = sys.modules.get("asyncio")
    if asyncio is None:
        return None
    try:
        task: object | None = asyncio.current_task()
    except RuntimeError:  # no running event loop
        return None
    return task


def _is_context_manager_machinery(frame: FrameType) -> bool:
    """contextlib frames, and @contextmanager generators that contextlib is driving."""
    if frame.f_globals.get("__name__") == "contextlib":
        return True
    back = frame.f_back
    return bool(
        frame.f_code.co_flags & (_GENERATOR_FLAGS | _COROUTINE_FLAGS)
        and back is not None
        and back.f_globals.get("__name__") == "contextlib"
    )


def _anchor(frame: FrameType | None) -> FrameType | None:
    """The frame whose pausing would pause a ``with`` block entered from ``frame``."""
    # A block entered through @contextmanager or ExitStack belongs to the code
    # that wrote the outer `with`, not to contextlib.
    while frame is not None and _is_context_manager_machinery(frame):
        frame = frame.f_back
    while frame is not None:
        if frame.f_code.co_flags & (_GENERATOR_FLAGS | _COROUTINE_FLAGS):
            return frame
        frame = frame.f_back
    return None


def ambient_for(guard_id: int) -> ActingContext | None:
    """The identity of the innermost running ``with handle:`` block for this guard."""
    entries = _AMBIENT.get().get(guard_id)
    if not entries:
        return None
    if len(entries) == 1 and entries[0].kind == "plain":
        return entries[0].ctx  # the usual synchronous case
    thread, task = threading.get_ident(), _current_task()
    running: list[_Entry] = []
    fallback: _Entry | None = None
    for entry in entries:  # oldest first, so newer entries win ties
        anchor = entry.anchor
        if entry.kind == "plain":
            fallback = entry
        elif anchor is not None and entry.thread == thread and entry.task is task:
            # A paused generator or coroutine has no f_back: its block is paused
            # too, and its identity stays with it.
            if anchor.f_back is not None:
                running.append(entry)
        elif entry.kind == "coroutine":
            fallback = entry  # inherited from the thread or task that started this one
        # A generator's block is never inherited: the context may have been
        # copied while the generator was paused.
    if len(running) == 1 and running[0].kind == "coroutine":
        return running[0].ctx  # a running coroutine of this task is on this stack
    if running:
        # Pick the innermost block whose anchor is on this thread's stack.
        anchors = {id(e.anchor): e for e in running}
        frame: FrameType | None = sys._getframe(1)
        while frame is not None:
            hit = anchors.get(id(frame))
            if hit is not None and hit.anchor is frame:
                return hit.ctx
            frame = frame.f_back
    return fallback.ctx if fallback is not None else None


class _OpState:
    """Per-operation state: who is acting, and the trace being recorded."""

    __slots__ = ("guard_id", "ctx", "steps")

    def __init__(self, guard_id: int, ctx: ActingContext, steps: list[TraceStep] | None) -> None:
        self.guard_id = guard_id
        self.ctx = ctx
        self.steps = steps


_OP: contextvars.ContextVar[_OpState | None] = contextvars.ContextVar("amg_op", default=None)
# guard id -> steps of that guard's last traced operation in this context.
_LAST_TRACE: contextvars.ContextVar[Mapping[int, tuple[TraceStep, ...]]] = (
    contextvars.ContextVar("amg_last_trace", default={})
)


class AgentHandle:
    """A guard bound to one agent. Give this to agent and tool code.

    Every call runs as the bound principal, and ``principal=`` cannot be passed
    to override it. Used as a context manager it also makes the agent the
    ambient identity for *this guard only*, so unmodified adapter code that
    calls ``guard.write(...)`` inside the block is attributed to the agent.

    A handle does not expose the guard's event log, quarantine, snapshots or
    classification registry; those stay with whoever holds the raw guard. Its
    ``snapshot()`` and ``rollback()`` return only a snapshot id, never the data.
    """

    __slots__ = ("_guard", "_pid")

    def __init__(self, guard: MemoryGuard, principal: str) -> None:
        self._guard = guard
        self._pid = _HandleId(check_id(principal))

    @property
    def principal(self) -> str:
        return str(self._pid)

    def __repr__(self) -> str:
        return f"AgentHandle({self.principal!r})"

    def _no_override(self, kw: dict[str, Any]) -> None:
        if "principal" in kw:
            raise TypeError(
                f"AgentHandle is bound to {self.principal!r}; principal= is not accepted"
            )

    def write(self, key: str, value: Any, **kw: Any) -> Action:
        self._no_override(kw)
        return self._guard.write(key, value, principal=self._pid, **kw)

    def read(self, key: str, default: Any = None, **kw: Any) -> Any:
        self._no_override(kw)
        return self._guard.read(key, default, principal=self._pid, **kw)

    def delete(self, key: str) -> None:
        self._guard.delete(key, principal=self._pid)

    def promote(self, key: str, target: MemoryClass, **kw: Any) -> None:
        self._no_override(kw)
        self._guard.promote(key, target, principal=self._pid, **kw)

    def snapshot(self, label: str = "manual") -> str:
        """Take a snapshot (admins only) and return its id."""
        return self._guard.snapshot(label, principal=self._pid).snapshot_id

    def rollback(self, snapshot_id: str | None = None) -> str:
        """Roll back to a snapshot (admins only) and return its id."""
        return self._guard.rollback(snapshot_id, principal=self._pid).snapshot_id

    def explain(self, operation: str, key: str, **kw: Any) -> AccessDecision:
        """Dry-run an operation as this agent. Shows only the deciding rule."""
        self._no_override(kw)
        return self._guard.explain(operation, key, principal=self._pid, **kw)

    def __enter__(self) -> AgentHandle:
        gid = self._guard._guard_id
        entry = _Entry(self, ActingContext(gid, self.principal, "context"), _anchor(sys._getframe(1)))
        current = _AMBIENT.get()
        _AMBIENT.set({**current, gid: (*current.get(gid, ()), entry)})
        return self

    def __exit__(self, *exc: Any) -> None:
        # Remove this block's own entry, wherever it is: blocks paused in
        # generators or tasks can exit in any order.
        gid = self._guard._guard_id
        current = _AMBIENT.get()
        entries = current.get(gid, ())
        anchor = _anchor(sys._getframe(1))
        thread, task = threading.get_ident(), _current_task()
        mine = [i for i, e in enumerate(entries) if e.handle is self]
        exact = [i for i in mine if entries[i].anchor is anchor]
        here = [i for i in mine if entries[i].thread == thread and entries[i].task is task]
        candidates = exact or here or mine
        if not candidates:
            raise RuntimeError(f"{self!r} exited a with block it did not enter in this context")
        index = candidates[-1]
        entries[index].anchor = None  # drop the frame reference
        rest = entries[:index] + entries[index + 1:]
        updated = {k: v for k, v in current.items() if k != gid}
        if rest:
            updated[gid] = rest
        _AMBIENT.set(updated)


__all__ = ["ActingContext", "AgentHandle", "check_id"]
