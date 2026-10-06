"""Who is acting: principal ids, the acting context, and agent handles.

A *principal* is an agent named by a string id. The id is all a caller can
state; roles come only from the policy's ``principals`` registry.

Identity reaches the guard in one of three ways, and the first one that is set
wins outright:

1. explicitly, with ``principal=`` or through an :class:`AgentHandle`;
2. ambiently, inside ``with guard.as_agent("id"):``. The ambient identity is
   bound to the guard that issued the handle, and every other guard ignores it.
   It covers the code that runs inside the block and the functions it calls,
   wherever that code is resumed, and is inherited by threads (through
   ``contextvars.copy_context()``) and asyncio tasks started there. It does not
   reach code that runs while the block is paused at a ``yield``: a generator's
   caller keeps its own identity. Tasks and threads started while a generator
   holds a block open in the same context start anonymous, because the guard
   cannot tell whether the generator or its caller started them;
3. otherwise the caller is anonymous.

In-process identity is asserted by the code that calls the guard. It is not
authentication: hand agents and tools an :class:`AgentHandle`, never the raw
guard, and never let model output choose the principal.
"""
from __future__ import annotations

import contextlib
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

    __slots__ = ("handle", "ctx", "anchor", "kind", "thread", "task", "closed")

    def __init__(self, handle: AgentHandle, ctx: ActingContext, anchor: FrameType | None) -> None:
        self.handle = handle
        self.ctx = ctx
        self.anchor = anchor  # cleared when the block exits
        # Set when the block can no longer apply anywhere, including in copies of
        # the context that child tasks and threads hold.
        self.closed = False
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

# Open blocks whose anchor can pause, by id(anchor frame), and every open block
# by id(handle), for the whole process. A generator can be resumed, and its
# block exited, in a context other than the one that entered it; these let the
# guard find the block from its frame wherever that happens. Values are
# replaced, never mutated in place, so readers need no lock.
_LOCK = threading.Lock()
_BY_ANCHOR: dict[int, tuple[_Entry, ...]] = {}
_BY_HANDLE: dict[int, tuple[_Entry, ...]] = {}
# guard id -> number of open blocks in _BY_ANCHOR, so other guards skip the stack walk.
_ANCHORED: dict[int, int] = {}


def _register(entry: _Entry) -> None:
    with _LOCK:
        hid = id(entry.handle)
        _BY_HANDLE[hid] = (*_BY_HANDLE.get(hid, ()), entry)
        if entry.anchor is not None:
            aid = id(entry.anchor)
            _BY_ANCHOR[aid] = (*_BY_ANCHOR.get(aid, ()), entry)
            gid = entry.ctx.guard_id
            _ANCHORED[gid] = _ANCHORED.get(gid, 0) + 1


def _close(entry: _Entry, *, revoke: bool = False) -> None:
    """End a block. ``revoke`` also ends it in copies of the context."""
    with _LOCK:
        # A generator's block is never inherited, so once it ends it must not
        # make child contexts fail closed either.
        if revoke or entry.kind == "generator":
            entry.closed = True
        tables = [(_BY_HANDLE, id(entry.handle))]
        if entry.anchor is not None:
            tables.append((_BY_ANCHOR, id(entry.anchor)))
        for table, key in tables:
            before = table.get(key, ())
            rest = tuple(e for e in before if e is not entry)
            if rest:
                table[key] = rest
            else:
                table.pop(key, None)
            if table is _BY_ANCHOR and len(rest) < len(before):
                gid = entry.ctx.guard_id
                left = _ANCHORED.get(gid, 1) - 1
                if left > 0:
                    _ANCHORED[gid] = left
                else:
                    _ANCHORED.pop(gid, None)
        entry.anchor = None  # drop the frame reference


def _open_on_stack(guard_id: int, frame: FrameType | None) -> _Entry | None:
    """The innermost open block of this guard whose anchor frame is on this stack."""
    by_anchor = _BY_ANCHOR
    while frame is not None:
        entries = by_anchor.get(id(frame))
        if entries:
            for entry in reversed(entries):
                if entry.anchor is frame and entry.ctx.guard_id == guard_id and not entry.closed:
                    return entry
        frame = frame.f_back
    return None


def _current_task() -> object | None:
    asyncio = sys.modules.get("asyncio")
    if asyncio is None:
        return None
    try:
        task: object | None = asyncio.current_task()
    except RuntimeError:  # no running event loop
        return None
    return task


# The code of the contextlib methods that run a @contextmanager or
# @asynccontextmanager generator as a context manager.
_CM_DRIVERS = frozenset(
    method.__code__
    for method in (
        contextlib._GeneratorContextManager.__enter__,
        contextlib._GeneratorContextManager.__exit__,
        contextlib._AsyncGeneratorContextManager.__aenter__,
        contextlib._AsyncGeneratorContextManager.__aexit__,
    )
)


def _is_context_manager_machinery(frame: FrameType) -> bool:
    """Frames whose ``with`` blocks belong to their caller.

    These are contextlib's own frames, @contextmanager generators while
    contextlib is entering or exiting them, and ``__aenter__``/``__aexit__``
    coroutines, which pause together with the coroutine that awaits them.
    """
    if frame.f_globals.get("__name__") == "contextlib":
        return True
    code = frame.f_code
    if code.co_flags & _COROUTINE_FLAGS and code.co_name in ("__aenter__", "__aexit__"):
        return True
    back = frame.f_back
    return bool(
        code.co_flags & (_GENERATOR_FLAGS | _COROUTINE_FLAGS)
        and back is not None
        and back.f_code in _CM_DRIVERS
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


def ambient_identity_possible(guard_id: int) -> bool:
    """Cheap check: could a ``with handle:`` block of this guard apply here?"""
    return bool(_AMBIENT.get() or guard_id in _ANCHORED)


def ambient_for(guard_id: int) -> ActingContext | None:
    """The identity of the innermost running ``with handle:`` block for this guard."""
    # A block whose own generator or coroutine frame is on this stack applies,
    # whichever thread, task or context resumed that frame.
    if guard_id in _ANCHORED:
        hit = _open_on_stack(guard_id, sys._getframe(1))
        if hit is not None:
            return hit.ctx
    entries = _AMBIENT.get().get(guard_id)
    if not entries:
        return None
    if len(entries) == 1 and entries[0].kind == "plain" and not entries[0].closed:
        return entries[0].ctx  # the usual synchronous case
    thread, task = threading.get_ident(), _current_task()
    fallback: _Entry | None = None
    ambiguous = False
    for entry in entries:  # oldest first, so newer entries win
        if entry.closed:
            continue
        if entry.kind == "plain":
            fallback = entry
        elif entry.thread == thread and entry.task is task:
            # This context's own generator or coroutine block, and its frame is
            # not on this stack: it is paused, and its identity stays with it.
            continue
        elif entry.kind == "coroutine":
            fallback = entry  # inherited from the thread or task that started this one
        else:
            # A generator's block is never inherited. A context copied while one
            # was open may have been copied by the generator itself, inside its
            # block, or by its caller while it was paused; the guard cannot tell
            # which, so the copy gets no identity from this context.
            ambiguous = True
    if ambiguous or fallback is None:
        return None
    return fallback.ctx


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

    def explain(self, operation: str, key: str = "*", **kw: Any) -> AccessDecision:
        """Dry-run an operation as this agent. Shows only the deciding rule."""
        self._no_override(kw)
        return self._guard.explain(operation, key, principal=self._pid, **kw)

    def __enter__(self) -> AgentHandle:
        gid = self._guard._guard_id
        entry = _Entry(self, ActingContext(gid, self.principal, "context"), _anchor(sys._getframe(1)))
        current = _AMBIENT.get()
        _AMBIENT.set({**current, gid: (*current.get(gid, ()), entry)})
        _register(entry)
        return self

    def __exit__(self, *exc: Any) -> None:
        # Remove this block's own entry, wherever it is: blocks paused in
        # generators or tasks can exit in any order.
        gid = self._guard._guard_id
        current = _AMBIENT.get()
        entries = current.get(gid, ())
        anchor = _anchor(sys._getframe(1))
        thread, task = threading.get_ident(), _current_task()
        mine = [i for i, e in enumerate(entries) if e.handle is self and not e.closed]
        here = [i for i in mine if entries[i].thread == thread and entries[i].task is task]
        if anchor is not None:
            exact = [i for i in mine if entries[i].anchor is anchor]
        else:  # a block in plain functions: never a paused generator's block
            exact = [i for i in here if entries[i].kind == "plain"]
        candidates = exact or here
        if candidates:
            index = candidates[-1]
            _close(entries[index])
            rest = entries[:index] + entries[index + 1:]
            updated = {k: v for k, v in current.items() if k != gid}
            if rest:
                updated[gid] = rest
            _AMBIENT.set(updated)
            return
        if anchor is not None:
            # A generator's block that was resumed, and is ending, in another
            # thread, task or context: find it by its frame. The entering
            # context's copy is now stale, so end it there too.
            found = [e for e in _BY_ANCHOR.get(id(anchor), ()) if e.handle is self]
            if found:
                _close(found[-1], revoke=True)
                return
        # Exited from a thread or task that did not enter it. Revoke the block so
        # it stops applying in the context that entered it, then report the misuse.
        if mine:
            _close(entries[mine[-1]], revoke=True)
        else:
            open_blocks = _BY_HANDLE.get(id(self), ())
            if len(open_blocks) == 1:
                _close(open_blocks[0], revoke=True)
        raise RuntimeError(
            f"{self!r} exited a with block it did not enter in this thread or task; "
            "the block has been ended everywhere"
        )


__all__ = ["ActingContext", "AgentHandle", "check_id"]
