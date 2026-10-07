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
   caller keeps its own identity. A ``with`` statement in an ordinary function
   belongs to that function, wherever it is called from. Tasks and threads
   started while a generator holds a block open in the same context start
   anonymous, because the guard cannot tell whether the generator or its caller
   started them;
3. otherwise the caller is anonymous.

In-process identity is asserted by the code that calls the guard. It is not
authentication: hand agents and tools an :class:`AgentHandle`, never the raw
guard, and never let model output choose the principal.
"""
from __future__ import annotations

import contextlib
import contextvars
import gc
import itertools
import opcode
import re
import sys
import threading
import weakref
from collections.abc import Callable, Mapping
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
_CO_GENERATOR = 0x20
_GENERATOR_FLAGS = _CO_GENERATOR | 0x100 | 0x200
_COROUTINE_FLAGS = 0x80
_PAUSABLE_FLAGS = _GENERATOR_FLAGS | _COROUTINE_FLAGS

_TaskRef = Callable[[], object]
_SEQ = itertools.count()  # orders blocks by when they started


def _task_ref(task: object | None) -> _TaskRef | None:
    """A weak reference to ``task``, so an open block does not keep its task alive."""
    if task is None:
        return None
    try:
        return weakref.ref(task)
    except TypeError:  # a task type without weak references
        return lambda: task


def _same_task(ref: _TaskRef | None, task: object | None) -> bool:
    if ref is None:
        return task is None
    return task is not None and ref() is task


class _Entry:
    """One active ``with handle:`` block.

    ``anchor`` is the frame the block is registered under in ``_BY_ANCHOR``:
    the innermost frame at or above the block that can pause (a generator or
    coroutine), or, for a ``with`` statement in an ordinary function nested
    inside such a block, that function's frame. It is None for blocks that need
    no registering. While a generator or coroutine anchor is paused, the block
    is paused too, so its identity must not apply to whatever runs meanwhile.
    """

    __slots__ = (
        "handle", "ctx", "anchor", "key", "owner", "kind", "thread", "task", "closed", "seq"
    )

    def __init__(
        self,
        handle: AgentHandle,
        ctx: ActingContext,
        anchor: FrameType | None,
        kind: str,
        owner: FrameType | None = None,
    ) -> None:
        self.handle = handle
        self.ctx = ctx
        self.anchor = anchor  # cleared when the block exits
        self.key = None if anchor is None else id(anchor)  # its _BY_ANCHOR key
        # The ordinary function whose ``with`` statement holds the block, if any.
        self.owner = owner
        self.kind = kind  # "plain" | "generator" | "coroutine"
        # Set when the block can no longer apply anywhere, including in copies of
        # the context that child tasks and threads hold.
        self.closed = False
        self.thread = threading.get_ident()
        self.task = _task_ref(_current_task())
        self.seq = next(_SEQ)


def _kind(anchor: FrameType | None) -> str:
    if anchor is None:
        return "plain"
    return "generator" if anchor.f_code.co_flags & _GENERATOR_FLAGS else "coroutine"


# guard id -> active blocks, oldest first. Replaced, never mutated in place.
_AMBIENT: contextvars.ContextVar[Mapping[int, tuple[_Entry, ...]]] = contextvars.ContextVar(
    "amg_ambient", default={}
)

# Open blocks registered under a frame (see _Entry.anchor), by id(frame), and
# every open block by id(handle), for the whole process. A generator can be
# resumed, and its block exited, in a context other than the one that entered
# it; these let the guard find the block from its frame wherever that happens.
# Values are replaced, never mutated in place, so readers need no lock.
_LOCK = threading.Lock()
_BY_ANCHOR: dict[int, tuple[_Entry, ...]] = {}
_BY_HANDLE: dict[int, tuple[_Entry, ...]] = {}
# guard id -> number of open blocks in _BY_ANCHOR, so other guards skip the stack walk.
_ANCHORED: dict[int, int] = {}


class _ThreadState(threading.local):
    # True while this thread runs a garbage collection. The collector finalizes
    # paused generators and coroutines at whatever point it was triggered, which
    # can be inside the bookkeeping below.
    gc = False
    # True while this thread holds _LOCK or is setting _AMBIENT.
    busy = False


_STATE = _ThreadState()
# Blocks ended by a finalizer while it was not safe to take _LOCK or set the
# context. They are marked closed at once, and taken out of the registry by the
# next block that starts or ends safely.
_DEFERRED: list[_Entry] = []


def _on_gc(phase: str, info: Mapping[str, Any]) -> None:
    _STATE.gc = phase == "start"


# Installed at import, so that even the first block a program opens can tell
# whether the garbage collector is running.
if _on_gc not in gc.callbacks:
    gc.callbacks.append(_on_gc)


def _unsafe() -> bool:
    """True if a finalizer running now may have interrupted this thread mid-update."""
    state = _STATE
    return state.gc or state.busy


def _set_ambient(value: Mapping[int, tuple[_Entry, ...]]) -> None:
    state = _STATE
    state.busy = True
    try:
        _AMBIENT.set(value)
    finally:
        state.busy = False


def _register(entry: _Entry) -> None:
    state = _STATE
    state.busy = True
    try:
        with _LOCK:
            hid = id(entry.handle)
            _BY_HANDLE[hid] = (*_BY_HANDLE.get(hid, ()), entry)
            if entry.key is not None:
                _BY_ANCHOR[entry.key] = (*_BY_ANCHOR.get(entry.key, ()), entry)
                gid = entry.ctx.guard_id
                _ANCHORED[gid] = _ANCHORED.get(gid, 0) + 1
    finally:
        state.busy = False


def _close(entry: _Entry, *, revoke: bool = False) -> None:
    """End a block. ``revoke`` also ends it in copies of the context."""
    state = _STATE
    state.busy = True
    try:
        with _LOCK:
            # A generator's block is never inherited, so once it ends it must not
            # make child contexts fail closed either.
            if revoke or entry.kind == "generator":
                entry.closed = True
            tables = [(_BY_HANDLE, id(entry.handle))]
            if entry.key is not None:
                tables.append((_BY_ANCHOR, entry.key))
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
            entry.anchor = entry.owner = None  # drop the frame references
    finally:
        state.busy = False


def _drain_deferred() -> None:
    while _DEFERRED:
        try:
            entry = _DEFERRED.pop()
        except IndexError:  # another thread took the last one
            return
        _close(entry, revoke=True)


def _prune(guard_id: int) -> None:
    """Drop ended blocks from this context's entries for one guard."""
    if _unsafe():
        return
    current = _AMBIENT.get()
    live = tuple(e for e in current.get(guard_id, ()) if not e.closed)
    updated = {k: v for k, v in current.items() if k != guard_id}
    if live:
        updated[guard_id] = live
    _set_ambient(updated)


def _open_on_stack(guard_id: int, frame: FrameType | None) -> _Entry | None:
    """The running block of this guard whose anchor frame is on this stack.

    That is the newest open block registered under the frames from here up to
    and including the innermost generator or coroutine that has one. A block a
    generator holds applies while that generator runs, however old it is, but
    below it the newest block wins, wherever it is registered: a block entered
    through ExitStack is registered under the generator, not the function that
    entered it.
    """
    by_anchor = _BY_ANCHOR
    best: _Entry | None = None
    while frame is not None:
        entries = by_anchor.get(id(frame))
        if entries:
            for entry in reversed(entries):
                if entry.anchor is frame and entry.ctx.guard_id == guard_id and not entry.closed:
                    if best is None or entry.seq > best.seq:
                        best = entry
                    break
        if best is not None and frame.f_code.co_flags & _PAUSABLE_FLAGS:
            return best
        frame = frame.f_back
    return best


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
        if frame.f_code.co_flags & _PAUSABLE_FLAGS:
            return frame
        frame = frame.f_back
    return None


def _past_machinery(frame: FrameType | None) -> FrameType | None:
    while frame is not None and _is_context_manager_machinery(frame):
        frame = frame.f_back
    return frame


# What a frame is executing while it calls __enter__ for its own `with`
# statement: SETUP_WITH (3.9-3.10), BEFORE_WITH (3.11-3.13), or from 3.14 a
# CALL with no arguments right after LOAD_SPECIAL 0 (__enter__).
_OPMAP = opcode.opmap
_EXTENDED_ARG = _OPMAP["EXTENDED_ARG"]
_WITH_ENTRY_OPS = frozenset(_OPMAP[name] for name in ("SETUP_WITH", "BEFORE_WITH") if name in _OPMAP)
_CALL = _OPMAP.get("CALL", -1)
_LOAD_SPECIAL = _OPMAP.get("LOAD_SPECIAL", -1)
_GCM_ENTER = contextlib._GeneratorContextManager.__enter__.__code__


def _runs_with_statement(frame: FrameType) -> bool:
    """True if ``frame`` is calling ``__enter__`` for a ``with`` statement of its own."""
    code = frame.f_code.co_code
    i = frame.f_lasti
    if i < 0:
        return False
    try:
        while code[i] == _EXTENDED_ARG:
            i += 2
        if code[i] in _WITH_ENTRY_OPS:
            return True
        return (
            code[i] == _CALL and code[i + 1] == 0
            and i >= 2 and code[i - 2] == _LOAD_SPECIAL and code[i - 1] == 0
        )
    except IndexError:
        return False


def _with_owner(caller: FrameType) -> FrameType | None:
    """The ordinary function whose own ``with`` statement is entering a block.

    Such a block starts and ends inside that function's frame, which cannot
    pause, so the block is never paused either, whatever is further up the
    stack. The ``with`` may name the handle, or a @contextmanager whose own
    ``with`` enters it (at any depth). Returns None if any step on the way is
    not a ``with`` statement (ExitStack, an explicit ``__enter__()`` call) or
    the ``with`` is in a generator or coroutine: those blocks can be held open
    across a ``yield``.
    """
    frame = caller
    while True:
        code = frame.f_code
        if code.co_flags & _PAUSABLE_FLAGS:
            # Only a @contextmanager generator entered by its caller's `with`,
            # entering the block with a `with` of its own.
            back = frame.f_back
            if (
                back is None
                or back.f_code is not _GCM_ENTER
                or not code.co_flags & _CO_GENERATOR
                or not _runs_with_statement(frame)
            ):
                return None
            next_frame = back.f_back
            if next_frame is None:
                return None
            frame = next_frame
            continue
        if _is_context_manager_machinery(frame):
            return None
        return frame if _runs_with_statement(frame) else None


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
    ambiguous = stale = False
    for entry in entries:  # oldest first, so newer entries win
        if entry.closed:
            stale = True
            continue
        if entry.kind == "plain":
            fallback = entry
        elif entry.thread == thread and _same_task(entry.task, task):
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
    if stale:
        _prune(guard_id)
    if ambiguous or fallback is None:
        return None
    return fallback.ctx


class _OpState:
    """Per-operation state: who is acting, and the trace being recorded."""

    __slots__ = ("guard_id", "ctx", "steps", "per_event", "checked", "shown")

    def __init__(
        self,
        guard_id: int,
        ctx: ActingContext,
        steps: list[TraceStep] | None,
        per_event: bool = False,
    ) -> None:
        self.guard_id = guard_id
        self.ctx = ctx
        self.steps = steps
        self.per_event = per_event  # give each event only its own steps (retire_if)
        self.checked = 0  # steps up to and including the access check
        self.shown = 0  # steps already given to an earlier event of this operation

    def mark_checked(self) -> None:
        if self.steps is not None:
            self.checked = len(self.steps)

    def event_steps(self) -> list[TraceStep]:
        """The steps an event carries: all steps so far, or for ``per_event``
        operations the opening steps, then those since the last event.

        ``retire_if`` logs an event per retired key, and would otherwise copy
        its whole growing trace into each one.
        """
        steps = self.steps or []
        if not self.per_event:
            return list(steps)
        start = max(self.checked, self.shown)
        self.shown = len(steps)
        return steps if start <= self.checked else steps[:self.checked] + steps[start:]


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
        if _unsafe():
            raise RuntimeError(
                f"{self!r} cannot start a with block in code that runs during garbage "
                "collection, such as the finally block of a stream the collector closes; "
                "call the handle's methods there instead"
            )
        if _DEFERRED:
            _drain_deferred()
        gid = self._guard._guard_id
        ctx = ActingContext(gid, self.principal, "context")
        caller = sys._getframe(1)
        owner = _with_owner(caller)
        if owner is not None:
            # Registered under its own frame only when it sits inside a block that
            # is found by frame, so that it wins over that outer block.
            nested = gid in _ANCHORED and _open_on_stack(gid, owner) is not None
            entry = _Entry(self, ctx, owner if nested else None, "plain", owner)
        else:
            anchor = _anchor(caller)
            entry = _Entry(self, ctx, anchor, _kind(anchor))
        current = _AMBIENT.get()
        live = tuple(e for e in current.get(gid, ()) if not e.closed)
        _set_ambient({**current, gid: (*live, entry)})
        _register(entry)
        return self

    def __exit__(self, *exc: Any) -> None:
        caller = sys._getframe(1)
        if _unsafe():
            # Run by a finalizer during garbage collection, or while this thread
            # was updating the registry: taking _LOCK or setting the context here
            # could deadlock or crash, so end the block and tidy up later.
            self._end_later(caller)
            return
        if _DEFERRED:
            _drain_deferred()
        # Remove this block's own entry, wherever it is: blocks paused in
        # generators or tasks can exit in any order.
        gid = self._guard._guard_id
        current = _AMBIENT.get()
        entries = current.get(gid, ())
        mine = [i for i, e in enumerate(entries) if e.handle is self and not e.closed]
        owner = _past_machinery(caller)
        candidates = [i for i in mine if owner is not None and entries[i].owner is owner]
        anchor = _anchor(caller)
        if not candidates:
            thread, task = threading.get_ident(), _current_task()
            here = [
                i for i in mine
                if entries[i].thread == thread and _same_task(entries[i].task, task)
            ]
            if anchor is not None:
                exact = [i for i in mine if entries[i].anchor is anchor]
                if not exact and self._end_by_frame(anchor):
                    return  # never fall back to another block of this thread
            else:  # a block in plain functions: never a paused generator's block
                exact = [i for i in here if entries[i].kind == "plain" and entries[i].owner is None]
            candidates = exact or here
        if candidates:
            index = candidates[-1]
            _close(entries[index])
            rest = tuple(e for i, e in enumerate(entries) if i != index and not e.closed)
            updated = {k: v for k, v in current.items() if k != gid}
            if rest:
                updated[gid] = rest
            _set_ambient(updated)
            return
        # Exited from a thread or task that did not enter it. Revoke the block so
        # it stops applying in the context that entered it, then report the misuse.
        if mine:
            _close(entries[mine[-1]], revoke=True)
        else:
            open_blocks = [e for e in _BY_HANDLE.get(id(self), ()) if not e.closed]
            if len(open_blocks) == 1:
                _close(open_blocks[0], revoke=True)
        raise RuntimeError(
            f"{self!r} exited a with block it did not enter in this thread or task; "
            "the block has been ended everywhere"
        )

    def _end_by_frame(self, anchor: FrameType) -> bool:
        """End this handle's block registered under ``anchor``, if there is one.

        That is a generator's block that was resumed, and is ending, in another
        thread, task or context. The entering context's copy is now stale, so
        it is ended there too.
        """
        found = [
            e for e in _BY_ANCHOR.get(id(anchor), ())
            if e.handle is self and e.anchor is anchor and not e.closed
        ]
        if not found:
            return False
        _close(found[-1], revoke=True)
        return True

    def _end_later(self, caller: FrameType) -> None:
        """End this handle's block without taking _LOCK or setting the context."""
        found = None
        anchor = _anchor(caller)
        if anchor is not None:
            found = next(
                (
                    e for e in reversed(_BY_ANCHOR.get(id(anchor), ()))
                    if e.handle is self and e.anchor is anchor and not e.closed
                ),
                None,
            )
        blocks = _BY_HANDLE.get(id(self), ())
        owner = _past_machinery(caller)
        if found is None and owner is not None:
            found = next((e for e in reversed(blocks) if e.owner is owner and not e.closed), None)
        if found is None:
            open_blocks = [e for e in blocks if not e.closed]
            if len(open_blocks) == 1:
                found = open_blocks[0]
        if found is not None:
            found.closed = True
            found.anchor = found.owner = None
            _DEFERRED.append(found)


__all__ = ["ActingContext", "AgentHandle", "check_id"]
