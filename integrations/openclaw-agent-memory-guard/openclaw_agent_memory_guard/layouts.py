"""Discover memory files and their default provenance for each agent layout.

OpenClaw (docs: concepts/memory, memory-architecture):
    USER.md, MEMORY.md (or memory.md), users/<id>/USER.md, memory/YYYY-MM-DD.md
    are workspace memory. DREAMS.md and memory/dreaming/, memory/.dreams/ are
    system scaffolding. OpenClaw classifies workspace memory Markdown as
    "agent" unless a recorded artifact provenance says "untrusted"; the
    recorded provenance lives in OpenClaw's plugin-state store and is not
    read here yet, so this adapter uses the path default and lets the caller
    override per file (see ``provenance_overrides``).

Hermes Agent (docs: user-guide/features/memory):
    ~/.hermes/memories/MEMORY.md and USER.md (per profile:
    ~/.hermes/profiles/<name>/memories/). Hermes records no provenance, so
    entries carry SourceClass.UNKNOWN.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from agent_memory_guard import SourceClass


class Layout(str, Enum):
    OPENCLAW = "openclaw"
    HERMES = "hermes"


@dataclass(frozen=True)
class MemoryFile:
    path: Path
    relative_path: str
    layout: Layout
    source_class: SourceClass
    curated: bool  # bootstrap-loaded core (MEMORY.md, USER.md) vs working notes


# Mirrors OpenClaw's memory-path-provenance.ts classification.
_OPENCLAW_ORIGIN_TO_SOURCE_CLASS: Mapping[str, SourceClass] = {
    "owner": SourceClass.USER_INPUT,
    "agent": SourceClass.AGENT_AUTHORED,
    "untrusted": SourceClass.EXTERNAL_TOOL,
    "system": SourceClass.SYSTEM,
}

_USERS_USER_MD = re.compile(r"^users/[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}/USER\.md$")


def openclaw_origin_to_source_class(origin_class: str) -> SourceClass:
    """Map an OpenClaw origin class (owner/agent/untrusted/system) to AMG."""
    return _OPENCLAW_ORIGIN_TO_SOURCE_CLASS.get(origin_class, SourceClass.UNKNOWN)


def classify_openclaw_path(relative_path: str) -> tuple[bool, str] | None:
    """Return (curated, origin_class) for a workspace-relative path, or None
    when the path is not a memory file OpenClaw would index."""
    rel = relative_path.replace("\\", "/")
    segments = rel.split("/")
    if len(segments) == 1 and segments[0] in ("DREAMS.md", "dreams.md"):
        return (False, "system")
    if segments[0] == "memory" and len(segments) > 1 and segments[1] in ("dreaming", ".dreams"):
        return (False, "system")
    curated = len(segments) == 1 and segments[0] in ("MEMORY.md", "memory.md", "USER.md")
    if curated or _USERS_USER_MD.match(rel):
        return (curated, "agent")
    if segments[0] == "memory" and rel.endswith(".md"):
        return (False, "agent")
    return None


def discover_openclaw(
    workspace: Path,
    *,
    provenance_overrides: Mapping[str, str] | None = None,
) -> list[MemoryFile]:
    """List OpenClaw memory files under ``workspace``.

    ``provenance_overrides`` maps a workspace-relative path to an OpenClaw
    origin class ("owner", "agent", "untrusted", "system"). Use it to feed in
    provenance exported from OpenClaw until the adapter reads the plugin-state
    store directly.
    """
    workspace = Path(workspace)
    overrides = dict(provenance_overrides or {})
    found: list[MemoryFile] = []
    candidates: Iterable[Path] = [
        *workspace.glob("*.md"),
        *workspace.glob("users/*/USER.md"),
        *workspace.glob("memory/**/*.md"),
    ]
    for path in sorted(set(candidates)):
        if not path.is_file():
            continue
        rel = path.relative_to(workspace).as_posix()
        classified = classify_openclaw_path(rel)
        if classified is None:
            continue
        curated, origin = classified
        origin = overrides.get(rel, origin)
        found.append(
            MemoryFile(
                path=path,
                relative_path=rel,
                layout=Layout.OPENCLAW,
                source_class=openclaw_origin_to_source_class(origin),
                curated=curated,
            )
        )
    return found


def discover_hermes(memories_dir: Path) -> list[MemoryFile]:
    """List Hermes memory files (MEMORY.md, USER.md) under ``memories_dir``."""
    memories_dir = Path(memories_dir)
    found: list[MemoryFile] = []
    for name in ("MEMORY.md", "USER.md"):
        path = memories_dir / name
        if path.is_file():
            found.append(
                MemoryFile(
                    path=path,
                    relative_path=name,
                    layout=Layout.HERMES,
                    source_class=SourceClass.UNKNOWN,
                    curated=True,
                )
            )
    return found
