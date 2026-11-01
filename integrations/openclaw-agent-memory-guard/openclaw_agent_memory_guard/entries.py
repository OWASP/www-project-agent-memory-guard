"""Split memory files into entries with stable keys.

OpenClaw marks entries promoted by dreaming with an HTML comment on the line
before the entry (memory-entry-origins.ts):

    <!-- openclaw-memory-promotion:<key> -->
    The entry text.

Those entries get the key ``<relative_path>#<promotion key>``. Text outside
markers is split into blank-line separated blocks keyed by their first line,
``<relative_path>#L<n>``. Dreaming section markers
(``<!-- openclaw:dreaming:<phase>:start -->``) are skipped as text.

Hermes stores entries separated by a line containing only ``§``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_PROMOTION = re.compile(r"^<!--\s*openclaw-memory-promotion:([^\n]*?)\s*-->$")
_HTML_COMMENT = re.compile(r"^<!--.*-->$")


@dataclass(frozen=True)
class Entry:
    key: str
    text: str
    line: int  # 1-based line of the first text line
    tracked: bool  # True when an OpenClaw promotion marker identified the entry


def split_openclaw(relative_path: str, content: str) -> list[Entry]:
    lines = content.splitlines()
    entries: list[Entry] = []
    block: list[str] = []
    block_start = 0
    pending_key: str | None = None

    def flush() -> None:
        nonlocal block, block_start, pending_key
        text = "\n".join(block).strip()
        if text:
            if pending_key is not None:
                entries.append(Entry(f"{relative_path}#{pending_key}", text, block_start, True))
            else:
                entries.append(Entry(f"{relative_path}#L{block_start}", text, block_start, False))
        block = []
        pending_key = None

    for number, raw in enumerate(lines, start=1):
        line = raw.rstrip()
        marker = _PROMOTION.match(line.strip())
        if marker:
            flush()
            pending_key = marker.group(1)
            block_start = number + 1
            continue
        if _HTML_COMMENT.match(line.strip()):
            continue
        if not line.strip():
            flush()
            continue
        if not block:
            block_start = number
        block.append(line)
    flush()
    return entries


def split_hermes(relative_path: str, content: str) -> list[Entry]:
    entries: list[Entry] = []
    block: list[str] = []
    block_start = 0
    for number, raw in enumerate(content.splitlines(), start=1):
        line = raw.rstrip()
        if line.strip() == "§":
            text = "\n".join(block).strip()
            if text:
                entries.append(Entry(f"{relative_path}#L{block_start}", text, block_start, False))
            block = []
            continue
        if not block:
            if not line.strip():
                continue
            block_start = number
        block.append(line)
    text = "\n".join(block).strip()
    if text:
        entries.append(Entry(f"{relative_path}#L{block_start}", text, block_start, False))
    return entries
