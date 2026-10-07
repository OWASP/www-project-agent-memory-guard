"""OWASP Agent Memory Guard adapter for file-based agent memory.

OpenClaw and Hermes Agent keep long-term memory as Markdown files. This
package reads those files, splits them into entries, runs the AMG detector
pipeline and policy on each entry, and reports per-entry verdicts. It works
out of band: OpenClaw exposes no memory-write hook, so the adapter catches a
poisoned entry on the next scan rather than at write time.
"""

from openclaw_agent_memory_guard.entries import Entry, split_hermes, split_openclaw
from openclaw_agent_memory_guard.layouts import (
    Layout,
    MemoryFile,
    discover_hermes,
    discover_openclaw,
)
from openclaw_agent_memory_guard.scan import EntryVerdict, WorkspaceScanResult, scan_workspace

__all__ = [
    "Entry",
    "EntryVerdict",
    "Layout",
    "MemoryFile",
    "WorkspaceScanResult",
    "discover_hermes",
    "discover_openclaw",
    "scan_workspace",
    "split_hermes",
    "split_openclaw",
]

__version__ = "0.1.0"
