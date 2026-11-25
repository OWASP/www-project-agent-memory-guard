"""Run the AMG guard over every entry of a memory workspace.

Each entry is written into a throwaway ``MemoryGuard`` with the entry's
provenance as ``source_class``. The guard's own detectors and policy decide
allow, redact, quarantine or block; the adapter records the decision and the
guard's ``SecurityEvent``s per entry. Nothing on disk is modified.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_memory_guard import Action, MemoryGuard, Policy, SecurityEvent
from agent_memory_guard.exceptions import PolicyViolation
from agent_memory_guard.scanner import Finding, ScanResult, Severity
from openclaw_agent_memory_guard.entries import Entry, split_hermes, split_openclaw
from openclaw_agent_memory_guard.layouts import (
    Layout,
    MemoryFile,
    discover_hermes,
    discover_openclaw,
)


@dataclass
class EntryVerdict:
    file: MemoryFile
    entry: Entry
    action: Action
    events: list[SecurityEvent] = field(default_factory=list)

    @property
    def flagged(self) -> bool:
        return self.action != Action.ALLOW or bool(self.events)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.entry.key,
            "file": self.file.relative_path,
            "line": self.entry.line,
            "layout": self.file.layout.value,
            "source_class": self.file.source_class.value,
            "tracked": self.entry.tracked,
            "action": self.action.value,
            "events": [e.to_dict() for e in self.events],
        }


@dataclass
class WorkspaceScanResult:
    root: Path
    layout: Layout
    verdicts: list[EntryVerdict]
    files_scanned: int

    @property
    def flagged(self) -> list[EntryVerdict]:
        return [v for v in self.verdicts if v.flagged]

    def to_scan_result(self) -> ScanResult:
        """Project onto AMG's scanner ``ScanResult`` so ``format_text``,
        ``format_json`` and ``format_sarif`` can render it unchanged."""
        findings: list[Finding] = []
        files_with_findings: set[str] = set()
        for v in self.flagged:
            files_with_findings.add(v.file.relative_path)
            worst = max((e.severity for e in v.events), default=None, key=_severity_rank)
            detectors = sorted({e.detector for e in v.events}) or ["policy"]
            message = "; ".join(e.message for e in v.events) or f"{v.action.value} by policy"
            findings.append(
                Finding(
                    rule_id=f"AMG-MEMORY-{v.action.value.upper()}",
                    title=f"Memory entry {v.action.value}: {', '.join(detectors)}",
                    description=message,
                    severity=_to_scanner_severity(worst, v.action),
                    file_path=str(v.file.path),
                    line=v.entry.line,
                    snippet=v.entry.text[:200],
                    recommendation=_recommendation(v),
                )
            )
        return ScanResult(
            findings=findings,
            files_scanned=self.files_scanned,
            files_with_findings=len(files_with_findings),
        )

    def to_json(self) -> str:
        return json.dumps(
            {
                "root": str(self.root),
                "layout": self.layout.value,
                "files_scanned": self.files_scanned,
                "entries": len(self.verdicts),
                "flagged": [v.to_dict() for v in self.flagged],
            },
            indent=2,
        )


def _severity_rank(severity: Any) -> int:
    order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(getattr(severity, "value", str(severity)), 0)


def _to_scanner_severity(worst: Any, action: Action) -> Severity:
    if worst is not None:
        return Severity(getattr(worst, "value", str(worst)))
    return Severity.HIGH if action == Action.BLOCK else Severity.MEDIUM


def _recommendation(v: EntryVerdict) -> str:
    if v.action == Action.BLOCK:
        return "Remove the entry or restore the file from a snapshot taken before it appeared."
    if v.action == Action.QUARANTINE:
        return "Review the entry; keep it out of the agent's bootstrap files until an owner confirms it."
    if v.action == Action.REDACT:
        return "The entry carries sensitive data; redact it in the file."
    return "Detector findings on an allowed entry; review if the source is untrusted."


def scan_files(
    files: list[MemoryFile],
    *,
    policy: Policy | None = None,
) -> list[EntryVerdict]:
    guard = MemoryGuard(policy=policy or Policy.strict(), snapshot_on_block=False)
    verdicts: list[EntryVerdict] = []
    for mf in files:
        content = mf.path.read_text(encoding="utf-8", errors="replace")
        entries = (
            split_hermes(mf.relative_path, content)
            if mf.layout == Layout.HERMES
            else split_openclaw(mf.relative_path, content)
        )
        for entry in entries:
            before = len(guard.events)
            try:
                action = guard.write(entry.key, entry.text, source_class=mf.source_class)
            except PolicyViolation:
                action = Action.BLOCK
            verdicts.append(EntryVerdict(mf, entry, action, list(guard.events[before:])))
    return verdicts


def scan_workspace(
    root: Path,
    *,
    layout: Layout = Layout.OPENCLAW,
    policy: Policy | None = None,
    provenance_overrides: Mapping[str, str] | None = None,
) -> WorkspaceScanResult:
    root = Path(root)
    files = (
        discover_hermes(root)
        if layout == Layout.HERMES
        else discover_openclaw(root, provenance_overrides=provenance_overrides)
    )
    return WorkspaceScanResult(
        root=root,
        layout=layout,
        verdicts=scan_files(files, policy=policy),
        files_scanned=len(files),
    )
