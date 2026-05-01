from __future__ import annotations

import copy
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from agent_memory_guard.integrity import hash_value


@dataclass(frozen=True)
class Snapshot:
    """Point-in-time capture of agent memory plus its integrity digest."""

    snapshot_id: str
    timestamp: float
    label: str
    data: dict[str, Any]
    digest: str
    metadata: dict[str, Any] = field(default_factory=dict)


class SnapshotStore:
    """Bounded ring buffer of memory snapshots for forensics and rollback."""

    def __init__(self, max_snapshots: int = 50) -> None:
        if max_snapshots < 1:
            raise ValueError("max_snapshots must be >= 1")
        self._max = max_snapshots
        self._snapshots: "OrderedDict[str, Snapshot]" = OrderedDict()

    def __len__(self) -> int:
        return len(self._snapshots)

    def capture(
        self,
        data: dict[str, Any],
        *,
        label: str = "manual",
        metadata: dict[str, Any] | None = None,
    ) -> Snapshot:
        snapshot = Snapshot(
            snapshot_id=str(uuid.uuid4()),
            timestamp=time.time(),
            label=label,
            data=copy.deepcopy(data),
            digest=hash_value(data),
            metadata=dict(metadata or {}),
        )
        self._snapshots[snapshot.snapshot_id] = snapshot
        while len(self._snapshots) > self._max:
            self._snapshots.popitem(last=False)
        return snapshot

    def get(self, snapshot_id: str) -> Snapshot | None:
        return self._snapshots.get(snapshot_id)

    def latest(self, label: str | None = None) -> Snapshot | None:
        for snap in reversed(self._snapshots.values()):
            if label is None or snap.label == label:
                return snap
        return None

    def list(self) -> list[Snapshot]:
        return list(self._snapshots.values())

    def restore_data(self, snapshot_id: str) -> dict[str, Any]:
        snap = self._snapshots.get(snapshot_id)
        if snap is None:
            raise KeyError(f"Unknown snapshot id: {snapshot_id}")
        return copy.deepcopy(snap.data)
