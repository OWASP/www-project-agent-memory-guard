"""Cross-task contamination detector.

Flags reads of durable memory (e.g. tool_observation, retrieved_fact) from a
different task than the one that produced it. This addresses scenario #1
raised on microsoft/autogen#7673: a tool result from task A silently
reappearing inside an unrelated task B.
"""
from __future__ import annotations

from typing import Any

from agent_memory_guard.classification import (
    DURABLE_CLASSES,
    ClassificationRegistry,
    MemoryClass,
)
from agent_memory_guard.detectors.base import DetectionResult
from agent_memory_guard.events import Severity


class CrossTaskContaminationDetector:
    """Flags reads of durable memory from a different task than the one that produced it.

    This detector prevents cross-task context contamination (e.g., tool results
    from Task A leaking into Task B's agent reasoning).

    Attributes:
        name: The unique identifier for this detector.
    """

    name = "cross_task_contamination"

    def __init__(
        self,
        registry: ClassificationRegistry,
        *,
        current_task: str | None = None,
        watched: frozenset[MemoryClass] = DURABLE_CLASSES,
        severity: Severity = Severity.HIGH,
    ) -> None:
        self._registry = registry
        self._current_task = current_task
        self._watched = watched
        self._severity = severity

    def set_current_task(self, task_id: str | None) -> None:
        """Switch the current active task identifier.

        Args:
            task_id: The ID of the task context to switch to.
        """
        self._current_task = task_id

    def inspect(self, key: str, value: Any, *, operation: str) -> DetectionResult:
        """Inspect read operations for cross-task contamination.

        Args:
            key: The memory key being accessed.
            value: The stored value being read.
            operation: The memory operation being performed. Only screens 'read' operations.

        Returns:
            DetectionResult: The check outcome, matched=True if cross-task leakage is detected.
        """
        if operation != "read":
            return DetectionResult(self.name, matched=False)
        mclass = self._registry.get(key)
        if mclass is None or mclass not in self._watched:
            return DetectionResult(self.name, matched=False)
        origin = self._registry.task_of(key)
        if origin is None or self._current_task is None or origin == self._current_task:
            return DetectionResult(self.name, matched=False)
        return DetectionResult(
            detector=self.name,
            matched=True,
            severity=self._severity,
            message=(
                f"Durable memory '{key}' ({mclass.value}) read from task "
                f"'{self._current_task}' but was written by task '{origin}'"
            ),
            metadata={
                "class": mclass.value,
                "origin_task": origin,
                "current_task": self._current_task,
            },
        )
