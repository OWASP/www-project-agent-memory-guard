"""Agent Memory Security Benchmark (AMSB).

A framework-neutral benchmark that grades **any** agent memory system for
resilience to memory-poisoning attacks (OWASP ASI06). Where the suite in
``benchmarks/security_benchmark.py`` measures Agent Memory Guard's own
detector accuracy on single writes, AMSB measures the *lifecycle* threat that
motivates the project: a payload is planted into memory, survives a context
reset, and is read back on a later turn where it becomes an active directive.

The benchmark scores a system on what a downstream turn can actually recall
after an attack sequence — not on whether a single write looked suspicious.
Systems are ranked with a 0–100 resilience score and an SSL-Labs-style letter
grade, with hard grade ceilings for catastrophic breaches.

Agent Memory Guard authors this benchmark and also submits itself for grading.
To keep the ranking honest, AMG is measured through the *same* adapter contract
as every other system, its results carry an explicit self-submission note, and
every score is reproducible with ``amg-bench``.
"""
from __future__ import annotations

from agent_memory_guard.bench.adapter import (
    MemorySystemAdapter,
    ProbeResult,
    RememberOutcome,
)
from agent_memory_guard.bench.harness import ScenarioRun, SystemReport, run_suite
from agent_memory_guard.bench.scenarios import (
    Scenario,
    Severity,
    Step,
    default_corpus,
)
from agent_memory_guard.bench.scoring import Grade, Scorecard, score_report

__all__ = [
    "MemorySystemAdapter",
    "RememberOutcome",
    "ProbeResult",
    "Scenario",
    "Step",
    "Severity",
    "default_corpus",
    "run_suite",
    "ScenarioRun",
    "SystemReport",
    "score_report",
    "Scorecard",
    "Grade",
]
