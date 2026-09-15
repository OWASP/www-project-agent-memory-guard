"""Execution harness: run scenarios against an adapter and record outcomes.

The harness is intentionally model-free. For each scenario it applies the
attack steps, crosses a simulated context reset, reads the probe key back, and
decides *breach* vs *defended* by a single deterministic rule: did the
scenario's canary survive into the recalled value?

That rule is the whole judgment. It means two people running the same corpus
against the same system get identical grades, and it means a system cannot game
the score by looking clever on the write path while still handing the poison
back on the read path.
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field

from agent_memory_guard.bench.adapter import MemorySystemAdapter, RememberOutcome
from agent_memory_guard.bench.scenarios import Scenario, default_corpus


@dataclass
class ScenarioRun:
    """Outcome of grading one scenario against one system."""

    scenario_id: str
    category: str
    severity: str
    malicious: bool
    #: For malicious scenarios: True if the system defended (canary did not
    #: survive). For benign scenarios: True if the content was preserved intact
    #: (no over-blocking). ``passed`` is the value the scorer aggregates.
    passed: bool
    #: True only for malicious scenarios the system failed to defend.
    breached: bool
    #: True only for benign scenarios the system wrongly blocked/mangled.
    false_positive: bool
    final_outcome: str
    recalled_present: bool
    latency_us: float
    detail: str = ""
    #: True if ``recall`` raised instead of returning a value. A read that
    #: throws reveals nothing about what the store persisted — the poison may
    #: still be there and would come back through a working read path — so an
    #: error run is never counted as a malicious defense (see ``run_scenario``).
    recall_error: bool = False


def _canary_survived(recalled: object | None, canary: str) -> bool:
    """True if the attack's canary is still present in the recalled value."""
    if recalled is None or not canary:
        return False
    return canary in _as_text(recalled)


def _as_text(value: object) -> str:
    return value if isinstance(value, str) else str(value)


def run_scenario(adapter: MemorySystemAdapter, scenario: Scenario) -> ScenarioRun:
    """Apply one scenario to a fresh adapter and judge the result.

    The caller is responsible for handing in an adapter that carries no state
    from a previous scenario; :func:`run_suite` does this by constructing one
    adapter per scenario via a factory.
    """
    start = time.perf_counter_ns()

    last_outcome = RememberOutcome.STORED
    for step in scenario.steps:
        try:
            last_outcome = adapter.remember(
                step.key, step.value, source_class=step.source_class
            )
        except Exception:
            # A system that raises on a write is defending (it refused the
            # write). Treat that like an explicit block for scoring.
            last_outcome = RememberOutcome.BLOCKED

    # The defining feature of the threat: memory outlives the session that
    # planted it. Judge only what survives the reset.
    adapter.context_reset()

    recall_error = False
    recall_error_detail = ""
    try:
        recalled = adapter.recall(scenario.probe_key)
    except Exception as exc:
        # A read that raises tells us nothing about what the store persisted:
        # the poison may still be there and would come back through a working
        # read path. Collapsing it into a clean "nothing recalled" would credit
        # a broken or nondeterministic read as a successful defense — a
        # direction that can only inflate the malicious defense rate, never
        # lower it. Record it as an explicit error instead of a defense.
        recalled = None
        recall_error = True
        recall_error_detail = f"recall raised {type(exc).__name__}"

    elapsed_us = (time.perf_counter_ns() - start) / 1000.0
    recalled_present = recalled is not None

    if scenario.malicious:
        if recall_error:
            # The system did not *demonstrably* defend. Do not count it as a
            # defense (the dangerous direction), and do not assert a breach we
            # could not observe.
            return ScenarioRun(
                scenario_id=scenario.id,
                category=scenario.category,
                severity=scenario.severity.value,
                malicious=True,
                passed=False,
                breached=False,
                false_positive=False,
                final_outcome=last_outcome.value,
                recalled_present=False,
                latency_us=round(elapsed_us, 1),
                detail=recall_error_detail,
                recall_error=True,
            )
        survived = _canary_survived(recalled, scenario.canary)
        breached = survived
        passed = not survived
        detail = (
            "canary survived into recall" if survived else "canary neutralized"
        )
        return ScenarioRun(
            scenario_id=scenario.id,
            category=scenario.category,
            severity=scenario.severity.value,
            malicious=True,
            passed=passed,
            breached=breached,
            false_positive=False,
            final_outcome=last_outcome.value,
            recalled_present=recalled_present,
            latency_us=round(elapsed_us, 1),
            detail=detail,
        )

    # Benign control: the system should keep legitimate content usable. It
    # fails by blocking/quarantining, or by mangling the value on the way
    # through so a later turn cannot read back what was stored — a read that
    # raises is likewise a system a later turn cannot use.
    original = scenario.steps[-1].value
    preserved = recalled is not None and _as_text(recalled) == original
    false_positive = not preserved
    if recall_error:
        detail = recall_error_detail
    else:
        detail = (
            "benign content preserved" if preserved else "benign content over-blocked"
        )
    return ScenarioRun(
        scenario_id=scenario.id,
        category=scenario.category,
        severity=scenario.severity.value,
        malicious=False,
        passed=preserved,
        breached=False,
        false_positive=false_positive,
        final_outcome=last_outcome.value,
        recalled_present=recalled_present,
        latency_us=round(elapsed_us, 1),
        detail=detail,
        recall_error=recall_error,
    )


@dataclass
class SystemReport:
    """All per-scenario runs for one graded system, plus identity metadata."""

    system: str
    version: str
    self_submission: bool
    runs: list[ScenarioRun] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "system": self.system,
            "version": self.version,
            "self_submission": self.self_submission,
            "runs": [asdict(r) for r in self.runs],
        }


def run_suite(
    adapter_factory,
    corpus: list[Scenario] | None = None,
) -> SystemReport:
    """Grade a system across a corpus, one fresh adapter per scenario.

    Args:
        adapter_factory: Zero-argument callable returning a new
            :class:`MemorySystemAdapter`. A fresh instance per scenario is what
            prevents an earlier attack from contaminating a later one.
        corpus: Scenarios to run; defaults to :func:`default_corpus`.

    Returns:
        A :class:`SystemReport` ready to hand to
        :func:`agent_memory_guard.bench.scoring.score_report`.
    """
    scenarios = corpus if corpus is not None else default_corpus()

    probe = adapter_factory()
    report = SystemReport(
        system=getattr(probe, "name", "unnamed-system"),
        version=getattr(probe, "version", "0.0.0"),
        self_submission=getattr(probe, "self_submission", False),
    )
    for scenario in scenarios:
        adapter = adapter_factory()
        report.runs.append(run_scenario(adapter, scenario))
    return report


__all__ = ["ScenarioRun", "SystemReport", "run_scenario", "run_suite"]
