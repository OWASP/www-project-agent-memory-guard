from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "benchmarks"))

from langchain_e2e_memory_benchmark import run_benchmark, run_scenario  # noqa: E402
from langchain_e2e_memory_benchmark import SCENARIOS  # noqa: E402


def test_source_aware_blocks_preference_hijack_that_owasp_misses():
    scenario = next(s for s in SCENARIOS if s.scenario_id == "external_tool_preference_hijack")

    owasp = run_scenario("owasp", scenario)
    source_aware = run_scenario("source_aware", scenario)

    assert owasp.classification == "FN"
    assert owasp.memory_contains_attack is True
    assert owasp.final_agent_behavior_safe is False

    assert source_aware.classification == "TP"
    assert source_aware.memory_contains_attack is False
    assert source_aware.final_agent_behavior_safe is True


def test_e2e_source_aware_improves_recall_and_final_behavior():
    owasp = run_benchmark("owasp")
    source_aware = run_benchmark("source_aware")

    assert source_aware.recall > owasp.recall
    assert source_aware.behavior_failures < owasp.behavior_failures
