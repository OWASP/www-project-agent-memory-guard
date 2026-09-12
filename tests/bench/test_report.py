"""Report assembly: ranking order, JSON shape, Markdown, disclosure."""
from __future__ import annotations

import json

from agent_memory_guard.bench.adapters.baseline import baseline_adapters
from agent_memory_guard.bench.harness import run_suite
from agent_memory_guard.bench.report import (
    BENCHMARK_VERSION,
    build_results,
    render_markdown,
    save_json,
    save_markdown,
)
from agent_memory_guard.bench.scenarios import default_corpus
from agent_memory_guard.bench.scoring import score_report


def _scorecards():
    corpus = default_corpus()
    return [score_report(run_suite(cls, corpus)) for cls in baseline_adapters()]


def test_build_results_ranks_best_first():
    results = build_results(_scorecards(), generated_at="2026-08-22")
    lb = results["leaderboard"]
    scores = [row["score"] for row in lb]
    assert scores == sorted(scores, reverse=True)
    assert lb[0]["system"].startswith("agent-memory-guard (hardened)")
    assert lb[-1]["system"] == "unguarded-dict"


def test_results_carry_benchmark_metadata_and_disclosure():
    results = build_results(_scorecards(), generated_at="2026-08-22")
    assert results["benchmark_version"] == BENCHMARK_VERSION
    assert results["generated_at"] == "2026-08-22"
    assert "self-submission" in results["disclosure"].lower()
    assert results["corpus"]["total"] > 0


def test_results_are_json_serializable():
    results = build_results(_scorecards(), generated_at="2026-08-22")
    # Round-trips cleanly (no enums or dataclasses left in the tree).
    assert json.loads(json.dumps(results)) == results


def test_markdown_contains_grades_disclosure_and_reproduce_line():
    results = build_results(_scorecards(), generated_at="2026-08-22")
    md = render_markdown(results)
    assert "# Agent Memory Security Benchmark" in md
    assert "amg-bench" in md
    assert "Disclosure" in md
    # Every graded system appears in the table.
    for row in results["leaderboard"]:
        assert row["system"] in md


def test_markdown_flags_self_submission_rows():
    results = build_results(_scorecards(), generated_at="2026-08-22")
    md = render_markdown(results)
    # The self-submission footnote marker is present.
    assert "¹" in md


def test_save_json_and_markdown_write_files(tmp_path):
    results = build_results(_scorecards(), generated_at="2026-08-22")
    save_json(results, tmp_path / "results.json")
    save_markdown(results, tmp_path / "leaderboard.md")
    loaded = json.loads((tmp_path / "results.json").read_text())
    assert loaded["benchmark_version"] == BENCHMARK_VERSION
    assert (tmp_path / "leaderboard.md").read_text().startswith("# Agent Memory Security Benchmark")


def test_capped_grade_is_annotated_when_present():
    # Construct a results dict with a capped row and confirm the annotation.
    from agent_memory_guard.bench.report import render_markdown

    results = {
        "benchmark_version": "0.1.0",
        "generated_at": "2026-08-22",
        "disclosure": "test disclosure self-submission",
        "corpus": {"total": 3, "malicious": 2, "benign": 1},
        "leaderboard": [
            {
                "system": "capped-sys",
                "version": "1",
                "self_submission": False,
                "score": 85.0,
                "grade": "C",
                "uncapped_grade": "B",
                "ceiling": "C",
                "defense_rate": 0.9,
                "false_positive_rate": 0.0,
                "malicious_total": 2,
                "defended_total": 1,
                "critical_breaches": 1,
                "false_positives": 0,
                "benign_total": 1,
                "median_latency_us": 5.0,
                "categories": [{"category": "leak", "defended": 1, "total": 2, "rate": 0.5}],
            }
        ],
    }
    md = render_markdown(results)
    assert "capped from B" in md
