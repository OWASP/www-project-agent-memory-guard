"""End-to-end CLI smoke test — offline baselines only."""
from __future__ import annotations

import json

from agent_memory_guard.bench.cli import main


def test_cli_writes_results_and_leaderboard(tmp_path, capsys):
    rc = main(["--out", str(tmp_path)])
    assert rc == 0

    results = json.loads((tmp_path / "results.json").read_text())
    assert results["benchmark"].startswith("Agent Memory Security Benchmark")
    assert len(results["leaderboard"]) == 3

    md = (tmp_path / "leaderboard.md").read_text()
    assert "Leaderboard" in md

    out = capsys.readouterr().out
    assert "grade" in out


def test_cli_json_only_skips_markdown(tmp_path):
    rc = main(["--out", str(tmp_path), "--json-only"])
    assert rc == 0
    assert (tmp_path / "results.json").exists()
    assert not (tmp_path / "leaderboard.md").exists()


def test_cli_without_out_still_succeeds(capsys):
    rc = main([])
    assert rc == 0
    assert "not written to disk" in capsys.readouterr().out


def test_cli_unknown_third_party_is_skipped_not_fatal(tmp_path):
    # A third-party system whose dependency is absent must not abort the run;
    # the baselines it is requested alongside still grade.
    rc = main(["--out", str(tmp_path), "--systems", "mem0", "agent-memory-guard"])
    assert rc == 0
    assert (tmp_path / "results.json").exists()
