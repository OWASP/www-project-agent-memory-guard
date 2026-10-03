"""Regression coverage for the optional security benchmark reporting path."""

from __future__ import annotations

import runpy
from pathlib import Path

import pytest

pytest.importorskip("matplotlib", reason="plotting is an optional benchmark dependency")
pytest.importorskip("numpy", reason="plotting is an optional benchmark dependency")

from agent_memory_guard import __version__ as amg_version  # noqa: E402


def test_plotting_and_report_use_installed_version(tmp_path: Path) -> None:
    """A fresh benchmark run renders plots and does not mislabel its release."""
    script = Path(__file__).resolve().parents[2] / "benchmarks" / "security_benchmark.py"
    benchmark = runpy.run_path(str(script))
    result = benchmark["run_benchmark"]()
    benchmark["generate_visualizations"](result, tmp_path)
    benchmark["generate_report"](result, tmp_path)

    report = (tmp_path / "benchmark_report.md").read_text()
    assert f"**Version**: {amg_version}" in report
    assert "not a general latency guarantee" in report
    assert (tmp_path / "latency_overhead.png").stat().st_size > 0
    assert (tmp_path / "benchmark_dashboard.png").stat().st_size > 0
