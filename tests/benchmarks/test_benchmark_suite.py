"""Tests for security benchmark suite and performance overhead measurements."""
from __future__ import annotations

import runpy
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def benchmark_module():
    script = Path(__file__).resolve().parents[2] / "benchmarks" / "security_benchmark.py"
    return runpy.run_path(str(script))


def test_attack_corpus_coverage(benchmark_module):
    """The attack corpus contains exactly 54 attack cases and 18 benign controls across 4 categories."""
    corpus = benchmark_module["ATTACK_CORPUS"]
    attack_cases = [tc for tc in corpus if tc.should_detect]
    benign_cases = [tc for tc in corpus if not tc.should_detect]

    assert len(attack_cases) == 54
    assert len(benign_cases) == 18
    assert len(corpus) == 72

    categories = {tc.category for tc in corpus}
    assert {"injection", "leakage", "tampering", "churn", "benign"}.issubset(categories)

    expected_counts = {"injection": 20, "leakage": 14, "tampering": 12, "churn": 8}
    for cat, count in expected_counts.items():
        cat_cases = [tc for tc in attack_cases if tc.category == cat]
        assert len(cat_cases) == count, f"Expected {count} cases for {cat}, got {len(cat_cases)}"


def test_benchmark_result_metrics(benchmark_module):
    """BenchmarkResult computes TP, FP, TN, FN, precision, recall, FPR, FNR, and confusion matrix."""
    benchmark_result_cls = benchmark_module["BenchmarkResult"]
    res = benchmark_result_cls(
        total=100,
        true_positives=40,
        false_negatives=10,
        true_negatives=45,
        false_positives=5,
    )

    assert res.accuracy == 0.85
    assert res.precision == 40 / 45
    assert res.recall == 40 / 50
    assert res.false_positive_rate == 5 / 50
    assert res.false_negative_rate == 10 / 50
    assert res.recall + res.false_negative_rate == 1.0

    cm = res.confusion_matrix
    assert cm == {"tp": 40, "fp": 5, "tn": 45, "fn": 10}


def test_performance_benchmark_execution(benchmark_module):
    """Performance measurements cover bare store baseline, read, write, snapshot, rollback."""
    run_perf = benchmark_module["run_performance_benchmark"]
    perf_res = run_perf(iterations=2)

    # Check bare store baseline measurements
    assert hasattr(perf_res, "bare_store_data")
    for sz in ["100b", "1kb", "10kb", "100kb"]:
        assert sz in perf_res.bare_store_data
        assert "read" in perf_res.bare_store_data[sz]
        assert "write" in perf_res.bare_store_data[sz]
        assert perf_res.bare_store_data[sz]["read"].median_us > 0
        assert perf_res.bare_store_data[sz]["write"].median_us > 0

    assert "InMemoryStore" in perf_res.data
    mem_data = perf_res.data["InMemoryStore"]

    for pol in ["1-rule", "10-rule"]:
        assert pol in mem_data
        for sz in ["100b", "1kb", "10kb", "100kb"]:
            assert sz in mem_data[pol]
            for op in ["read", "write", "snapshot", "rollback"]:
                m = mem_data[pol][sz][op]
                assert m.median_us > 0
                assert m.mean_us > 0
                assert m.ops_per_sec > 0

            # Guard overhead is guarded latency minus bare store latency
            bare_write = perf_res.bare_store_data[sz]["write"].median_us
            guarded_write = mem_data[pol][sz]["write"].median_us
            overhead = guarded_write - bare_write
            assert isinstance(overhead, float)

    assert isinstance(perf_res.redis_available, bool)
    assert len(perf_res.redis_status) > 0


def test_redis_backend_graceful_handling(benchmark_module, monkeypatch):
    """Redis backend reports graceful status and never fabricates results."""
    get_redis = benchmark_module["get_redis_backend"]
    store, status = get_redis()
    # In this test environment, fakeredis is installed so store is present
    if store is not None:
        assert status == "RedisMemoryStore (fakeredis, in-process)" or "Redis server" in status

    # When both redis and fakeredis are unavailable, it handles gracefully
    import sys
    monkeypatch.setitem(sys.modules, "redis", None)
    monkeypatch.setitem(sys.modules, "fakeredis", None)
    store_none, status_msg = get_redis()
    assert store_none is None
    assert "unavailable" in status_msg or "not installed" in status_msg


def test_plotting_visualizations_optional(benchmark_module, tmp_path):
    """Visualizations are generated when plotting dependencies are present."""
    pytest.importorskip("matplotlib", reason="plotting is an optional benchmark dependency")
    pytest.importorskip("numpy", reason="numpy is an optional benchmark dependency")

    result = benchmark_module["run_benchmark"]()
    benchmark_module["generate_visualizations"](result, tmp_path)
    assert (tmp_path / "detection_scorecard.png").exists()
    assert (tmp_path / "confusion_matrix.png").exists()
    assert (tmp_path / "latency_overhead.png").exists()
