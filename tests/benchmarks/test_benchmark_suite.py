"""Tests for security benchmark suite and performance overhead measurements."""
from __future__ import annotations

import runpy
from pathlib import Path

import pytest

pytest.importorskip("matplotlib", reason="plotting is an optional benchmark dependency")
pytest.importorskip("numpy", reason="numpy is an optional benchmark dependency")


@pytest.fixture(scope="module")
def benchmark_module():
    script = Path(__file__).resolve().parents[2] / "benchmarks" / "security_benchmark.py"
    return runpy.run_path(str(script))


def test_attack_corpus_coverage(benchmark_module):
    """The attack corpus contains >= 50 labeled cases across the 4 threat categories."""
    corpus = benchmark_module["ATTACK_CORPUS"]
    attack_cases = [tc for tc in corpus if tc.should_detect]
    benign_cases = [tc for tc in corpus if not tc.should_detect]

    assert len(attack_cases) >= 50
    assert len(benign_cases) >= 15

    categories = {tc.category for tc in corpus}
    assert {"injection", "leakage", "tampering", "churn", "benign"}.issubset(categories)

    for cat in ["injection", "leakage", "tampering", "churn"]:
        cat_cases = [tc for tc in attack_cases if tc.category == cat]
        assert len(cat_cases) >= 5, f"Expected at least 5 cases for {cat}"


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
    """Performance measurements cover read, write, snapshot, rollback, 1/10-rule, 100b-100kb."""
    run_perf = benchmark_module["run_performance_benchmark"]
    perf_res = run_perf(iterations=2)

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

    assert isinstance(perf_res.redis_available, bool)
    assert len(perf_res.redis_status) > 0


def test_redis_backend_graceful_handling(benchmark_module, monkeypatch):
    """Redis backend reports graceful status and never fabricates results."""
    get_redis = benchmark_module["get_redis_backend"]
    store, status = get_redis()
    # In this test environment, fakeredis is installed so store is present
    if store is not None:
        assert "fakeredis" in status or "Redis server" in status

    # When both redis and fakeredis are unavailable, it handles gracefully
    import sys
    monkeypatch.setitem(sys.modules, "redis", None)
    monkeypatch.setitem(sys.modules, "fakeredis", None)
    store_none, status_msg = get_redis()
    assert store_none is None
    assert "unavailable" in status_msg or "not installed" in status_msg
