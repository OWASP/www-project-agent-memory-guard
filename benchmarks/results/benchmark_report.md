# OWASP Agent Memory Guard — Security Benchmark Report

**Version**: main @ fa2df6a
**Test Cases**: 72
**Date**: 2026-10-27
**Python**: 3.13.5

---

## Executive Summary

With this benchmark policy and opt-in detector configuration, Agent Memory Guard detected **94.4%** of attack cases with **100.0% precision** across 72 labeled test cases; median write latency was **37 µs** in this local run.

| Metric | Value |
|--------|-------|
| **Accuracy** | 95.8% |
| **Precision** | 100.0% |
| **Recall (Detection Rate)** | 94.4% |
| **F1 Score** | 0.971 |
| **False Positive Rate** | 0.0% |
| **False Negative Rate** | 5.6% |
| **True Positives (TP)** | 51 |
| **True Negatives (TN)** | 18 |
| **False Positives (FP)** | 0 |
| **False Negatives (FN)** | 3 |

### Confusion Matrix

| Actual \ Predicted | Detected (Positive) | Allowed (Negative) |
|---|---|---|
| **Attack (Actual Positive)** | True Positive (TP): **51** | False Negative (FN): **3** |
| **Benign (Actual Negative)** | False Positive (FP): **0** | True Negative (TN): **18** |

---

## Detection by Attack Category

| Category | Detection Rate | Detected | Missed | Total |
|----------|---------------|----------|--------|-------|
| Injection | 100% | 20 | 0 | 20 |
| Leakage | 79% | 11 | 3 | 14 |
| Tampering | 100% | 12 | 0 | 12 |
| Churn | 100% | 8 | 0 | 8 |

### False Positive Analysis (Benign Operations)

| Metric | Value |
|--------|-------|
| Benign samples tested | 18 |
| Correctly allowed (TN) | 18 |
| Incorrectly flagged (FP) | 0 |
| False positive rate | 0.0% |

---

## Configuration Coverage

The headline figures above are measured with the opt-in `memory_persistence_injection` detector enabled under a custom `Policy` (`default_action=ALLOW`). A plain `MemoryGuard()` with default configuration does not load the opt-in detector, so the same corpus scores differently out of the box. Both runs use the identical corpus (54 attacks, 18 benign controls) and custom policy; only the detector set differs.

| Configuration | Detectors | Recall | Precision | FP rate | Missed |
|---------------|-----------|--------|-----------|---------|--------|
| Default suite (out of the box) | 7 | 85.2% | 100.0% | 0.0% | 8 |
| Benchmarked configuration | 8 | 94.4% | 100.0% | 0.0% | 3 |

**Opt-in detectors enabled in custom configuration**: `memory_persistence_injection`

Per-category detection, default suite vs benchmarked configuration:

| Category | Default suite | Benchmarked |
|----------|---------------|-------------|
| Injection | 15/20 | 20/20 |
| Leakage | 11/14 | 11/14 |
| Tampering | 12/12 | 12/12 |
| Churn | 8/8 | 8/8 |

---

## Performance Overhead

| Metric | Value |
|--------|-------|
| **Median latency** | 37 µs |
| **Mean latency** | 60 µs |
| **P95 latency** | 204 µs |
| **P99 latency** | 266 µs |
| **Max latency** | 370 µs |

This local, synthetic measurement is not a general latency guarantee for production agent operations.

### MemoryGuard Overhead Baseline (Guarded vs Bare InMemoryStore)

Overhead is calculated as guarded latency minus unguarded bare InMemoryStore latency across payload sizes. Measurements are local and synthetic.

| Policy | Payload Size | Operation | Unguarded Bare Store (µs) | Guarded MemoryGuard (µs) | Guard Overhead (µs) |
|--------|--------------|-----------|---------------------------|--------------------------|---------------------|
| 1-rule | 100b | read | 0.1 | 17.5 | 17.4 |
| 1-rule | 100b | write | 0.1 | 18.4 | 18.3 |
| 1-rule | 1kb | read | 0.1 | 142.5 | 142.3 |
| 1-rule | 1kb | write | 0.1 | 143.7 | 143.6 |
| 1-rule | 10kb | read | 0.1 | 1364.5 | 1364.4 |
| 1-rule | 10kb | write | 0.1 | 1390.0 | 1390.0 |
| 1-rule | 100kb | read | 0.1 | 13723.9 | 13723.8 |
| 1-rule | 100kb | write | 0.1 | 13592.7 | 13592.6 |
| 10-rule | 100b | read | 0.1 | 17.0 | 16.9 |
| 10-rule | 100b | write | 0.1 | 17.8 | 17.7 |
| 10-rule | 1kb | read | 0.1 | 137.5 | 137.4 |
| 10-rule | 1kb | write | 0.1 | 138.9 | 138.8 |
| 10-rule | 10kb | read | 0.1 | 1349.9 | 1349.8 |
| 10-rule | 10kb | write | 0.1 | 1372.6 | 1372.5 |
| 10-rule | 100kb | read | 0.1 | 13658.3 | 13658.2 |
| 10-rule | 100kb | write | 0.1 | 13580.5 | 13580.4 |

### Store Backend Comparison: InMemoryStore vs RedisMemoryStore (fakeredis, in-process)

**Redis Backend Status**: RedisMemoryStore (fakeredis, in-process)

Limitations: RedisMemoryStore measurements use fakeredis (in-process emulation, no network I/O). These synthetic local numbers do not represent network latency or a real Redis server.

| Policy | Size | Operation | InMemoryStore (µs) | RedisMemoryStore (fakeredis, in-process) (µs) | fakeredis / in-memory ratio (synthetic in-process, no network) |
|--------|------|-----------|--------------------|-----------------------------------------------|----------------------------------------------------------------|
| 1-rule | 100b | read | 17.5 | 96.1 | 5.5x |
| 1-rule | 100b | write | 18.4 | 49.4 | 2.7x |
| 1-rule | 100b | snapshot | 10.1 | 95.8 | 9.5x |
| 1-rule | 100b | rollback | 5.8 | 112.0 | 19.2x |
| 1-rule | 1kb | read | 142.5 | 216.9 | 1.5x |
| 1-rule | 1kb | write | 143.7 | 181.8 | 1.3x |
| 1-rule | 1kb | snapshot | 12.1 | 103.9 | 8.6x |
| 1-rule | 1kb | rollback | 5.6 | 115.4 | 20.5x |
| 1-rule | 10kb | read | 1364.5 | 1464.5 | 1.1x |
| 1-rule | 10kb | write | 1390.0 | 1422.2 | 1.0x |
| 1-rule | 10kb | snapshot | 35.8 | 131.6 | 3.7x |
| 1-rule | 10kb | rollback | 5.8 | 135.2 | 23.1x |
| 1-rule | 100kb | read | 13723.9 | 13846.1 | 1.0x |
| 1-rule | 100kb | write | 13592.7 | 13968.8 | 1.0x |
| 1-rule | 100kb | snapshot | 271.1 | 458.3 | 1.7x |
| 1-rule | 100kb | rollback | 5.6 | 334.2 | 59.7x |
| 10-rule | 100b | read | 17.0 | 95.1 | 5.6x |
| 10-rule | 100b | write | 17.8 | 47.9 | 2.7x |
| 10-rule | 100b | snapshot | 9.4 | 95.9 | 10.2x |
| 10-rule | 100b | rollback | 5.8 | 109.9 | 18.9x |
| 10-rule | 1kb | read | 137.5 | 216.2 | 1.6x |
| 10-rule | 1kb | write | 138.9 | 171.0 | 1.2x |
| 10-rule | 1kb | snapshot | 12.0 | 94.0 | 7.8x |
| 10-rule | 1kb | rollback | 5.8 | 113.6 | 19.7x |
| 10-rule | 10kb | read | 1349.9 | 1450.1 | 1.1x |
| 10-rule | 10kb | write | 1372.6 | 1414.2 | 1.0x |
| 10-rule | 10kb | snapshot | 37.3 | 132.4 | 3.5x |
| 10-rule | 10kb | rollback | 6.0 | 137.1 | 22.8x |
| 10-rule | 100kb | read | 13658.3 | 13939.3 | 1.0x |
| 10-rule | 100kb | write | 13580.5 | 13944.6 | 1.0x |
| 10-rule | 100kb | snapshot | 274.5 | 447.5 | 1.6x |
| 10-rule | 100kb | rollback | 5.7 | 347.8 | 61.3x |

---

## Visualizations

![Detection Scorecard](detection_scorecard.png)

![Attack Category Breakdown](attack_category_breakdown.png)

![Confusion Matrix](confusion_matrix.png)

![Latency Overhead](latency_overhead.png)

![Full Dashboard](benchmark_dashboard.png)

---

## Methodology

- **Guard Configuration**: custom `Policy` (`default_action=ALLOW`) with rules covering injection, secrets redaction, protected keys, size anomalies, churn, and memory persistence
- **Attack Corpus**: exactly 54 attack payloads across injection, leakage, tampering, and churn, alongside 18 benign controls (72 test cases total)
- **Categories Tested**: Injection (20), Leakage (14), Tampering (12), Churn (8), Benign (18)
- **Configurations Tested**:
  - **Default Configuration (7 detectors)**: `PromptInjectionDetector`, `SensitiveDataDetector`, `SizeAnomalyDetector`, `RapidChangeDetector`, `ProtectedKeyDetector`, `CrossTaskContaminationDetector`, `SelfReinforcementDetector`
  - **Custom Benchmark Configuration (8 detectors)**: Default suite plus opt-in `MemoryPersistenceInjectionDetector` (`memory_persistence_injection`)
- **Measurement**: Each test case runs on a fresh `MemoryGuard` instance to avoid state leakage
- **Latency**: Measured via `time.perf_counter_ns()` (wall-clock, includes all detector processing)
- **Overhead Baseline**: Measured against unguarded bare `InMemoryStore` operations per payload size (overhead = guarded latency − unguarded latency)
- **Backend Emulation**: Redis tests use in-process `fakeredis` emulation without network round-trips

---

## How to Reproduce

```bash
cd /path/to/www-project-agent-memory-guard
pip install -e ".[dev]"
pip install matplotlib numpy fakeredis
python benchmarks/security_benchmark.py
```

Results are saved to `benchmarks/results/`.
