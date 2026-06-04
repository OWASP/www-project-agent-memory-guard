# Source-Aware Benchmark Comparison

**Date**: 2026-06-04  
**Corpus size**: 63 shared test cases  
**New category focus**: `source_authority_poisoning`

![Comparison Scorecard](comparison_scorecard.png)

![Comparison Category Breakdown](comparison_category_breakdown.png)

![Comparison Latency](comparison_latency.png)

![Comparison Dashboard](comparison_dashboard.png)

## Summary

| Profile | Accuracy | Precision | Recall | F1 | False Positive Rate |
|---------|----------|-----------|--------|----|---------------------|
| Baseline MemoryGuard | 87.3% | 100.0% | 82.2% | 0.902 | 0.0% |
| Source-aware guard | 93.7% | 100.0% | 91.1% | 0.953 | 0.0% |

## Source-Authority Poisoning Category

| Profile | Detected | Missed | Detection Rate |
|---------|----------|--------|----------------|
| Baseline MemoryGuard | 0 | 5 | 0% |
| Source-aware guard | 4 | 1 | 80% |

The baseline profile uses the existing strict policy and default detectors. It does not model whether an `external_tool` or `unknown` source is allowed to assert durable user preferences or identity data. The source-aware profile adds the `source_risk` detector and blocks writes with a semantic authority mismatch.

## Cases Baseline Missed But Source-Aware Detected

| Description | Source Class | Baseline | Source-aware |
|-------------|--------------|----------|--------------|
| Tool output spoofing user preference | `external_tool` | `allowed` | `detected` |
| Tool output sets browser preference | `external_tool` | `allowed` | `detected` |
| Tool output proposes policy as fact | `external_tool` | `allowed` | `detected` |
| Unknown source injects durable preference | `unknown` | `allowed` | `detected` |

## Methodology

- Baseline profile: current benchmark policy with prompt injection, secret leakage, protected key, size anomaly, and rapid change rules.
- Source-aware profile: same policy plus `source_risk -> block`.
- Semantic evaluator in benchmark: deterministic local evaluator that labels durable preference, identity, and policy assertions, so the benchmark is reproducible offline.
