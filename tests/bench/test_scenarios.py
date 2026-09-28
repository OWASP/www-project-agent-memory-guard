"""The scenario corpus must stay well-formed for grading to be meaningful."""
from __future__ import annotations

from agent_memory_guard.bench.scenarios import (
    SEVERITY_WEIGHT,
    Severity,
    corpus_stats,
    default_corpus,
)


def test_corpus_nonempty_and_mixed():
    corpus = default_corpus()
    assert len(corpus) >= 15
    assert any(s.malicious for s in corpus)
    assert any(not s.malicious for s in corpus)


def test_ids_are_unique():
    ids = [s.id for s in default_corpus()]
    assert len(ids) == len(set(ids))


def test_malicious_scenarios_carry_a_canary_benign_do_not():
    for s in default_corpus():
        if s.malicious:
            assert s.canary, f"{s.id} is malicious but has no canary"
        else:
            assert s.canary == "", f"{s.id} is benign but has a canary"


def test_every_scenario_has_at_least_one_step_and_probe_key():
    for s in default_corpus():
        assert s.steps, f"{s.id} has no steps"
        assert s.probe_key, f"{s.id} has no probe key"


def test_probe_key_is_written_by_some_step():
    # The probe reads a key the attack actually touched, else it can never breach.
    for s in default_corpus():
        keys = {step.key for step in s.steps}
        assert s.probe_key in keys, f"{s.id} probes a key it never writes"


def test_weight_matches_severity_table():
    for s in default_corpus():
        assert s.weight == SEVERITY_WEIGHT[s.severity]


def test_corpus_covers_the_core_threat_families():
    cats = {s.category for s in default_corpus()}
    for expected in (
        "prompt_injection",
        "sensitive_data",
        "protected_key",
        "memory_persistence",
        "benign",
    ):
        assert expected in cats


def test_corpus_stats_totals_are_consistent():
    stats = corpus_stats()
    assert stats["total"] == stats["malicious"] + stats["benign"]
    assert stats["malicious"] > 0 and stats["benign"] > 0


def test_severity_weights_are_strictly_ordered():
    assert (
        SEVERITY_WEIGHT[Severity.LOW]
        < SEVERITY_WEIGHT[Severity.MEDIUM]
        < SEVERITY_WEIGHT[Severity.HIGH]
        < SEVERITY_WEIGHT[Severity.CRITICAL]
    )
