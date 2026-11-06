"""Regression tests for the deja-vu recall screening example (issue #199)."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def _load_example():
    path = Path(__file__).resolve().parents[1] / "examples" / "deja_vu_recall_guard.py"
    name = "deja_vu_recall_guard_example"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def example():
    return _load_example()


def test_run_demo_allows_clean_redacts_secret_and_blocks_injection(example) -> None:
    result = example.run_demo()
    reinjected = result["reinjected"]
    blocked = result["blocked"]

    assert len(reinjected) == 2
    assert reinjected[0]["session_id"] == "ses_clean_01"
    assert reinjected[0]["action"] == "allow"
    assert "PRAGMA busy_timeout = 5000" in reinjected[0]["text"]

    assert reinjected[1]["session_id"] == "ses_secret_02"
    assert reinjected[1]["action"] == "redact"
    assert "sk-" + "A" * 40 not in reinjected[1]["text"]

    assert len(blocked) == 1
    assert blocked[0]["session_id"] == "ses_poison_03"
