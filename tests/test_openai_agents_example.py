"""Regression tests for the OpenAI Agents session-memory example (issue #8 slice)."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from agent_memory_guard import MemoryGuard, Policy


def _load_example():
    path = Path(__file__).resolve().parents[1] / "examples" / "openai_agents_memory_guard.py"
    name = "openai_agents_memory_guard_example"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # required so @dataclass annotations resolve
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def example():
    return _load_example()


def test_run_demo_blocks_injection_and_queues_hitl(example) -> None:
    summary = example.run_demo()
    assert summary["clean_committed"] is True
    assert summary["poison_committed"] is False
    assert summary["scratch_after"] is not None
    assert "Ignore previous instructions" not in str(summary["scratch_after"])
    assert len(summary["hitl_queue"]) == 1
    assert "web_search" in summary["hitl_queue"][0]["key"]


def test_remember_tool_output_commits_clean_value(example) -> None:
    memory = example.GuardedSessionMemory(guard=MemoryGuard(policy=Policy.strict()))
    assert memory.remember_tool_output("calc", "2+2=4") is True
    assert memory.recall("calc") == "2+2=4"
    assert memory.pending_hitl() == []
