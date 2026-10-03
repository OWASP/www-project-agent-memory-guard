"""Regression tests for CLI configuration propagation."""
from __future__ import annotations

import argparse
import os
import sys
from types import SimpleNamespace

from agent_memory_guard.cli import cmd_serve


def test_cmd_serve_propagates_policy_before_uvicorn_import(monkeypatch):
    """The CLI policy choice must reach server.py through AMG_POLICY."""
    captured: dict[str, object] = {}

    def fake_run(app: str, **kwargs: object) -> None:
        captured["app"] = app
        captured.update(kwargs)
        captured["policy_at_server_import"] = os.environ["AMG_POLICY"]

    monkeypatch.setitem(sys.modules, "uvicorn", SimpleNamespace(run=fake_run))
    monkeypatch.delenv("AMG_POLICY", raising=False)

    args = argparse.Namespace(
        host="127.0.0.1",
        port=8000,
        reload=False,
        policy="tiered",
    )

    assert cmd_serve(args) == 0
    assert captured == {
        "app": "agent_memory_guard.server:app",
        "host": "127.0.0.1",
        "port": 8000,
        "reload": False,
        "policy_at_server_import": "tiered",
    }
