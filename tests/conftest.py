"""Optional compatibility modes for running the whole suite through the access gate.

Set ``AMG_TEST_MODE`` to re-run every existing test with the multi-agent code
paths switched on, without changing the tests:

- ``trace``: every guard records a decision trace (``trace=True``).
- ``allow-all``: every policy without access rules gets one rule that lets
  everyone do everything, so each operation goes through the access gate.

In both modes the results must match a normal run. The tests written for
access control, identity and tracing set these options themselves and are left
alone.
"""
from __future__ import annotations

import dataclasses
import os
import warnings

import pytest

_MODE = os.environ.get("AMG_TEST_MODE", "")
_OWN_MODULES = (
    "test_access_control",
    "test_identity_context",
    "test_decision_trace",
    "test_policy_yaml_guard",
)


@pytest.fixture(autouse=True)
def _amg_test_mode(request, monkeypatch):
    if not _MODE or request.module.__name__.rsplit(".", 1)[-1] in _OWN_MODULES:
        yield
        return
    if _MODE not in ("trace", "allow-all"):
        raise pytest.UsageError(f"Unknown AMG_TEST_MODE {_MODE!r}; use 'trace' or 'allow-all'")

    from agent_memory_guard import AccessRule
    from agent_memory_guard.guard import MemoryGuard
    from agent_memory_guard.policies.policy import Policy

    original_init = MemoryGuard.__init__

    def patched_init(self, store=None, **kwargs):
        if _MODE == "trace":
            kwargs.setdefault("trace", True)
        else:
            policy = kwargs.get("policy") or Policy.permissive()
            if dataclasses.is_dataclass(policy) and getattr(policy, "access", None) is None:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    kwargs["policy"] = policy.with_access(
                        AccessRule("allow_all", keys=["*"], writers=["*"], readers=["*"]),
                        default="allow",
                        admins=["*"],
                    )
        original_init(self, store, **kwargs)

    monkeypatch.setattr(MemoryGuard, "__init__", patched_init)
    yield
