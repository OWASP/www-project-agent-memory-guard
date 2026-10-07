"""YAML policies: per-agent fields fail loudly instead of being silently dropped.

0.3 ignored unknown fields, so a rule such as ``agents: [supervisor]`` turned
"only the supervisor" into "anyone". Fields that can only mean per-agent
permissions are now an error; other unknown fields give a PolicyWarning.
"""
import warnings
from pathlib import Path

import pytest

from agent_memory_guard import PolicyWarning
from agent_memory_guard.policies.policy import load_policy

ROOT = Path(__file__).resolve().parent.parent

SILENT_DROP_03 = """
version: 1
protected_keys: ["plan.*"]
rules:
  - name: plan_only_supervisor
    on: protected_key
    action: block
    agents: [supervisor]
"""


def test_the_03_silent_drop_policy_now_fails_with_a_hint():
    with pytest.raises(ValueError, match=r"per-agent field\(s\) \['agents'\]") as exc:
        load_policy(SILENT_DROP_03)
    assert "Policy.with_access" in str(exc.value)


@pytest.mark.parametrize(
    "field",
    ["agent", "agents", "writers", "writer", "readers", "reader", "principal", "principals",
     "access", "Agents", "WRITERS"],
)
def test_access_fields_on_a_rule_are_errors(field):
    with pytest.raises(ValueError, match="per-agent"):
        load_policy({"rules": [{"name": "r", "on": "prompt_injection", "action": "block", field: ["x"]}]})


@pytest.mark.parametrize("section", ["access", "principals", "agents", "ACCESS", "Principals"])
def test_access_sections_are_errors_until_yaml_supports_them(section):
    with pytest.raises(ValueError, match="not read from YAML"):
        load_policy({section: {"supervisor": {}}, "rules": []})


@pytest.mark.parametrize("field", ["owner", "role", "actor_role", "allowed_agents", "only"])
def test_other_unknown_rule_fields_warn_and_still_load(field):
    with pytest.warns(PolicyWarning, match=field):
        policy = load_policy(
            {"rules": [{"name": "r", "on": "prompt_injection", "action": "block", field: "secops"}]}
        )
    assert [r.name for r in policy.rules] == ["r"]


def test_unknown_top_level_fields_warn_at_the_callers_line():
    with pytest.warns(PolicyWarning, match="description") as record:
        load_policy({"description": "team policy", "rules": []})
    assert record[0].filename == __file__


@pytest.mark.parametrize(
    "path", ["examples/policy.yaml", "templates/secure-agent-starter/policy.yaml"]
)
def test_shipped_policies_load_without_warnings(path):
    with warnings.catch_warnings():
        warnings.simplefilter("error", PolicyWarning)
        policy = load_policy(ROOT / path)
    assert policy.rules
