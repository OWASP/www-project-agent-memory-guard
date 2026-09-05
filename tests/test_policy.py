import textwrap

from agent_memory_guard.events import Action, Severity
from agent_memory_guard.policies.policy import Policy, load_policy


def test_load_yaml_string():
    src = textwrap.dedent(
        """
        version: 1
        default_action: allow
        protected_keys: [system.*]
        immutable_keys: [identity.user_id]
        rules:
          - name: block_injection
            on: prompt_injection
            action: block
          - name: redact_secrets
            on: sensitive_data
            action: redact
        """
    )
    policy = load_policy(src)
    assert policy.default_action == Action.ALLOW
    assert "system.*" in policy.protected_keys
    assert policy.decide("prompt_injection", Severity.HIGH, "x") == Action.BLOCK
    assert policy.decide("sensitive_data", Severity.HIGH, "x") == Action.REDACT
    assert policy.decide("size_anomaly", Severity.MEDIUM, "x") == Action.ALLOW


def test_strict_policy_blocks_injection_and_redacts_secrets():
    p = Policy.strict()
    assert p.decide("prompt_injection", Severity.HIGH, "k") == Action.BLOCK
    assert p.decide("sensitive_data", Severity.HIGH, "k") == Action.REDACT
    assert p.decide("size_anomaly", Severity.MEDIUM, "k") == Action.QUARANTINE


def test_rule_filters_by_min_severity():
    p = load_policy(
        {
            "default_action": "allow",
            "rules": [
                {
                    "name": "only_high",
                    "on": "size_anomaly",
                    "action": "block",
                    "min_severity": "high",
                }
            ],
        }
    )
    assert p.decide("size_anomaly", Severity.MEDIUM, "k") == Action.ALLOW
    assert p.decide("size_anomaly", Severity.HIGH, "k") == Action.BLOCK


def test_protected_key_rule_without_keys_is_rejected():
    """A rule on protected_key with no keys declared can never fire.

    ProtectedKeyDetector only reports keys matching the policy's protected or
    immutable patterns, so with neither declared the rule is inert while the
    policy still loads and the guard still enforces its other rules. Nothing
    downstream reveals it, so it has to be caught at load time.
    """
    import pytest

    data = {
        "default_action": "allow",
        "rules": [
            {"name": "block_injection", "on": "prompt_injection", "action": "block"},
            {"name": "block_protected_key", "on": "protected_key", "action": "block"},
        ],
    }

    with pytest.raises(ValueError) as excinfo:
        Policy.from_dict(data)

    message = str(excinfo.value)
    assert "block_protected_key" in message
    assert "protected_keys" in message


def test_protected_key_rule_accepts_either_key_list():
    """Either list is enough to make the rule reachable."""
    base = {
        "default_action": "allow",
        "rules": [
            {"name": "block_protected_key", "on": "protected_key", "action": "block"},
        ],
    }

    assert Policy.from_dict({**base, "protected_keys": ["identity.*"]}).protected_keys == (
        "identity.*",
    )
    assert Policy.from_dict({**base, "immutable_keys": ["identity.*"]}).immutable_keys == (
        "identity.*",
    )


def test_policy_without_a_protected_key_rule_still_loads_with_no_keys():
    """Only rules on that detector are affected; nothing else changes."""
    data = {
        "default_action": "allow",
        "rules": [
            {"name": "block_injection", "on": "prompt_injection", "action": "block"},
        ],
    }

    policy = Policy.from_dict(data)
    assert policy.protected_keys == ()
    assert [r.name for r in policy.rules] == ["block_injection"]
