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
