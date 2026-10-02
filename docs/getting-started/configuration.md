# Configuration

Agent Memory Guard is configured in Python: choose a policy (a preset or your own
rules), optionally choose the detectors, and pass both to `MemoryGuard`.

## Python configuration

```python
from agent_memory_guard import MemoryGuard, Policy

guard = MemoryGuard(
    policy=Policy.strict(),       # or Policy.permissive(), Policy.tiered()
    snapshot_on_block=True,       # capture a snapshot before each block (default)
    current_task="task_123",      # enables cross-task contamination checks
)
```

| Preset | What it does |
|--------|--------------|
| `Policy.permissive()` | Allows every write and records findings as events (detect and log). |
| `Policy.strict()` | Blocks prompt injection and writes to `identity.*`, `system.*` and `agent.goal`; redacts secrets and PII; quarantines size and rapid-change anomalies. |
| `Policy.tiered()` | Per-namespace rules: `credentials.*` and `permissions.*` are locked down, `facts.*` findings are quarantined for review, `preferences.*` are redacted, `tool_results.*` and `scratch.*` stay writable. |

## Policy files (YAML)

Load a policy from a YAML file, a YAML string or a dict with `load_policy`:

```yaml
# policy.yaml
version: 1
default_action: allow

protected_keys:
  - system.*
  - identity.role

immutable_keys:
  - identity.user_id

rules:
  - name: block_prompt_injection
    on: prompt_injection
    action: block

  - name: redact_sensitive_data
    on: sensitive_data
    action: redact

  - name: block_protected_key_writes
    on: protected_key
    action: block

  - name: quarantine_size_anomaly
    on: size_anomaly
    action: quarantine
    min_severity: medium
```

```python
from agent_memory_guard import MemoryGuard
from agent_memory_guard.policies import load_policy

guard = MemoryGuard(policy=load_policy("policy.yaml"))
```

| Field | Meaning |
|-------|---------|
| `version` | Schema version. Use `1`. |
| `default_action` | Action when no rule matches a finding: `allow` (default), `redact`, `quarantine` or `block`. |
| `protected_keys` | Glob patterns. A write to a matching key raises a `protected_key` finding. |
| `immutable_keys` | Glob patterns. Protected like `protected_keys`, and the first committed value is integrity-baselined; a value changed outside the guard raises `IntegrityError` on read. |
| `rules[].name` | A label for the rule. |
| `rules[].on` | The detector whose findings the rule handles, for example `prompt_injection`, `sensitive_data`, `protected_key`, `size_anomaly`, `rapid_change`, `cross_task_contamination`, `self_reinforcement`, `memory_persistence_injection`. |
| `rules[].action` | `allow`, `redact`, `quarantine` or `block`. |
| `rules[].min_severity` | Only findings at or above this severity: `low` (default), `medium`, `high`, `critical`. |
| `rules[].keys` | Optional glob patterns that limit the rule to some keys. |

For each finding the first matching rule decides; when one write has several
findings, the strongest action wins (`block` > `quarantine` > `redact` > `allow`).
A rule `on: protected_key` with no `protected_keys` or `immutable_keys` is rejected
at load time, because it could never fire.

`PolicyViolation` is raised only for `block`. Redacted and quarantined writes return
`Action.REDACT` / `Action.QUARANTINE`, so check the return value of `guard.write()`.

## Detectors

The default suite is `prompt_injection`, `sensitive_data`, `size_anomaly`,
`rapid_change`, `protected_key`, `cross_task_contamination` and `self_reinforcement`.
Opt-in detectors include `memory_persistence_injection`, `privilege_escalation`,
`tool_abuse`, `excessive_autonomy` and an ML classifier (`pip install
agent-memory-guard[ml]`).

Passing `detectors=[...]` replaces the first four; the protected-key, cross-task and
self-reinforcement detectors are always added. A detector's findings only change the
outcome if a rule handles them, so add a rule when you add a detector:

```python
from agent_memory_guard import Action, MemoryGuard, Policy
from agent_memory_guard.detectors import (
    MemoryPersistenceInjectionDetector,
    PromptInjectionDetector,
    RapidChangeDetector,
    SensitiveDataDetector,
    SizeAnomalyDetector,
)
from agent_memory_guard.detectors.leakage import DEFAULT_LEAKAGE_PATTERNS
from agent_memory_guard.policies import PolicyRule

policy = Policy.strict()
policy.rules.append(
    PolicyRule("block_persistence", "memory_persistence_injection", Action.BLOCK)
)

guard = MemoryGuard(
    policy=policy,
    detectors=[
        PromptInjectionDetector(),
        SensitiveDataDetector(
            patterns={**DEFAULT_LEAKAGE_PATTERNS, "internal_id": r"INTERNAL-\d+"}
        ),
        SizeAnomalyDetector(max_bytes=32 * 1024),
        RapidChangeDetector(),
        MemoryPersistenceInjectionDetector(),
    ],
)
```

## API server settings

`amg serve` takes `--host` (default `127.0.0.1`), `--port` (default `8000`) and
`--policy` (`permissive`, `strict` or `tiered`; default `strict`). The server has no
authentication, so binding a non-loopback address prints a warning.

| Variable | Default | Description |
|----------|---------|-------------|
| `AMG_POLICY` | `strict` | Policy for the server's guard. `amg serve --policy` sets it for you. |
| `AMG_CORS_ORIGINS` | empty (CORS off) | Comma-separated exact origins allowed to call the API from a browser. `*` is refused. |

## Logging

AMG uses Python's standard `logging` module under the `agent_memory_guard` logger:

```python
import logging
logging.getLogger("agent_memory_guard").setLevel(logging.DEBUG)
```
