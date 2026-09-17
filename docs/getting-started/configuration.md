# Configuration

Agent Memory Guard can be configured in Python, with a YAML policy file, and—only for the optional REST server—with the environment variables documented below.

## Python policy configuration

The default `MemoryGuard()` policy is permissive: findings can be detected and recorded, but unmatched operations are allowed. Select an enforcement policy deliberately.

```python
from agent_memory_guard import MemoryGuard, Policy

guard = MemoryGuard(
    policy=Policy.strict(),
    snapshot_on_block=True,
    current_task="task_123",
)
```

Available presets are `Policy.permissive()`, `Policy.strict()`, and `Policy.tiered()`. A preset is a starting point, not a complete authorization policy. Review its protected-key patterns and detector rules against your own namespaces and threat model.

## YAML policy files

A policy file uses the same fields as `Policy.from_dict`: `version`, `default_action`, `protected_keys`, `immutable_keys`, and an ordered list of `rules`.

```yaml
version: 1
default_action: allow

protected_keys:
  - "system.*"
  - "identity.role"

immutable_keys:
  - "identity.user_id"

rules:
  - name: block_prompt_injection
    on: prompt_injection
    action: block
    min_severity: low

  - name: redact_sensitive_data
    on: sensitive_data
    action: redact
    min_severity: low

  - name: block_protected_key_changes
    on: protected_key
    action: block
    min_severity: low

  - name: quarantine_size_anomalies
    on: size_anomaly
    action: quarantine
    min_severity: low
```

Load and use the policy explicitly:

```python
from agent_memory_guard import MemoryGuard, Policy

policy = Policy.from_yaml(".amg-policy.yml")
guard = MemoryGuard(policy=policy)
```

Rules are evaluated in order and the first applicable rule supplies the action. When no rule applies, `default_action` is used. Supported actions are `allow`, `redact`, `quarantine`, and `block`. A protected-key rule is ineffective without matching `protected_keys`; current policy parsing rejects that inconsistent configuration.

## REST server configuration

Install the server extra and start it on loopback:

```bash
pip install "agent-memory-guard[server]"
amg serve --host 127.0.0.1 --port 8000
```

`amg serve` binds to `127.0.0.1` by default. The server does **not** implement built-in authentication, authorization, TLS, tenant isolation, or rate limiting. Do not bind it to a non-loopback interface unless an authenticated, authorized, TLS-terminating gateway and network controls protect it.

### Environment variables actually read by the server

| Variable | Default | Behavior |
|---|---|---|
| `AMG_POLICY` | `strict` | Selects `permissive`, `strict`, or `tiered` when the server module initializes. An unrecognized value currently falls back to `strict`. |
| `AMG_CORS_ORIGINS` | empty | When empty, browser CORS middleware is not installed. To enable browser access, provide a comma-separated allowlist of exact origins. The wildcard `*` is rejected. |

Example:

```bash
AMG_POLICY=tiered \
AMG_CORS_ORIGINS="https://console.example.org" \
amg serve --host 127.0.0.1 --port 8000
```

Host, port, and reload are command-line options (`--host`, `--port`, and `--reload`), not `AMG_HOST`, `AMG_PORT`, or `AMG_LOG_LEVEL` environment variables in v0.3.2.

> **Known v0.3.2 limitation:** the `amg serve --policy ...` argument is displayed by the CLI but is not propagated into the imported server application. Set `AMG_POLICY` explicitly until the tracked fix is included in a release.

### CORS is not authentication

CORS restricts browser origins; it does not authenticate a client or protect non-browser access. Allowed origins can invoke the unauthenticated endpoints. Use the smallest exact origin list and keep the service on a protected network boundary.

## Detector configuration

Callers may supply a detector collection. AMG will still ensure that protected-key, cross-task, and self-reinforcement detectors are present.

```python
from agent_memory_guard import MemoryGuard, Policy
from agent_memory_guard.detectors.injection import PromptInjectionDetector
from agent_memory_guard.detectors.leakage import SensitiveDataDetector

guard = MemoryGuard(
    policy=Policy.strict(),
    detectors=[
        PromptInjectionDetector(),
        SensitiveDataDetector(custom_patterns=[r"INTERNAL-\d+"]),
    ],
)
```

Custom detector configuration changes the project’s tested security behavior. Add tests for the selected set and do not infer coverage from detectors that are not actually installed in the guard.

## Logging and sensitive data

AMG uses Python’s `logging` module under the `agent_memory_guard` logger:

```python
import logging

logging.getLogger("agent_memory_guard").setLevel(logging.INFO)
```

Events, logs, snapshots, quarantine values, and backing stores can contain sensitive content or metadata. Configure access, transport, retention, redaction, and deletion in the surrounding application and telemetry systems.
