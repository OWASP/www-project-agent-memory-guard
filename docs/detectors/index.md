# Detectors

Agent Memory Guard uses a modular detector architecture. Each detector specializes in identifying a specific class of memory security threat. Detectors run in sequence on every memory write operation and return findings with severity levels.

## Available Detectors

| Detector | Threat Category | Severity Range | OWASP ID |
|----------|----------------|----------------|----------|
| [Prompt Injection](injection.md) | Instruction hijacking | HIGH–CRITICAL | ASI-03 |
| [Sensitive Data Leakage](leakage.md) | Data exfiltration | MEDIUM–HIGH | ASI-06 |
| [Privilege Escalation](privilege-escalation.md) | Unauthorized access | HIGH–CRITICAL | ASI-04 |
| [Tool Abuse](tool-abuse.md) | Dangerous tool invocation | MEDIUM–CRITICAL | ASI-07 |
| [Excessive Autonomy](excessive-autonomy.md) | Agent overreach | MEDIUM–HIGH | ASI-09 |
| [Cross-Task Contamination](cross-task.md) | Task boundary violation | MEDIUM–HIGH | ASI-06 |
| [Self-Reinforcement](self-reinforcement.md) | Feedback loop manipulation | MEDIUM–HIGH | ASI-06 |
| [ML-Based Detection](ml-detection.md) | Advanced injection (DeBERTa-v3) | HIGH–CRITICAL | ASI-03 |
| Size Anomaly | Unusually large values | LOW–MEDIUM | ASI-06 |
| Rapid Change | Suspicious write frequency | LOW–MEDIUM | ASI-06 |

## How Detectors Work

Each detector implements the `Detector` protocol: a `name` and an `inspect()` method that is called for every memory operation:

```python
from typing import Any

from agent_memory_guard.detectors.base import DetectionResult, Detector

class MyDetector(Detector):
    name = "my_detector"

    def inspect(self, key: str, value: Any, *, operation: str) -> DetectionResult:
        # Analyze the key-value pair for a "read" or "write" operation
        # Return DetectionResult with matched, severity, message, metadata
        ...
```

## Severity Levels

| Level | Meaning | Default Action (Strict) |
|-------|---------|------------------------|
| CRITICAL | Immediate security risk | Block/Quarantine |
| HIGH | Likely attack attempt | Block/Quarantine |
| MEDIUM | Suspicious pattern | Log + Alert |
| LOW | Minor anomaly | Log |
| INFO | Informational | Allow |

## Enabling/Disabling Detectors

By default, all rule-based detectors are enabled. The ML detector requires the `ml` extra.

```python
from agent_memory_guard import MemoryGuard
from agent_memory_guard.detectors.injection import PromptInjectionDetector
from agent_memory_guard.detectors.leakage import SensitiveDataDetector

# Use only specific detectors
guard = MemoryGuard(detectors=[
    PromptInjectionDetector(),
    SensitiveDataDetector(),
])
```

## Custom Detectors

You can create custom detectors by implementing the `Detector` protocol:

```python
from typing import Any

from agent_memory_guard import Severity
from agent_memory_guard.detectors.base import DetectionResult, Detector

class CompanyPolicyDetector(Detector):
    """Detect violations of company-specific memory policies."""

    name = "company_policy"

    def inspect(self, key: str, value: Any, *, operation: str) -> DetectionResult:
        if "CONFIDENTIAL" in str(value).upper():
            return DetectionResult(
                detector=self.name,
                matched=True,
                severity=Severity.HIGH,
                message="Confidential data should not be stored in agent memory",
            )
        return DetectionResult(detector=self.name, matched=False)
```

Register it with the guard. Passing `detectors=` replaces the default rule-based detectors, so list the ones you want to keep, and add a policy rule for the detector's `name` so its matches are acted on:

```python
from agent_memory_guard import Action, MemoryGuard, Policy
from agent_memory_guard.detectors import (
    PromptInjectionDetector,
    RapidChangeDetector,
    SensitiveDataDetector,
    SizeAnomalyDetector,
)
from agent_memory_guard.policies import PolicyRule

policy = Policy.strict()
policy.rules.append(PolicyRule("block_company_policy", "company_policy", Action.BLOCK))

guard = MemoryGuard(
    policy=policy,
    detectors=[
        PromptInjectionDetector(),
        SensitiveDataDetector(),
        SizeAnomalyDetector(),
        RapidChangeDetector(),
        CompanyPolicyDetector(),
    ],
)
```
