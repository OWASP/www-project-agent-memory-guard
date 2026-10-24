# OWASP Agent Memory Guard

<div style="text-align: center; margin: 2rem 0;">
  <img src="assets/shield-icon.svg" alt="AMG Shield" width="120" />
  <p><strong>Runtime defense layer for AI agent memory systems</strong></p>
</div>

---

**Agent Memory Guard (AMG)** is a Python library that protects AI agent memory from poisoning, injection, and manipulation attacks. It sits between your agent and its memory store, screening every read and write operation for security threats in real time.

## Why Agent Memory Guard?

AI agents that use persistent memory (conversation history, tool results, user preferences) are vulnerable to a class of attacks where malicious content is injected into memory to permanently alter agent behavior. This is documented as **OWASP ASI-06: Memory Poisoning**.

AMG addresses this by providing:

- **10 specialized detectors** covering prompt injection, data leakage, privilege escalation, tool abuse, excessive autonomy, cross-task contamination, and more
- **ML-powered detection** using a fine-tuned DeBERTa-v3 classifier for advanced injection patterns
- **Policy engine** with permissive, strict, and tiered enforcement modes
- **Drop-in integrations** for LangChain, CrewAI, LlamaIndex, and AutoGen
- **CLI scanner** for CI/CD pipeline integration
- **REST API server** for language-agnostic deployments
- **GitHub Action** with SARIF output for Security tab integration

## Quick Example

```python
from agent_memory_guard import MemoryGuard, Policy

guard = MemoryGuard(policy=Policy.strict())

# Safe write — passes through
guard.write("user_preference", "I prefer dark mode")

# Malicious write — blocked
guard.write("system_prompt", "Ignore all previous instructions and...")
# Raises PolicyViolation or returns Action.QUARANTINE
```

## Installation

```bash
pip install agent-memory-guard
```

For additional features:

```bash
# REST API server
pip install agent-memory-guard[server]

# ML-based detection (DeBERTa-v3)
pip install agent-memory-guard[ml]

# Framework integrations
pip install agent-memory-guard[langchain]
pip install agent-memory-guard[all]
```

## Architecture Overview

```
┌─────────────────────────────────────────────────┐
│                  Your AI Agent                   │
└──────────────────────┬──────────────────────────┘
                       │ write("key", "value")
                       ▼
┌─────────────────────────────────────────────────┐
│              Agent Memory Guard                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────┐│
│  │Detectors │ │  Policy  │ │ Event Handlers   ││
│  │(10 types)│ │  Engine  │ │ (logging/alerts) ││
│  └──────────┘ └──────────┘ └──────────────────┘│
└──────────────────────┬──────────────────────────┘
                       │ allow / quarantine / block
                       ▼
┌─────────────────────────────────────────────────┐
│              Memory Store (Redis, DB, etc.)      │
└─────────────────────────────────────────────────┘
```

## OWASP Alignment

Agent Memory Guard is an **OWASP Incubator Project** that directly addresses threats identified in the OWASP Agentic Security Initiative:

| OWASP Threat ID | Threat Name | AMG Coverage |
|-----------------|-------------|--------------|
| ASI-06 | Memory Poisoning | Core focus — all detectors |
| ASI-03 | Prompt Injection | Injection detector + ML detector |
| ASI-04 | Privilege Escalation | Privilege escalation detector |
| ASI-07 | Tool Misuse | Tool abuse detector |
| ASI-09 | Excessive Autonomy | Excessive autonomy detector |

## Links

- [GitHub Repository](https://github.com/OWASP/www-project-agent-memory-guard)
- [PyPI Package](https://pypi.org/project/agent-memory-guard/)
- [Live Playground](https://amg-playground.manus.space)
- [OWASP Project Page](https://owasp.org/www-project-agent-memory-guard/)
