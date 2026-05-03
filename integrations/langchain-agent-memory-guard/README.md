# langchain-agent-memory-guard

[![PyPI](https://img.shields.io/pypi/v/langchain-agent-memory-guard)](https://pypi.org/project/langchain-agent-memory-guard/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/OWASP/www-project-agent-memory-guard/blob/main/LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-Incubator-blue)](https://owasp.org/www-project-agent-memory-guard/)

**LangChain middleware integration for [OWASP Agent Memory Guard](https://github.com/OWASP/www-project-agent-memory-guard)** — runtime defense against AI agent memory poisoning attacks (OWASP ASI06).

## Overview

This middleware protects LangChain agents by scanning model inputs, outputs, and tool results for:

- **Prompt injection** — Detects injected instructions hidden in memory/context
- **Secret leakage** — Catches API keys, tokens, and credentials in responses
- **Content anomalies** — Flags abnormally large payloads that may indicate stuffing attacks
- **Protected key tampering** — Prevents unauthorized modification of critical memory fields

## Installation

```bash
pip install langchain-agent-memory-guard
```

## Quick Start

```python
from langchain_agent_memory_guard import MemoryGuardMiddleware
from langchain.agents import create_agent

# Basic usage with strict security policy (recommended)
agent = create_agent(
    "openai:gpt-4o",
    tools=[my_search_tool, my_db_tool],
    middleware=[MemoryGuardMiddleware()],
)

# The agent is now protected — any memory poisoning attempts
# in tool outputs or context will be detected and blocked
result = agent.invoke({"messages": [("user", "Search for recent news")]})
```

## Configuration

### Violation Handling Modes

```python
# Block mode (default) — raises MemoryGuardViolation on detection
middleware = MemoryGuardMiddleware(on_violation="block")

# Warn mode — logs warning but allows execution to continue
middleware = MemoryGuardMiddleware(on_violation="warn")

# Strip mode — silently removes violating content
middleware = MemoryGuardMiddleware(on_violation="strip")
```

### Custom Security Policy

```python
from agent_memory_guard import Policy, PolicyRule

# Only check for injection and secrets (skip size checks)
policy = Policy(rules=[PolicyRule.NO_INJECTION, PolicyRule.NO_SECRETS])
middleware = MemoryGuardMiddleware(policy=policy)

# Full strict policy with custom protected keys
policy = Policy.strict(protected_keys=["user.api_key", "system.config"])
middleware = MemoryGuardMiddleware(policy=policy)
```

## How It Works

The middleware hooks into three points in the LangChain agent loop:

| Hook | What It Scans | Threat Mitigated |
|------|--------------|-----------------|
| `before_model` | Messages in agent state | Injection in memory/context |
| `after_model` | Model response content | Secret leakage, injection propagation |
| `wrap_tool_call` | Tool output content | Injection via tool results (primary attack vector) |

### Why Tool Output Scanning Matters

Tool outputs are the **primary vector** for memory poisoning. An attacker can embed prompt injection payloads in:
- Web pages fetched by a search tool
- Database records returned by a query tool
- API responses from external services

This middleware catches these attacks before they can influence the agent's behavior.

## Error Handling

```python
from langchain_agent_memory_guard import MemoryGuardMiddleware
from langchain_agent_memory_guard.middleware import MemoryGuardViolation

middleware = MemoryGuardMiddleware(on_violation="block")

try:
    result = agent.invoke({"messages": [("user", "Process this data")]})
except MemoryGuardViolation as e:
    print(f"Attack detected: {e}")
    # Handle the violation (alert, log, fallback response, etc.)
```

## Metrics

```python
middleware = MemoryGuardMiddleware()
# ... after running the agent ...
print(f"Total violations detected: {middleware.violation_count}")
```

## Related

- [OWASP Agent Memory Guard](https://github.com/OWASP/www-project-agent-memory-guard) — Core library
- [OWASP Agentic Security Initiative (ASI06)](https://owasp.org/www-project-agentic-security-initiative/) — The threat model
- [agent-memory-guard on PyPI](https://pypi.org/project/agent-memory-guard/) — Core package

## License

Apache 2.0
