# Semgrep Rules for Agent Memory Security

Static analysis rules that flag unguarded memory writes in AI agent code and recommend Agent Memory Guard as the remediation.

## Rules

| Rule ID | What it catches |
|---------|----------------|
| `unguarded-agent-memory-write` | Direct dict/store writes to memory-like variables |
| `unguarded-mem0-add` | Unscreened `mem0_client.add()` calls |
| `unguarded-langchain-history-append` | Unguarded LangChain chat history writes |
| `unguarded-autogen-history-append` | Unguarded conversation history appends (AutoGen/CrewAI) |

## Usage

```bash
# Install semgrep
pip install semgrep

# Scan your project
semgrep --config ./semgrep/agent-memory-unguarded.yaml /path/to/your/agent/code

# Or scan from the registry (once published)
semgrep --config r/owasp.agent-memory-guard /path/to/your/agent/code
```

## Tests

Each rule ships with annotated true-positive (`# ruleid:`) and true-negative
(`# ok:`) cases in `agent-memory-unguarded.py`, following the
[semgrep-rules](https://github.com/semgrep/semgrep-rules) testing convention:

```bash
semgrep --test semgrep/
```

## What gets flagged

```python
# ⚠️ FLAGGED: unguarded memory write
agent_memory["session.context"] = tool_response

# ✓ SAFE: guarded with AMG
from agent_memory_guard import MemoryGuard, Policy
guard = MemoryGuard(policy=Policy.strict())
guard.write("session.context", tool_response)
```

## Why this matters

Memory poisoning (OWASP ASI06) is an attack where malicious content is written into an AI agent's persistent memory. Unlike prompt injection at the input layer, poisoned memory:

- **Survives context resets** — the attack persists across sessions
- **Bypasses input filters** — it enters through tools, RAG, or shared stores
- **Escalates over time** — the agent treats poisoned memory as trusted context

These Semgrep rules catch the vulnerability at development time. Agent Memory Guard fixes it at runtime.

## References

- [OWASP Agent Memory Guard](https://github.com/OWASP/www-project-agent-memory-guard)
- [OWASP Top 10 for Agentic Applications — ASI06](https://owasp.org/www-project-top-10-for-llm-applications/)
