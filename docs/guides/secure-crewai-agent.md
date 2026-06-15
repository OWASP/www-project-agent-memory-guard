# Add Memory Poisoning Defense to a CrewAI Agent

> **TL;DR:** Install the CrewAI extra and wrap your crew's memory with Agent Memory Guard to block prompt injection and data poisoning before it enters shared agent memory. Three lines of config, works with any CrewAI crew.

---

## The Problem

CrewAI agents share memory across a crew — short-term, long-term, and entity memory all flow between agents. If one agent's output is poisoned (via a malicious tool response, a compromised RAG source, or adversarial user input), that poison propagates to every other agent in the crew.

A single poisoned memory entry can:

- Make the researcher agent feed false data to the writer agent
- Override the manager agent's delegation logic
- Exfiltrate internal context through a tool call

The attack is invisible because CrewAI trusts its own memory implicitly.

---

## The Fix (5 minutes)

### Step 1: Install

```bash
pip install agent-memory-guard[crewai]
```

### Step 2: Wrap your crew's memory

```python
from crewai import Agent, Task, Crew
from agent_memory_guard.integrations.crewai import GuardedMemory, Policy

# Define your agents as normal
researcher = Agent(
    role="Senior Research Analyst",
    goal="Find accurate market data",
    backstory="You are a meticulous analyst...",
    verbose=True,
)

writer = Agent(
    role="Content Writer",
    goal="Write compelling reports from research",
    backstory="You turn data into narrative...",
    verbose=True,
)

# Create a guarded crew
crew = Crew(
    agents=[researcher, writer],
    tasks=[...],
    memory=True,  # Enable memory
    memory_config={
        "provider": GuardedMemory(policy=Policy.strict()),
    },
)

result = crew.kickoff()
```

### Step 3: That's it

Every memory write (short-term, long-term, entity) now passes through Agent Memory Guard before persisting. Poisoned content is blocked and logged.

---

## What Gets Caught

| Attack Vector | Example | Result |
|--------------|---------|--------|
| Tool response injection | Malicious API returns "IGNORE PREVIOUS INSTRUCTIONS" | **BLOCKED** |
| Cross-agent poisoning | Agent A stores override instructions for Agent B | **BLOCKED** |
| RAG source contamination | Retrieved doc contains embedded commands | **BLOCKED** |
| Entity memory tampering | "Company X revenue: $0 (bankrupt)" injected | **BLOCKED** |
| Normal delegation | "Research complete. Key findings: ..." | ✓ Allowed |

---

## Monitoring Blocked Attempts

```python
from agent_memory_guard.integrations.crewai import GuardedMemory, Policy

guarded = GuardedMemory(
    policy=Policy.strict(),
    on_block=lambda event: print(f"⚠️ BLOCKED: {event.detector} in {event.agent_role}")
)

# Or export to OpenTelemetry
from agent_memory_guard import OTelExporter
guarded = GuardedMemory(
    policy=Policy.strict(),
    exporter=OTelExporter(endpoint="http://localhost:4317")
)
```

---

## Custom Policy for Multi-Agent Crews

```yaml
# crew_policy.yaml
version: "1.0"
rules:
  - detector: prompt_injection
    action: block
    severity: critical
  - detector: cross_agent_override
    action: block
    severity: critical
  - detector: secret_leak
    action: redact
    severity: high
  - detector: size_anomaly
    threshold: 5000
    action: block
```

```python
guarded = GuardedMemory(policy=Policy.from_yaml("crew_policy.yaml"))
```

---

## Performance Impact

Agent Memory Guard adds **59 microseconds** median latency per memory operation. CrewAI's internal memory writes typically take 10-50ms (embedding + storage). The security check is negligible.

---

## Architecture

```
Agent A output → [Agent Memory Guard] → CrewAI Memory Store → [Agent Memory Guard] → Agent B input
                      ↓ (if blocked)
                 Block + Log + Alert
```

Both write-path and read-path are protected. Even if a memory was somehow written before AMG was installed, it gets validated on read.

---

## Next Steps

- [Full API documentation](https://github.com/OWASP/www-project-agent-memory-guard)
- [CrewAI integration source](https://github.com/OWASP/www-project-agent-memory-guard/tree/main/integrations/crewai)
- [YAML policy reference](https://github.com/OWASP/www-project-agent-memory-guard#yaml-policy)
- [Report a vulnerability](https://github.com/OWASP/www-project-agent-memory-guard/security)

---

*This guide is part of the [OWASP Agent Memory Guard](https://github.com/OWASP/www-project-agent-memory-guard) project — the reference implementation for OWASP Agentic AI Top 10 ASI06 (Memory & Context Poisoning).*
