# Integrations

Agent Memory Guard provides drop-in integrations for popular AI agent frameworks. Each integration wraps the framework's memory layer with AMG's detection engine, requiring minimal code changes.

## Supported Frameworks

| Framework | Integration Type | Install Extra |
|-----------|-----------------|---------------|
| [LangChain](langchain.md) | Custom memory class | `langchain` |
| [CrewAI](crewai.md) | Callback handler | `crewai` |
| [LlamaIndex](llamaindex.md) | Guarded chat store | `llamaindex` |
| [GitHub Actions](github-actions.md) | CI/CD action | (none) |

## Installation

```bash
# Install specific integration
pip install agent-memory-guard[langchain]
pip install agent-memory-guard[crewai]
pip install agent-memory-guard[llamaindex]

# Install all integrations
pip install agent-memory-guard[all]
```

## General Pattern

All integrations follow the same pattern:

1. Create a `MemoryGuard` instance with your desired policy
2. Wrap the framework's memory component with the AMG integration
3. Use the wrapped component as a drop-in replacement

```python
from agent_memory_guard import MemoryGuard, Policy

# Step 1: Configure the guard
guard = MemoryGuard(policy=Policy.strict())

# Step 2: Wrap framework memory (varies by framework)
guarded_memory = FrameworkIntegration(original_memory, guard=guard)

# Step 3: Use as normal — AMG screens all operations transparently
agent = Agent(memory=guarded_memory)
```

## FAQ

**Using `langchain.agents.create_agent`?** See the [LangChain integration page](langchain.md#middleware-for-create_agent) for the middleware how-to, a public clinic, and how to add your team to adopters.
