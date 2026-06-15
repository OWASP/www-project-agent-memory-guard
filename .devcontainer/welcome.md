# 🛡️ Secure AI Agent Starter

Welcome! This environment has **OWASP Agent Memory Guard** pre-installed alongside popular agent frameworks.

## Quick Demo

Run the demo to see AMG block a memory poisoning attack:

```bash
python demo.py
```

## What's Installed

| Package | Purpose |
|---------|---------|
| `agent-memory-guard[all]` | Memory poisoning defense (OWASP ASI06) |
| `mem0ai` | Persistent agent memory |
| `crewai` | Multi-agent orchestration |
| `langchain` + `langgraph` | Agent framework + state graphs |
| `openai` | LLM provider |
| `jupyter` | Interactive notebooks |

## Try It

1. **Run the attack-then-block demo:** `python demo.py`
2. **Open the notebook:** `jupyter notebook examples/poison_and_protect.ipynb`
3. **Build your own agent:** Start from `templates/secure_agent.py`

## Learn More

- [Full documentation](https://github.com/OWASP/www-project-agent-memory-guard)
- [Integration guides](https://github.com/OWASP/www-project-agent-memory-guard/tree/main/docs/guides)
- [OWASP Agentic AI Top 10](https://owasp.org/www-project-agentic-ai-top-10/)
