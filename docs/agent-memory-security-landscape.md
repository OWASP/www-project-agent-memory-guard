# Agent Memory Security: The Options (2026)

A fair, honest comparison of tools that defend AI agent memory against poisoning attacks. This page exists because developers evaluating memory security deserve a clear picture of what's available, what each tool does well, and where the tradeoffs are.

Last updated: June 2026.

---

## The Problem

Any AI agent with persistent memory — vector stores, conversation history, RAG pipelines, or structured knowledge bases — is vulnerable to memory poisoning. An attacker injects malicious content into the memory layer, and the agent's behavior changes permanently. OWASP classifies this as **ASI06: Memory and Context Poisoning** in the Agentic AI Security Top 10.

The Agent Security Bench reports a highest average attack success rate of 84.30% across 27 attack and defense methods. No single tool solves this. Defense in depth is the only credible posture.

---

## The Tools

### OWASP Agent Memory Guard

| Attribute | Detail |
|-----------|--------|
| **Focus** | Write-time and read-time memory screening |
| **Architecture** | Drop-in middleware between agent and memory store |
| **License** | Apache 2.0 (fully open source) |
| **Backing** | OWASP Lab Project |
| **Install** | `pip install agent-memory-guard` |
| **Stars** | 44 (growing) |
| **Downloads** | 5,800+ |

**What it does well:**
- Purpose-built for memory poisoning (not repurposed from general guardrails)
- Screens both read and write paths through a YAML-driven detector pipeline
- Built-in detectors: prompt injection markers, secret/PII leakage, protected-key modifications, size anomalies
- SHA-256 cryptographic baselines for tamper detection
- Snapshot-based rollback to known-good memory states
- `allow` / `redact` / `quarantine` / `block` dispositions per detector
- Works with any memory store (Mem0, LangChain, LlamaIndex, custom)
- No vendor lock-in, no enterprise tier required

**Honest tradeoffs:**
- Smaller community (newer project, growing)
- No managed cloud offering (self-hosted only)
- No built-in SIEM integration (events are emitted; routing is your responsibility)
- Consolidation and behavioral monitoring layers are not in scope

**Best for:** Teams that want a standards-aligned, open-source baseline for Layer 1 (write-time controls) and Layer 3 (read-time screening) without vendor lock-in.

---

### Hindsight Memory Defense (Vectorize)

| Attribute | Detail |
|-----------|--------|
| **Focus** | Full-stack memory defense (5 layers) |
| **Architecture** | Native to Hindsight memory platform |
| **License** | OSS tier + Enterprise (proprietary) |
| **Stars** | 16,400+ |
| **Pricing** | Free (OSS, limited) / Enterprise (contact sales) |

**What it does well:**
- Full 5-layer defense model (write-time, sanitization, retrieval, scope isolation, monitoring)
- Enterprise tier: 7-stage pipeline with LLM-based credential detection, prompt injection blocking
- 220-pattern credential detection (detect-secrets + GitLeaks + native)
- HMAC-signed webhook delivery to SIEM (Splunk, Datadog, PagerDuty, Slack)
- Multi-scope memory architecture limits blast radius
- Per-bank policy granularity
- Large community and active development

**Honest tradeoffs:**
- OSS tier is limited (44-pattern regex only, no prompt injection detection, block downgraded to redact)
- Full defense requires Enterprise tier (paid, closed-source components)
- Tightly coupled to Hindsight platform (not drop-in for other memory stores)
- Enterprise pricing not publicly available

**Best for:** Teams already using Hindsight as their memory platform who want integrated defense, or enterprises that need full-stack coverage with SIEM integration and are willing to pay.

---

### General LLM Guardrails (NeMo, Guardrails AI, LLM Guard)

| Tool | Stars | Focus |
|------|-------|-------|
| NVIDIA NeMo Guardrails | ~4,000 | Conversational flow control, topic steering |
| Guardrails AI | ~4,000 | Output validation, structured generation |
| LLM Guard | ~4,000 | Input/output content scanning |

**What they do well:**
- Broad coverage of LLM safety concerns (toxicity, hallucination, topic drift)
- Mature ecosystems with large communities
- Good documentation and integration guides

**Honest tradeoffs:**
- Not designed for memory-specific attacks (session-level, not persistence-level)
- Don't address the temporal decoupling problem (attack today, effect next month)
- No memory-layer integration (operate at prompt/response boundary)
- No tamper detection or rollback capabilities for stored memories

**Best for:** Teams that need general LLM safety guardrails. These are complementary to memory-specific defenses, not substitutes.

---

### Lakera Guard / Rebuff

| Tool | Focus | Type |
|------|-------|------|
| Lakera Guard | Prompt injection detection | SaaS API |
| Rebuff | Prompt injection detection | OSS |

**What they do well:**
- Strong prompt injection detection at the input boundary
- Low-latency API calls suitable for production
- Lakera: continuously updated threat intelligence

**Honest tradeoffs:**
- Operate at the session boundary, not the memory write path
- Don't detect poisoning that arrives through legitimate channels (summarization, tool outputs)
- No memory-specific features (no tamper detection, no rollback, no provenance)
- Lakera: SaaS dependency, pricing per API call

**Best for:** Adding prompt injection detection at the API gateway level. Complementary to memory-layer defenses.

---

## How They Map to the Five Defense Layers

| Layer | AMG | Hindsight Enterprise | NeMo/Guardrails AI | Lakera/Rebuff |
|-------|-----|---------------------|-------------------|---------------|
| 1. Write-time input controls | **Full** | **Full** | Partial (session-level) | Partial (injection only) |
| 2. Sanitization + provenance | Partial (SHA-256 baselines) | **Full** | None | None |
| 3. Trust-aware retrieval | **Read-path screening** | Substrate provided | None | None |
| 4. Scope isolation | Not in scope | **Full** | None | None |
| 5. Behavioral monitoring | Events emitted | **Full** (SIEM integration) | None | None |

---

## Decision Framework

**Choose OWASP Agent Memory Guard if:**
- You want a standards-aligned open-source baseline
- You use any memory store (not just Hindsight)
- You need both read and write path screening
- You want zero vendor lock-in
- You're building compliance documentation against OWASP ASI06
- Budget is constrained (fully free, no enterprise tier needed)

**Choose Hindsight Memory Defense if:**
- You're already on the Hindsight platform
- You need full 5-layer coverage with SIEM integration
- You have enterprise budget for the full pipeline
- You need managed audit trails with HMAC-signed delivery

**Layer AMG + Hindsight if:**
- You want the standards-aligned baseline (AMG) plus the full enterprise stack (Hindsight)
- Vectorize themselves recommend this combination in their documentation

**Add general guardrails (NeMo, Guardrails AI) regardless:**
- These address different threat vectors (toxicity, hallucination, topic drift)
- They're complementary to memory-specific defenses, not alternatives

---

## Further Reading

- [OWASP Agentic AI Security Top 10](https://owasp.org/www-project-agentic-ai-security-top-10/) — the standard that defines ASI06
- [Agent Memory Guard on GitHub](https://github.com/OWASP/www-project-agent-memory-guard) — source code and documentation
- [Vectorize: How to Prevent AI Memory Poisoning](https://vectorize.io/articles/how-to-prevent-ai-memory-poisoning) — Vectorize's defense-in-depth guide
- [Unit 42: Indirect Prompt Injection Poisons AI Long-Term Memory](https://unit42.paloaltonetworks.com/indirect-prompt-injection-poisons-ai-longterm-memory/) — Palo Alto Networks proof of concept
- [Memory Poisoning Attack and Defense on Memory Based LLM-Agents (arXiv)](https://arxiv.org/abs/2601.05504) — academic research on attack/defense methods

---

*This page is maintained by the OWASP Agent Memory Guard project. If you maintain a tool that should be listed here, open a PR or issue.*
