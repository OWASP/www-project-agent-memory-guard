---

layout: col-sidebar
title: OWASP Agent Memory Guard
tags: example-tag
level: 2
type: code
pitch: A very brief, one-line description of your project

---

Agent Memory Guard protects AI agents from memory poisoning attacks — the corruption of persistent agent memory that leads to misalignment, data exfiltration, and malicious behavior across sessions.

AI agents built on LangChain, LlamaIndex, and CrewAI store mutable state (goals, user context, conversation history, permissions) that can be tampered with through prompt injection, context manipulation, and identity hijacking. Unlike LLM model weights, this memory is writable at runtime and persists across sessions, making it a high-value attack surface with no existing defenses.

Agent Memory Guard provides a runtime defense layer that:

* Validates memory integrity using cryptographic baselines (SHA-256 hashing)
* Detects injection attempts, sensitive data leakage, protected key modifications, rapid changes, and size anomalies
* Enforces declarative YAML security policies on memory read/write operations
* Captures snapshots for forensic analysis and enables rollback to known-good states
* Integrates as drop-in middleware for popular agentic AI frameworks

The project directly addresses ASI06: Memory Poisoning from the OWASP Top 10 for Agentic Applications, providing the reference implementation that the risk definition currently lacks.

### Road Map
Q1 2026: Set up OWASP project page, transfer repo to OWASP GitHub, recruit co-leader, publish v0.2.1 with OWASP branding.

Q2 2026: Release v0.3.0 — add LlamaIndex/CrewAI integrations, Redis/PostgreSQL backends, Prometheus metrics.

Q3 2026: Release v0.4.0 — ML-based anomaly detection, vector store protection, real-time monitoring dashboard.

Q4 2026: Release v1.0.0 stable, multi-agent security, apply for Lab promotion.
