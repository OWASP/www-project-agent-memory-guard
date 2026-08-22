## [Unreleased] - 2026-05-14

### Added
- **Agent Memory Security Benchmark (AMSB)** — a framework-neutral benchmark and leaderboard that grades any agent memory system for resilience to the memory-poisoning lifecycle (plant → survive context reset → recall). Ships the `agent_memory_guard.bench` package (adapter contract, scenario corpus, harness, SSL-Labs-style scoring with grade ceilings, report renderer), an `amg-bench` CLI, offline baselines (unguarded dict + two AMG configurations), and opt-in reference adapters for mem0/Letta/Zep. AMG is graded arm's-length as one system among others. Committed results under `benchmarks/memory-systems/`.
- Expanded community adoption: GitHub issues opened on microsoft/semantic-kernel, run-llama/llama_index, langchain-ai/langgraph, and BerriAI/litellm requesting native ASI06 integration
- - Documentation updates for v0.3.0 roadmap (LlamaIndex/CrewAI adapters, Redis/PostgreSQL backends)
 
  - ## [0.2.1] - 2026-05-02
 
  - ### Added
  - - Full detector pipeline: prompt injection, sensitive data leakage, protected keys, size anomaly, rapid change
    - - Declarative YAML policy engine with `allow`, `redact`, `quarantine`, and `block` actions
      - - SHA-256 integrity baselines for immutable keys with drift detection
        - - Point-in-time snapshot store with rollback capability
          - - `GuardedChatMessageHistory` integration for LangChain
            - - Structured `SecurityEvent` emission for forensics and monitoring
              - - Comprehensive test suite (29 tests, 85%+ coverage)
                - - CI/CD pipeline with GitHub Actions (lint, type-check, test, publish)
                  - - OWASP branding and alignment with ASI06 reference implementation
                   
                    - ### Security
                    - - Detects and blocks prompt injection patterns in memory writes
                      - - Redacts secrets (AWS keys, GitHub tokens, API keys) before storage
                        - - Prevents unauthorized modification of protected and immutable keys
                          - - Quarantines oversized payloads and rapid-change churn attacks
                           
                            - ## [0.1.0] - 2026-03-15
                           
                            - ### Added
                            - - Initial project structure and OWASP proposal
                              - - Basic memory guard concept and architecture design
                                - - Project accepted into OWASP Incubator
                                 
                                  - [0.2.1]: https://github.com/OWASP/www-project-agent-memory-guard/releases/tag/v0.2.1
                                  - [0.1.0]: https://github.com/OWASP/www-project-agent-memory-guard/releases/tag/v0.1.0
