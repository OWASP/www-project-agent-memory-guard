# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-05-02

### Added
- Full detector pipeline: prompt injection, sensitive data leakage, protected keys, size anomaly, rapid change
- Declarative YAML policy engine with `allow`, `redact`, `quarantine`, and `block` actions
- SHA-256 integrity baselines for immutable keys with drift detection
- Point-in-time snapshot store with rollback capability
- `GuardedChatMessageHistory` integration for LangChain
- Structured `SecurityEvent` emission for forensics and monitoring
- Comprehensive test suite (29 tests, 85%+ coverage)
- CI/CD pipeline with GitHub Actions (lint, type-check, test, publish)
- OWASP branding and alignment with ASI06 reference implementation

### Security
- Detects and blocks prompt injection patterns in memory writes
- Redacts secrets (AWS keys, GitHub tokens, API keys) before storage
- Prevents unauthorized modification of protected and immutable keys
- Quarantines oversized payloads and rapid-change churn attacks

## [0.1.0] - 2026-03-15

### Added
- Initial project structure and OWASP proposal
- Basic memory guard concept and architecture design
- Project accepted into OWASP Incubator

[0.2.1]: https://github.com/OWASP/www-project-agent-memory-guard/releases/tag/v0.2.1
[0.1.0]: https://github.com/OWASP/www-project-agent-memory-guard/releases/tag/v0.1.0
