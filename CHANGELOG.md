# Changelog

All notable changes to OWASP Agent Memory Guard are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Note on this file.** Entries below 0.3.1 were reconstructed on 2026-08-25. The
> previous version of this changelog had become structurally corrupted — successive
> edits nested each release inside the previous one's bullet list, so every section
> from 0.2.1 down rendered as an ever-deepening staircase, and 0.3.0 had no entry at
> all. Content has been preserved where it existed and reconstructed from tags and
> commit history where it did not.

## [0.3.2] - 2026-09-09

### Fixed

- **`Policy.strict()` protected-key rule could never fire.** The preset shipped
  `block_protected_key` with an empty `protected_keys` tuple, so identity/system
  writes were allowed in the documented quickstart. `Policy.strict()` now declares
  `identity.*`, `system.*`, and `agent.goal` — the same tuple already used in the
  project examples. Thanks [@arpitjain099](https://github.com/arpitjain099). ([#90], [#89])

- **Independent writes could wipe self-reinforcement history.** A single
  attacker-controlled `USER_INPUT` write cleared the entire detector window.
  Independent non-agent writes now decay history by one entry instead of resetting
  it. Scope is bounded: this does not claim to prevent all reset/evasion patterns.
  Thanks [@Moviw](https://github.com/Moviw). ([#109], [#87])

- **YAML policies with a dead `protected_key` rule loaded silently.**
  `Policy.from_dict` now raises when a rule acts on `protected_key` but both
  `protected_keys` and `immutable_keys` are empty, so an inert control cannot
  look live. Check remains in `from_dict` only (constructor-built presets
  unaffected). Original design by [@arpitjain099](https://github.com/arpitjain099);
  rebased as [#120] after [#90]. ([#120], [#106], [#92])

### Changed

- README LangChain middleware section now links the wrapper package, how-to
  Discussion, and public clinic Gist. ([#118])

## [0.3.1] - 2026-08-25

### Fixed

- **Scanner matched no files and reported zero findings on every codebase.**
  `MemorySecurityScanner._collect_files` normalized include patterns with
  `pattern.lstrip("**/")`. `str.lstrip` strips any leading character present in its
  argument — it treats the argument as a set, not as a prefix — so the default pattern
  `"**/*.py"` was reduced to `".py"` and `rglob(".py")` matched nothing. `amg scan`
  therefore reported `files_scanned: 0, total_findings: 0` on every repository and
  exited 0, with no error. The GitHub Action inherited the same default. ([#93])

  **This affects 0.3.0 only** — the CLI scanner was introduced in that release, so no
  earlier version is impacted. The `MemoryGuard` runtime path, which screens memory
  reads and writes, never calls `_collect_files` and is unaffected. The published
  benchmark figures were measured on 0.2.2, predating the scanner, and are unaffected.

  **If you ran `amg scan` on 0.3.0 and saw a clean result, re-scan on 0.3.1.**

- Package version reported itself as `0.3.0-dev` in the released 0.3.0 build.
- SARIF output carried a hardcoded tool version that could drift from the package
  version; it now derives from `__version__`.

### Changed

- Corrected the detection figures in `docs/compliance-mapping.md`. The document stated
  a 97.3% detection rate and a 200+ payload corpus in four places; the measured values
  are 92.5% recall at 100% precision (F1 0.961) across 55 cases, against a 75-example
  public corpus. Added a "Basis of measurement" section tying every figure in the
  document to the artifact that produced it, with an explicit statement of what the
  numbers do not establish. ([#94])

- Repository adoption figures now report PyPI downloads and git clones separately
  rather than summing them into a single "total downloads" number.

### Added

- `tests/test_scanner_file_discovery.py` — eight regression tests covering include-pattern
  normalization and end-to-end file discovery, including assertions that a directory
  containing Python files never scans zero. Five of these fail against 0.3.0.

## [0.3.0] - 2026-06-10

### Added

- CLI scanner (`amg scan`) for static analysis of agent codebases.
  **Known defect — see 0.3.1.** This command did not work in this release.
- REST API server (`amg serve`) built on FastAPI, exposing `/scan`, `/write`, `/read`,
  `/events`, and `/stats`.
- MCP server package (`amg-mcp-server`) exposing the guard as Model Context Protocol
  tools for scanning and validating memory entries.
- Additional detectors, including memory-persistence injection (delayed-activation
  writes that are inert in the current turn).
- MkDocs documentation site.
- Google-style docstrings across all public classes and methods.
- Redis backend for persistent memory storage.

## [0.2.2] - 2026-05-02

### Added

- Security benchmark suite (`benchmarks/security_benchmark.py`) with a labeled corpus of
  55 cases: 40 attack payloads across five categories plus 15 benign controls. This is
  the release the published benchmark figures were measured against — 92.5% recall,
  100% precision, F1 0.961, 59 µs median added latency per memory operation.

## [0.2.1] - 2026-05-02

### Added

- Full detector pipeline: prompt injection, sensitive data leakage, protected keys,
  size anomaly, rapid change
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

[#120]: https://github.com/OWASP/www-project-agent-memory-guard/pull/120
[#118]: https://github.com/OWASP/www-project-agent-memory-guard/pull/118
[#109]: https://github.com/OWASP/www-project-agent-memory-guard/pull/109
[#106]: https://github.com/OWASP/www-project-agent-memory-guard/pull/106
[#92]: https://github.com/OWASP/www-project-agent-memory-guard/issues/92
[#90]: https://github.com/OWASP/www-project-agent-memory-guard/pull/90
[#89]: https://github.com/OWASP/www-project-agent-memory-guard/issues/89
[#87]: https://github.com/OWASP/www-project-agent-memory-guard/issues/87
[#93]: https://github.com/OWASP/www-project-agent-memory-guard/pull/93
[#94]: https://github.com/OWASP/www-project-agent-memory-guard/pull/94
[0.3.2]: https://github.com/OWASP/www-project-agent-memory-guard/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/OWASP/www-project-agent-memory-guard/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/OWASP/www-project-agent-memory-guard/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/OWASP/www-project-agent-memory-guard/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/OWASP/www-project-agent-memory-guard/releases/tag/v0.2.1
[0.1.0]: https://github.com/OWASP/www-project-agent-memory-guard/releases/tag/v0.1.0
