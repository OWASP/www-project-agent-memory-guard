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

## [Unreleased]

### Added

- **Per-agent access control.** `Policy.with_access(AccessRule(...))` says which
  agents may read and write which keys, for example "only the supervisor may change
  `plan.*`". The guard checks it before any detector runs, before the existence check
  on read, and before the store is touched. A denial raises `AccessDenied` (a
  `PolicyViolation`), logs an `access_control` event and takes no snapshot. Policies
  without access rules behave as before.
- **Agent identity.** `guard.as_agent("id")` returns an `AgentHandle` bound to one
  agent; `write`, `read`, `delete`, `promote`, `snapshot`, `rollback` and `retire_if`
  also take `principal=`. Inside `with guard.as_agent("id"):` plain calls on that
  guard run as the agent; a generator paused inside the block does not pass the
  identity to its caller, and its own code keeps the identity wherever it is
  resumed. A `with` statement in an ordinary function belongs to that function, so
  the tasks and threads it starts get its identity even when a generator further up
  the stack called it. Tasks and threads started while a generator holds a block
  open start anonymous. A handle's `snapshot()` and `rollback()` return only the
  snapshot id. Every `SecurityEvent` has a new `principal` field.
- **Private namespaces.** A key pattern such as `agents.{owner}.*` with
  `writers=["{owner}"]` gives every agent its own space.
- **Class gate and admins.** With access rules, only `admins` may `snapshot()`,
  `rollback()` and `retire_if()`, and only the admins may write, delete or promote
  POLICY and VERIFIED_PREFERENCE memory unless `class_writers` names others for a
  class. `retire_if()` skips keys whose class the caller may not change, and
  `rollback()` is refused if it would change such memory. If no admins are named,
  nobody may do these things; `admins=["<anonymous>"]` gives them to code that calls
  the guard without an agent identity, as in 0.3.
- **Values are copied with access rules.** The guard stores a deep copy of each
  written value and returns a deep copy on read, so an agent cannot change memory it
  may only read by editing the object it got back.
- **Looking inside a decision.** `guard.explain(...)` dry-runs an access decision
  (`snapshot_id=` picks the snapshot for `rollback`). `MemoryGuard(trace=True)`
  records each step of every operation (identity, access rules, each detector, the
  deciding policy rule, snapshot, commit); `guard.last_trace()` returns those of the
  last operation in the current thread or asyncio task, events carry them in
  `metadata["trace"]`, and `format_trace()` prints them. When one operation logs
  several events (`retire_if()`), each carries the opening steps and the steps
  since the previous event.
- `Policy.evaluate()` returns the action and the name of the deciding rule.

### Changed

- **YAML policies with per-agent fields now fail to load.** 0.3 silently ignored
  fields such as `agents: [supervisor]` on a rule, which let every agent through.
  Rule fields `agent(s)`, `writer(s)`, `reader(s)`, `principal(s)` and top-level
  `access`, `principals` or `agents` sections now raise `ValueError`. Other unknown
  fields give a `PolicyWarning` and are still ignored.
- `rollback()` now restores class labels and origin tasks saved with the snapshot,
  instead of keeping the labels from before the rollback. This applies with or
  without access rules. Snapshots record them, with each captured key's last
  writer, in a new `metadata["amg_state"]` entry.
- A copied or unpickled `MemoryGuard` is a new guard: `with` blocks and
  `last_trace()` of the original do not apply to it.
- `Policy` has a new `access` field (None unless you call `with_access`), which
  shows in its `repr`.
- `rollback()` on a store without `restore()` writes copies of the snapshot's
  values (the value itself if it cannot be copied), so editing a restored value no
  longer changes the snapshot.
- `Policy.from_dict()` and `load_policy()` raise `ValueError` for a policy document
  that is not a mapping, where 0.3 raised `AttributeError`.
- Without access rules, each operation now checks for an agent identity. A write
  plus a read costs about 3 to 5 microseconds more than in 0.3.3: about 10% on a
  tiny value and 2 to 5% on a typical one (Python 3.12 and 3.13).
- CI runs on Python 3.13 and 3.14.

### Fixed

- `AccessDenied`, `ClassificationError` and `IntegrityError` can be pickled and
  copied, so they reach the caller from a process pool instead of breaking it.
- The LlamaIndex adapter's `delete_message()` raises `AccessDenied` instead of
  deleting the message from the backing store when the agent may not delete it.

## [0.3.3] - 2026-10-02

### Security

- **A nesting pad disabled every content detector.** `_stringify` walked nested
  values with no depth bound, so a value nested a few hundred levels deep raised
  `RecursionError` inside the detectors; the guard swallowed the errors and allowed
  the write with no events. The walk is now bounded at 50 levels. Reported and fixed
  by [@Yeagerist0](https://github.com/Yeagerist0). ([#135])
- **Content nested below that bound was still allowed silently.** Anything deeper
  than 50 levels was replaced by a marker that no detector reads, so a payload nested
  51 or more levels deep was written with no event. Such values are now reported as a
  `size_anomaly` finding: `Policy.strict()` quarantines them and permissive policies
  record the event. Found while preparing this release.
- **Glob `immutable_keys` created no integrity baseline.** `immutable_keys=("identity.*",)`
  blocked deletes but never baselined the matching keys, so out-of-band tampering went
  undetected. Baselines now use the same glob matching. Reported and fixed by
  [@Yeagerist0](https://github.com/Yeagerist0). ([#136])
- **A failing detector was invisible.** When a detector raised, its verdict was dropped
  with no event. The guard now emits a low-severity `SecurityEvent` carrying
  `detector_error` metadata, so operators can alert on it. ([#138], [#137])
- **GitHub Action inputs could be substituted into the run script.** The composite
  action now passes inputs through `env:`. Thanks [@avp9-nexus](https://github.com/avp9-nexus). ([#122])

### Added

- **Agent Memory Security Benchmark (AMSB)** — a framework-neutral benchmark and
  leaderboard that grades any agent memory system for resilience to the
  memory-poisoning lifecycle (plant → survive context reset → recall). Ships the
  `agent_memory_guard.bench` package (adapter contract, scenario corpus, harness,
  SSL-Labs-style scoring with grade ceilings, report renderer), an `amg-bench` CLI,
  offline baselines (unguarded dict + two AMG configurations), and opt-in reference
  adapters for mem0/Letta/Zep. AMG is graded arm's-length as one system among others.
  Committed results under `benchmarks/memory-systems/`. ([#88])
- **AutoGen and OpenAI Agents SDK adapters**: `GuardedAutoGenAgent`,
  `GuardedGroupChatManager` and `install_guard`; `GuardedAgentContext`,
  `GuardedToolOutput` and `GuardedHandoff`. Thanks [@hesam-oxe](https://github.com/hesam-oxe). ([#22])
- **Agno integration**: `GuardedMemoryManager`. ([#55])
- A runnable OpenAI Agents example that screens tool outputs and queues blocked
  writes for human review. Thanks [@b-pm](https://github.com/b-pm). ([#126])
- A trusted-publishing workflow for `amg-mcp-server` (dry run by default). The
  server's `mcp` dependency is capped below 2.0, whose SDK removed `FastMCP`. ([#100])

### Fixed

- **`amg check` crashed on the input it exists to flag.** Any text the strict
  policy blocks raised a `PolicyViolation` traceback. The command now reports
  the block (text and JSON) and exits 1.
- **`amg scan <file>` scanned nothing.** A file path was walked as a directory,
  matched no files, and reported a clean scan with exit 0. Files are now scanned
  directly. One secret matched by two patterns on the same line is reported once.
- **REST API returned HTTP 500 for blocked content.** `/scan` and `/write` now
  return `action: "block"` (with `safe`/`stored` false) and the events; `/read`
  returns `blocked: true` for policy blocks and integrity failures. The server
  module also imports on Python 3.9 again (runtime-evaluated `X | None`
  annotations replaced with `Optional[X]`).
- **`demo.py` under-reported its own results.** Redacted and quarantined writes
  were counted as misses, the "size anomaly" payload (50 KB) sat under the
  64 KiB default limit, and the "SYSTEM OVERRIDE:" payload matched no detector.
  The demo now reports each outcome as it happens; the prompt-injection
  detector recognises header-style `SYSTEM OVERRIDE:` directives (prose that
  mentions a system override is not flagged).
- **The LlamaIndex chat store was not a LlamaIndex chat store.** The adapter imported
  `BaseChatStore` from a module that does not exist in llama-index-core 0.10+ and
  silently fell back to `object`, so `ChatMemoryBuffer.from_defaults(chat_store=...)`
  rejected it. It now subclasses the real base, and each message gets its own guard
  key, so a long, fast conversation is no longer quarantined as rapid change.
- Type-checking errors reported by mypy in `guard.py`, the LlamaIndex and Agno
  integrations, and the self-reinforcement detector.
- `amg serve --policy` now reaches the running server; it always used `strict`. ([#147])
- Benchmark plots work with Matplotlib 3.11, and reports carry the installed version
  instead of a hard-coded one. ([#148])
- Self-reinforcement decay is trust-aware: only writes from trusted provenance classes
  decay a key's history. Thanks [@JavierQuinan](https://github.com/JavierQuinan). ([#124])

### Changed

- The `test` extra now installs FastAPI and pydantic so CI exercises the API server.
- Every third-party action in CI and in the composite action is pinned to a commit
  SHA. Thanks [@rksharma-owg](https://github.com/rksharma-owg). ([#54])
- Bumped `actions/setup-python` to v7.0.0, `actions/upload-artifact` to v7.0.1 and
  `github/codeql-action/upload-sarif` to v4.38.2. ([#144], [#145], [#146])

### Documentation

- `Snapshot.digest` is documented as not verified on rollback. ([#139])
- The GitHub Action docs pointed at `OWASP/www-project-agent-memory-guard/action@main`,
  which does not exist (`action.yml` is at the repository root). They now use
  `OWASP/www-project-agent-memory-guard@v0.3.3`.
- The configuration guide documented `Policy.from_yaml()` (which does not exist), a
  YAML schema the loader does not read, unused environment variables and a
  `custom_patterns` argument. It now documents `load_policy`, the real policy
  schema and rule semantics, adding detectors, and the server settings.
- The README's AutoGen, mem0 and CrewAI snippets passed the original content on after
  a write, so a value the strict policy had redacted still reached the framework in
  clear, and a quarantined value was stored anyway. They now pass on the guard's
  stored (redacted) value and skip quarantined writes.
- The LlamaIndex guide imported `SimpleChatStore` from `llama_index.core.chat_store`,
  which does not exist; it is `llama_index.core.storage.chat_store`.
- The README's recognition section states that the mentions are not endorsements.
  Thanks [@GhostCoder6969](https://github.com/GhostCoder6969). ([#141], [#140])

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

[#135]: https://github.com/OWASP/www-project-agent-memory-guard/pull/135
[#136]: https://github.com/OWASP/www-project-agent-memory-guard/pull/136
[#137]: https://github.com/OWASP/www-project-agent-memory-guard/issues/137
[#138]: https://github.com/OWASP/www-project-agent-memory-guard/pull/138
[#139]: https://github.com/OWASP/www-project-agent-memory-guard/pull/139
[#122]: https://github.com/OWASP/www-project-agent-memory-guard/pull/122
[#88]: https://github.com/OWASP/www-project-agent-memory-guard/pull/88
[#22]: https://github.com/OWASP/www-project-agent-memory-guard/pull/22
[#55]: https://github.com/OWASP/www-project-agent-memory-guard/pull/55
[#126]: https://github.com/OWASP/www-project-agent-memory-guard/pull/126
[#100]: https://github.com/OWASP/www-project-agent-memory-guard/pull/100
[#147]: https://github.com/OWASP/www-project-agent-memory-guard/pull/147
[#148]: https://github.com/OWASP/www-project-agent-memory-guard/pull/148
[#124]: https://github.com/OWASP/www-project-agent-memory-guard/pull/124
[#54]: https://github.com/OWASP/www-project-agent-memory-guard/pull/54
[#144]: https://github.com/OWASP/www-project-agent-memory-guard/pull/144
[#145]: https://github.com/OWASP/www-project-agent-memory-guard/pull/145
[#146]: https://github.com/OWASP/www-project-agent-memory-guard/pull/146
[#141]: https://github.com/OWASP/www-project-agent-memory-guard/pull/141
[#140]: https://github.com/OWASP/www-project-agent-memory-guard/issues/140
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
[0.3.3]: https://github.com/OWASP/www-project-agent-memory-guard/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/OWASP/www-project-agent-memory-guard/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/OWASP/www-project-agent-memory-guard/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/OWASP/www-project-agent-memory-guard/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/OWASP/www-project-agent-memory-guard/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/OWASP/www-project-agent-memory-guard/releases/tag/v0.2.1
[0.1.0]: https://github.com/OWASP/www-project-agent-memory-guard/releases/tag/v0.1.0
