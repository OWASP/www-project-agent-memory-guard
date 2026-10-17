# openclaw-agent-memory-guard

**OWASP Agent Memory Guard adapter for OpenClaw and Hermes Agent memory files.**

OpenClaw and Hermes keep long-term memory as Markdown files (`MEMORY.md`, `USER.md`, `memory/*.md`), not as a key-value store. This adapter reads those files, splits them into entries, runs the AMG detector pipeline and policy on each entry, and reports a verdict per entry. It runs out of band, from a shell, a cron job or CI.

Tracked in [issue #142](https://github.com/OWASP/www-project-agent-memory-guard/issues/142).

## What it does

- Discovers memory files for the OpenClaw workspace layout (`USER.md`, `MEMORY.md`, `users/<id>/USER.md`, `memory/YYYY-MM-DD.md`, `DREAMS.md`) and the Hermes layout (`~/.hermes/memories/MEMORY.md`, `USER.md`).
- Splits files into entries with stable keys. OpenClaw entries promoted by dreaming carry a marker (`<!-- openclaw-memory-promotion:<key> -->`) and get the key `MEMORY.md#<key>`; other blocks get `path#L<line>`. Hermes entries are separated by `§`.
- Maps provenance onto AMG `SourceClass`: OpenClaw origin classes `owner`, `agent`, `untrusted`, `system` map one to one to `user_input`, `agent_authored`, `external_tool`, `system`. Hermes records no provenance, so its entries are `unknown`.
- Writes each entry into a throwaway `MemoryGuard` with the policy you choose (`strict` by default) and records the action (allow, redact, quarantine, block) and the guard's `SecurityEvent`s.
- Renders text, JSON or SARIF through AMG's existing scanner formatters, and exits non-zero on findings when asked.

## What it does not do

- It does not stop a poisoned write at write time on OpenClaw. OpenClaw has no memory-write hook for plugins (openclaw/openclaw#48509). The adapter finds the entry on the next scan.
- It does not modify files. Snapshot, diff and rollback of the workspace are planned as the next step.
- It does not read OpenClaw's recorded artifact provenance yet. That store lives in OpenClaw's plugin state. Until the adapter reads it, files get OpenClaw's own path default (`agent` for workspace memory, `system` for dreaming files) and you can override per file with `--provenance` (a JSON map from workspace-relative path to origin class).
- Detection quality is AMG's detection quality. In the Agent Memory Security Benchmark, `Policy.strict()` scores a D because it loads no persistence detector; treat the default as a starting point, not a guarantee.

## Install

```bash
pip install openclaw-agent-memory-guard
```

## Use

```bash
# OpenClaw workspace, default policy, human-readable report
amg-openclaw scan --workspace ~/.openclaw/workspace

# Hermes memories, SARIF for CI, fail the job on findings
amg-openclaw scan --workspace ~/.hermes/memories --layout hermes --format sarif --fail-on-findings

# Feed provenance exported from OpenClaw
amg-openclaw scan --workspace ~/.openclaw/workspace --provenance provenance.json
```

`provenance.json`:

```json
{ "memory/2026-09-30.md": "untrusted", "MEMORY.md": "owner" }
```

From Python:

```python
from openclaw_agent_memory_guard import Layout, scan_workspace

result = scan_workspace("~/.openclaw/workspace", layout=Layout.OPENCLAW)
for v in result.flagged:
    print(v.entry.key, v.action.value, [e.detector for e in v.events])
```

## Tests

```bash
pip install -e integrations/openclaw-agent-memory-guard pytest
pytest integrations/openclaw-agent-memory-guard/tests
```

The fixture workspace plants an instruction-carrying line in a daily notes file and checks that the scan blocks that entry, leaves the tracked `MEMORY.md` entries alone, and that the SARIF projection points at the right file and line.

## License

Apache-2.0, same as the parent project.
