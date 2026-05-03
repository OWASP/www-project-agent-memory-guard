# OWASP Agent Memory Guard — GitHub Action

Scan your AI agent code for memory poisoning vulnerabilities (OWASP ASI06) in every PR and push.

## Quick Start

Add this to `.github/workflows/memory-security.yml` in your repository:

```yaml
name: Agent Memory Security Scan
on: [push, pull_request]

jobs:
  memory-guard:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # Required for SARIF upload
    steps:
      - uses: actions/checkout@v4

      - name: Run OWASP Agent Memory Guard
        uses: OWASP/www-project-agent-memory-guard/action@main
        with:
          scan-path: '.'
          fail-on-findings: 'true'
          output-format: 'sarif'
```

## What It Detects

| Rule ID | Category | Severity | Description |
|---------|----------|----------|-------------|
| AMG001 | Unguarded Memory | HIGH | Memory write operations without Agent Memory Guard protection |
| AMG002 | Secret Leakage | CRITICAL | Hardcoded secrets that could be exfiltrated via memory poisoning |
| AMG003 | Prompt Injection | HIGH | Injection patterns that could poison agent memory |
| AMG004 | Unsafe Deserialization | CRITICAL | Deserializing untrusted data into agent memory |

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `scan-path` | Path to scan | `.` |
| `fail-on-findings` | Fail workflow on findings | `true` |
| `include-patterns` | Glob patterns to include | `**/*.py` |
| `exclude-patterns` | Glob patterns to exclude | `**/test*/**,**/node_modules/**` |
| `min-severity` | Minimum severity: `low`, `medium`, `high`, `critical` | `medium` |
| `output-format` | Output: `text`, `json`, `sarif` | `text` |

## Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total findings detected |
| `critical-count` | Critical severity findings |
| `high-count` | High severity findings |
| `report-path` | Path to generated report |
| `sarif-path` | Path to SARIF file (for GitHub Security tab) |

## SARIF Integration

When using `output-format: sarif`, findings appear directly in the **Security** tab of your GitHub repository, alongside CodeQL and other security tools.

## Examples

### Scan only specific directories

```yaml
- uses: OWASP/www-project-agent-memory-guard/action@main
  with:
    scan-path: 'src/agents'
    include-patterns: '**/*.py'
```

### Non-blocking scan (report only)

```yaml
- uses: OWASP/www-project-agent-memory-guard/action@main
  with:
    fail-on-findings: 'false'
    output-format: 'json'
```

### Critical-only blocking

```yaml
- uses: OWASP/www-project-agent-memory-guard/action@main
  with:
    min-severity: 'critical'
    fail-on-findings: 'true'
```

## Related

- [OWASP Agent Memory Guard](https://owasp.org/www-project-agent-memory-guard/) — Full runtime protection library
- [OWASP Top 10 for Agentic Applications](https://owasp.org/www-project-top-10-for-llm-applications/) — ASI06: Memory Poisoning
- Install the library: `pip install agent-memory-guard`
