# GitHub Actions Integration

Scan your codebase for memory security vulnerabilities in CI/CD with the official AMG GitHub Action. Results appear in GitHub's Security tab via SARIF integration.

## Quick Start

Add to `.github/workflows/security.yml`:

```yaml
name: Memory Security Scan
on: [push, pull_request]

jobs:
  amg-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # Required for SARIF upload
    steps:
      - uses: actions/checkout@v4

      - uses: OWASP/www-project-agent-memory-guard@v0.3.3
        with:
          scan-path: "."
          min-severity: "medium"
          fail-on-findings: "true"
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `scan-path` | `.` | Directory to scan |
| `fail-on-findings` | `true` | Fail the workflow if findings detected |
| `include-patterns` | `**/*.py` | Glob patterns for files to include |
| `exclude-patterns` | `**/test*/**,...` | Glob patterns to exclude |
| `min-severity` | `medium` | Minimum severity: `low`, `medium`, `high`, `critical` |
| `output-format` | `sarif` | Format: `text`, `json`, `sarif` |
| `upload-sarif` | `true` | Upload SARIF to GitHub Security tab |
| `python-version` | `3.11` | Python version to use |

## Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of findings |
| `critical-count` | Number of critical findings |
| `high-count` | Number of high findings |
| `report-path` | Path to generated report |
| `sarif-path` | Path to SARIF file |

## Examples

### Block PRs with Critical Findings

```yaml
- uses: OWASP/www-project-agent-memory-guard@v0.3.3
  id: amg
  with:
    min-severity: "critical"
    fail-on-findings: "true"

- name: Comment on PR
  if: failure() && github.event_name == 'pull_request'
  uses: actions/github-script@v7
  with:
    script: |
      github.rest.issues.createComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.issue.number,
        body: `🛡️ AMG found ${{ steps.amg.outputs.findings-count }} memory security issue(s). Please review the Security tab.`
      })
```

### Scan Multiple Languages

```yaml
- uses: OWASP/www-project-agent-memory-guard@v0.3.3
  with:
    include-patterns: "**/*.py,**/*.js,**/*.ts"
    exclude-patterns: "**/node_modules/**,**/test*/**"
```

### JSON Report as Artifact

```yaml
- uses: OWASP/www-project-agent-memory-guard@v0.3.3
  with:
    output-format: "json"
    upload-sarif: "false"
```

## SARIF Integration

When `output-format` is `sarif` and `upload-sarif` is `true`, findings appear directly in your repository's **Security → Code scanning alerts** tab. This provides:

- Inline annotations on affected lines
- Alert management (dismiss, reopen, assign)
- Trend tracking over time
- Integration with branch protection rules

## Workflow Summary

The action automatically adds a summary to the workflow run:

```
## 🛡️ Agent Memory Guard Scan Results

⚠️ 3 finding(s) detected (1 critical, 2 high)

Report: `amg-results.sarif`
```
