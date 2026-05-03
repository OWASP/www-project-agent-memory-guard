#!/usr/bin/env python3
"""
OWASP Agent Memory Guard — Static Security Scanner
====================================================
Scans Python source files for potential memory poisoning vulnerabilities
in AI agent code. Used by the GitHub Action and as a standalone CLI tool.

Detects:
- Unguarded memory write operations (AMG001)
- Hardcoded secrets that could be exfiltrated via memory poisoning (AMG002)
- Prompt injection patterns in string literals stored to memory (AMG003)
- Unsafe deserialization into memory stores (AMG004)
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatch
from pathlib import Path
from typing import Any


# ============================================================================
# SEVERITY & FINDING MODELS
# ============================================================================

class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def numeric(self) -> int:
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    file_path: str
    line: int
    column: int = 0
    snippet: str = ""
    recommendation: str = ""


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_with_findings: int = 0


# ============================================================================
# DETECTION RULES
# ============================================================================

# Patterns that indicate unguarded memory operations
MEMORY_WRITE_PATTERNS = [
    # Direct memory/store writes without guard
    r"\.set\s*\(",
    r"\.put\s*\(",
    r"\.store\s*\(",
    r"\.save_context\s*\(",
    r"\.add_message\s*\(",
    r"\.add_memory\s*\(",
    r"\.upsert\s*\(",
    r"memory\[.*\]\s*=",
    r"chat_history\.append\s*\(",
]

# Patterns indicating secrets/credentials in memory operations
SECRET_PATTERNS = [
    (r"['\"](?:sk-|sk-proj-)[a-zA-Z0-9]{20,}['\"]", "OpenAI API key literal"),
    (r"['\"](?:ghp_|gho_|ghu_)[a-zA-Z0-9]{30,}['\"]", "GitHub token literal"),
    (r"['\"](?:AKIA)[A-Z0-9]{16}['\"]", "AWS access key literal"),
    (r"['\"](?:xox[bpras]-)[a-zA-Z0-9\-]{20,}['\"]", "Slack token literal"),
    (r"password\s*=\s*['\"][^'\"]+['\"]", "Hardcoded password"),
    (r"api_key\s*=\s*['\"][^'\"]+['\"]", "Hardcoded API key"),
]

# Patterns indicating prompt injection risks
INJECTION_PATTERNS = [
    (r"ignore\s+(?:all\s+)?previous\s+instructions", "Prompt injection: instruction override"),
    (r"you\s+are\s+now\s+(?:DAN|unrestricted|jailbroken)", "Prompt injection: persona hijack"),
    (r"disregard\s+(?:all\s+)?(?:prior|previous)\s+(?:rules|instructions)", "Prompt injection: rule bypass"),
    (r"system\s*prompt\s*[:=]", "Prompt injection: system prompt manipulation"),
    (r"override\s+(?:safety|security)\s+(?:guardrails|guidelines|rules)", "Prompt injection: safety override"),
]

# Patterns indicating unsafe deserialization
UNSAFE_DESER_PATTERNS = [
    (r"pickle\.loads?\s*\(", "Unsafe pickle deserialization into memory"),
    (r"yaml\.(?:unsafe_)?load\s*\(", "Unsafe YAML load (use safe_load)"),
    (r"eval\s*\(", "Use of eval() — potential code injection"),
    (r"exec\s*\(", "Use of exec() — potential code injection"),
]

# Memory-related import/class patterns
MEMORY_INDICATORS = [
    r"from\s+langchain.*memory",
    r"from\s+llama_index.*storage",
    r"from\s+crewai.*memory",
    r"from\s+autogen.*memory",
    r"from\s+agent_memory_guard",
    r"MemoryStore",
    r"ChatMessageHistory",
    r"ConversationBuffer",
    r"VectorStore",
]


# ============================================================================
# SCANNER
# ============================================================================

class MemorySecurityScanner:
    """Scans Python files for agent memory security vulnerabilities."""

    def __init__(
        self,
        min_severity: Severity = Severity.MEDIUM,
        include_patterns: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
    ):
        self.min_severity = min_severity
        self.include_patterns = include_patterns or ["**/*.py"]
        self.exclude_patterns = exclude_patterns or ["**/test*/**", "**/node_modules/**", "**/.venv/**"]

    def scan_directory(self, path: Path) -> ScanResult:
        """Scan a directory for memory security issues."""
        result = ScanResult()
        files_with_issues: set[str] = set()

        for py_file in self._collect_files(path):
            findings = self._scan_file(py_file)
            result.files_scanned += 1
            for f in findings:
                if f.severity.numeric >= self.min_severity.numeric:
                    result.findings.append(f)
                    files_with_issues.add(f.file_path)

        result.files_with_findings = len(files_with_issues)
        return result

    def _collect_files(self, root: Path) -> list[Path]:
        """Collect files matching include/exclude patterns."""
        files = []
        for pattern in self.include_patterns:
            for f in root.rglob(pattern.lstrip("**/") if pattern.startswith("**/") else pattern):
                if f.is_file() and not self._is_excluded(f, root):
                    files.append(f)
        return sorted(set(files))

    def _is_excluded(self, file_path: Path, root: Path) -> bool:
        """Check if a file matches any exclusion pattern."""
        rel = str(file_path.relative_to(root))
        for pattern in self.exclude_patterns:
            if fnmatch(rel, pattern):
                return True
        return False

    def _scan_file(self, file_path: Path) -> list[Finding]:
        """Scan a single file for vulnerabilities."""
        findings: list[Finding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
        except (OSError, UnicodeDecodeError):
            return findings

        # Check if file is memory-related
        is_memory_file = any(
            re.search(pat, content) for pat in MEMORY_INDICATORS
        )

        # Rule 1: Unguarded memory writes (only in memory-related files)
        if is_memory_file:
            has_guard = "MemoryGuard" in content or "agent_memory_guard" in content
            if not has_guard:
                for i, line in enumerate(lines, 1):
                    for pattern in MEMORY_WRITE_PATTERNS:
                        if re.search(pattern, line):
                            findings.append(Finding(
                                rule_id="AMG001",
                                title="Unguarded memory write operation",
                                description=f"Memory write detected without Agent Memory Guard protection. "
                                           f"This operation is vulnerable to memory poisoning attacks (OWASP ASI06).",
                                severity=Severity.HIGH,
                                file_path=str(file_path),
                                line=i,
                                snippet=line.strip(),
                                recommendation="Wrap memory operations with MemoryGuard: "
                                              "`from agent_memory_guard import MemoryGuard, Policy; "
                                              "guard = MemoryGuard(policy=Policy.strict())`",
                            ))

        # Rule 2: Secrets in source (always scan)
        for i, line in enumerate(lines, 1):
            for pattern, desc in SECRET_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        rule_id="AMG002",
                        title="Hardcoded secret detected",
                        description=f"{desc} found in source code. If stored in agent memory, "
                                   f"this could be exfiltrated via memory poisoning.",
                        severity=Severity.CRITICAL,
                        file_path=str(file_path),
                        line=i,
                        snippet=line.strip()[:80],
                        recommendation="Use environment variables or a secrets manager. "
                                      "Agent Memory Guard can auto-redact secrets with Policy.strict().",
                    ))

        # Rule 3: Prompt injection patterns in string literals
        for i, line in enumerate(lines, 1):
            for pattern, desc in INJECTION_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    # Skip if it's in a test file or comment
                    stripped = line.strip()
                    if stripped.startswith("#") or "test" in str(file_path).lower():
                        continue
                    findings.append(Finding(
                        rule_id="AMG003",
                        title="Prompt injection pattern detected",
                        description=f"{desc}. This string could be used to poison agent memory.",
                        severity=Severity.HIGH,
                        file_path=str(file_path),
                        line=i,
                        snippet=stripped[:80],
                        recommendation="Validate all inputs before storing in agent memory. "
                                      "Use MemoryGuard with prompt_injection detector enabled.",
                    ))

        # Rule 4: Unsafe deserialization
        for i, line in enumerate(lines, 1):
            for pattern, desc in UNSAFE_DESER_PATTERNS:
                if re.search(pattern, line):
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    findings.append(Finding(
                        rule_id="AMG004",
                        title="Unsafe deserialization",
                        description=f"{desc}. Deserializing untrusted data into agent memory "
                                   f"enables remote code execution.",
                        severity=Severity.CRITICAL,
                        file_path=str(file_path),
                        line=i,
                        snippet=stripped[:80],
                        recommendation="Use safe deserialization (json.loads, yaml.safe_load). "
                                      "Validate data integrity before loading into memory.",
                    ))

        return findings


# ============================================================================
# OUTPUT FORMATTERS
# ============================================================================

def format_text(result: ScanResult) -> str:
    """Format results as human-readable text."""
    lines = []
    lines.append("=" * 70)
    lines.append("  OWASP Agent Memory Guard — Security Scan Results")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"  Files scanned:        {result.files_scanned}")
    lines.append(f"  Files with findings:  {result.files_with_findings}")
    lines.append(f"  Total findings:       {len(result.findings)}")
    lines.append("")

    if not result.findings:
        lines.append("  ✓ No memory security vulnerabilities detected.")
        lines.append("")
        return "\n".join(lines)

    # Group by severity
    by_severity: dict[Severity, list[Finding]] = {}
    for f in result.findings:
        by_severity.setdefault(f.severity, []).append(f)

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        findings = by_severity.get(sev, [])
        if not findings:
            continue
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}[sev.value]
        lines.append(f"  {icon} {sev.value.upper()} ({len(findings)} findings)")
        lines.append("  " + "-" * 60)
        for f in findings:
            lines.append(f"    [{f.rule_id}] {f.title}")
            lines.append(f"    File: {f.file_path}:{f.line}")
            lines.append(f"    Code: {f.snippet}")
            lines.append(f"    Fix:  {f.recommendation}")
            lines.append("")

    return "\n".join(lines)


def format_json(result: ScanResult) -> str:
    """Format results as JSON."""
    data = {
        "tool": "owasp-agent-memory-guard",
        "version": "0.2.2",
        "summary": {
            "files_scanned": result.files_scanned,
            "files_with_findings": result.files_with_findings,
            "total_findings": len(result.findings),
            "critical": sum(1 for f in result.findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in result.findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in result.findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in result.findings if f.severity == Severity.LOW),
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "location": {
                    "file": f.file_path,
                    "line": f.line,
                    "column": f.column,
                },
                "snippet": f.snippet,
                "recommendation": f.recommendation,
            }
            for f in result.findings
        ],
    }
    return json.dumps(data, indent=2)


def format_sarif(result: ScanResult) -> str:
    """Format results as SARIF for GitHub Security tab."""
    rules = {}
    results_list = []

    for f in result.findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "helpUri": "https://owasp.org/www-project-agent-memory-guard/",
                "properties": {
                    "security-severity": str(f.severity.numeric * 2.5),
                },
            }

        results_list.append({
            "ruleId": f.rule_id,
            "level": {
                "critical": "error",
                "high": "error",
                "medium": "warning",
                "low": "note",
            }[f.severity.value],
            "message": {"text": f.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path},
                    "region": {"startLine": f.line, "startColumn": f.column or 1},
                }
            }],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "OWASP Agent Memory Guard",
                    "version": "0.2.2",
                    "informationUri": "https://owasp.org/www-project-agent-memory-guard/",
                    "rules": list(rules.values()),
                }
            },
            "results": results_list,
        }],
    }
    return json.dumps(sarif, indent=2)


# ============================================================================
# MAIN (GitHub Action Entry Point)
# ============================================================================

def main() -> None:
    """Main entry point for the GitHub Action."""
    # Read inputs from environment
    scan_path = Path(os.environ.get("SCAN_PATH", "."))
    include_raw = os.environ.get("INCLUDE_PATTERNS", "**/*.py")
    exclude_raw = os.environ.get("EXCLUDE_PATTERNS", "**/test*/**,**/node_modules/**,**/.venv/**")
    min_severity_str = os.environ.get("MIN_SEVERITY", "medium")
    output_format = os.environ.get("OUTPUT_FORMAT", "text")
    fail_on_findings = os.environ.get("FAIL_ON_FINDINGS", "true").lower() == "true"

    include_patterns = [p.strip() for p in include_raw.split(",")]
    exclude_patterns = [p.strip() for p in exclude_raw.split(",")]
    min_severity = Severity(min_severity_str)

    # Run scan
    scanner = MemorySecurityScanner(
        min_severity=min_severity,
        include_patterns=include_patterns,
        exclude_patterns=exclude_patterns,
    )
    result = scanner.scan_directory(scan_path)

    # Format output
    if output_format == "json":
        output = format_json(result)
        report_path = "memory-guard-report.json"
    elif output_format == "sarif":
        output = format_sarif(result)
        report_path = "memory-guard-report.sarif"
    else:
        output = format_text(result)
        report_path = "memory-guard-report.txt"

    # Write report
    Path(report_path).write_text(output)
    print(output)

    # Set GitHub Action outputs
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"findings-count={len(result.findings)}\n")
            f.write(f"critical-count={sum(1 for x in result.findings if x.severity == Severity.CRITICAL)}\n")
            f.write(f"high-count={sum(1 for x in result.findings if x.severity == Severity.HIGH)}\n")
            f.write(f"report-path={report_path}\n")
            if output_format == "sarif":
                f.write(f"sarif-path={report_path}\n")

    # Exit code
    if fail_on_findings and result.findings:
        critical = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in result.findings if f.severity == Severity.HIGH)
        print(f"\n❌ Scan failed: {len(result.findings)} findings "
              f"({critical} critical, {high} high)")
        sys.exit(1)
    else:
        print(f"\n✓ Scan complete: {result.files_scanned} files scanned, "
              f"{len(result.findings)} findings")
        sys.exit(0)


if __name__ == "__main__":
    main()
