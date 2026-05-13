"""Scan rules for Agent Memory Guard."""

import re


def _unprotected_memory_write(content: str, filepath) -> list[dict]:
    """Detect unprotected memory writes."""
    results = []
    pattern = re.compile(r'(memory|state)\[["\']?\w+["\']?\]\s*=\s*', re.IGNORECASE)
    guard_pattern = re.compile(r'guard\.(wrap|check|protect)', re.IGNORECASE)
    
    for i, line in enumerate(content.split("\n"), 1):
        if pattern.search(line) and not guard_pattern.search(line):
            results.append({"line": i, "column": 0})
    return results


def _hardcoded_secrets(content: str, filepath) -> list[dict]:
    """Detect hardcoded secrets."""
    results = []
    secret_patterns = [
        r'(?i)(api_key|secret|password|token)\s*=\s*["\'][^"\']+["\']',
        r'(?i)(sk-[a-zA-Z0-9]{20,})',
        r'(?i)(ghp_[a-zA-Z0-9]{36})',
    ]
    for pat in secret_patterns:
        for i, line in enumerate(content.split("\n"), 1):
            if re.search(pat, line):
                results.append({"line": i, "column": 0})
    return results


def _missing_policy_file(content: str, filepath) -> list[dict]:
    """Check if policy file is referenced but missing."""
    results = []
    policy_dir = filepath.parent / "policies"
    if "policy" in content.lower() and not policy_dir.exists():
        results.append({"line": 1, "column": 0})
    return results


SCAN_RULES = [
    {
        "id": "AMG-001",
        "pattern": _unprotected_memory_write,
        "message": "Unprotected memory write detected — wrap with guard protection",
        "severity": "high",
        "min_policy": 1,
    },
    {
        "id": "AMG-002",
        "pattern": _hardcoded_secrets,
        "message": "Hardcoded secret or credential found in source code",
        "severity": "high",
        "min_policy": 0,
    },
    {
        "id": "AMG-003",
        "pattern": _missing_policy_file,
        "message": "Policy file referenced but policies/ directory not found",
        "severity": "medium",
        "min_policy": 2,
    },
]