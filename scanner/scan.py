#!/usr/bin/env python3
"""Main scanner script for Agent Memory Guard GitHub Action."""

import argparse
import sys
from pathlib import Path

from scanner.rules import SCAN_RULES
from scanner.sarif_output import write_sarif


def scan_file(filepath: Path, policy: str) -> list[dict]:
    """Scan a single file for memory vulnerabilities."""
    results = []
    try:
        content = filepath.read_text(encoding="utf-8")
    except Exception:
        return results

    for rule in SCAN_RULES:
        if rule["min_policy"] > {"basic": 0, "moderate": 1, "strict": 2}[policy]:
            continue
        for match in rule["pattern"](content, filepath):
            results.append({
                "rule_id": rule["id"],
                "message": rule["message"],
                "severity": rule["severity"],
                "file": str(filepath),
                "line": match.get("line", 1),
                "column": match.get("column", 1),
            })
    return results


def main():
    parser = argparse.ArgumentParser(description="Agent Memory Guard Scanner")
    parser.add_argument("--path", default=".", help="Path to scan")
    parser.add_argument("--policy", default="moderate", choices=["basic", "moderate", "strict"])
    parser.add_argument("--fail-on", default="high", choices=["low", "medium", "high"])
    parser.add_argument("--output", default="sarif")
    parser.add_argument("--output-file", default="results.sarif")
    args = parser.parse_args()

    scan_root = Path(args.path)
    all_results = []

    for py_file in scan_root.rglob("*.py"):
        all_results.extend(scan_file(py_file, args.policy))

    if args.output == "sarif":
        write_sarif(all_results, args.output_file)

    severity_levels = {"low": 0, "medium": 1, "high": 2}
    max_severity = max(
        (severity_levels.get(r["severity"].lower(), 0) for r in all_results),
        default=0,
    )

    print(f"Scanned: {len(all_results)} issue(s) found.")
    if max_severity >= severity_levels[args.fail_on]:
        print(f"Failing due to {args.fail_on} severity or higher.")
        sys.exit(1)


if __name__ == "__main__":
    main()