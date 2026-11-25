"""``amg-openclaw``: scan OpenClaw or Hermes memory files with AMG."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent_memory_guard import Policy
from agent_memory_guard.policies.policy import load_policy
from agent_memory_guard.scanner import format_sarif, format_text
from openclaw_agent_memory_guard.layouts import Layout
from openclaw_agent_memory_guard.scan import scan_workspace


def _load_policy(name: str) -> Policy:
    if name == "strict":
        return Policy.strict()
    if name == "tiered":
        return Policy.tiered()
    if name == "permissive":
        return Policy.permissive()
    path = Path(name)
    if path.suffix in (".yml", ".yaml") and path.is_file():
        return load_policy(path)
    raise SystemExit(f"Unknown policy: {name} (use strict, tiered, permissive or a YAML file)")


def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.workspace).expanduser()
    if not root.is_dir():
        print(f"Error: {root} is not a directory", file=sys.stderr)
        return 2
    overrides = None
    if args.provenance:
        overrides = json.loads(Path(args.provenance).read_text(encoding="utf-8"))
    result = scan_workspace(
        root,
        layout=Layout(args.layout),
        policy=_load_policy(args.policy),
        provenance_overrides=overrides,
    )
    if args.format == "json":
        output = result.to_json()
    elif args.format == "sarif":
        output = format_sarif(result.to_scan_result())
    else:
        output = format_text(result.to_scan_result())
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output)
    if args.fail_on_findings and result.flagged:
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="amg-openclaw",
        description="Scan OpenClaw or Hermes Agent memory files with OWASP Agent Memory Guard.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan a memory workspace and report per-entry verdicts")
    scan.add_argument(
        "--workspace",
        default="~/.openclaw/workspace",
        help="OpenClaw workspace or Hermes memories directory",
    )
    scan.add_argument(
        "--layout", choices=[item.value for item in Layout], default=Layout.OPENCLAW.value
    )
    scan.add_argument(
        "--policy", default="strict", help="strict, tiered, permissive or a policy YAML file"
    )
    scan.add_argument(
        "--provenance", help="JSON file mapping workspace-relative path to OpenClaw origin class"
    )
    scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan.add_argument("--output", help="Write the report to a file instead of stdout")
    scan.add_argument(
        "--fail-on-findings", action="store_true", help="Exit 1 when any entry is flagged"
    )
    scan.set_defaults(func=cmd_scan)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
