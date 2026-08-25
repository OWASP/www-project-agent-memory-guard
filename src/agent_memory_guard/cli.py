"""OWASP Agent Memory Guard — CLI interface.

Provides two main commands:
  amg scan <path>   — Static security scanner for AI agent codebases
  amg serve         — Start the REST API server for runtime scanning
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="amg",
        description="OWASP Agent Memory Guard — Protect AI agent memory from poisoning attacks",
    )
    parser.add_argument(
        "--version", action="store_true", help="Show version and exit"
    )
    sub = parser.add_subparsers(dest="command")

    # --- scan subcommand ---
    scan_parser = sub.add_parser(
        "scan",
        help="Scan Python files for memory security vulnerabilities",
        description="Static analysis scanner that detects unguarded memory writes, "
        "hardcoded secrets, prompt injection patterns, and unsafe deserialization.",
    )
    scan_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Directory or file to scan (default: current directory)",
    )
    scan_parser.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        default="medium",
        help="Minimum severity to report (default: medium)",
    )
    scan_parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    scan_parser.add_argument(
        "--output", "-o", type=str, default=None, help="Write report to file"
    )
    scan_parser.add_argument(
        "--include",
        type=str,
        default="**/*.py",
        help="Comma-separated glob patterns to include (default: **/*.py)",
    )
    scan_parser.add_argument(
        "--exclude",
        type=str,
        default="**/test*/**,**/node_modules/**,**/.venv/**",
        help="Comma-separated glob patterns to exclude",
    )
    scan_parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        default=False,
        help="Exit with code 1 if findings are detected",
    )

    # --- serve subcommand ---
    serve_parser = sub.add_parser(
        "serve",
        help="Start the Agent Memory Guard API server",
        description="Launch a FastAPI-based REST API for runtime memory scanning.",
    )
    serve_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help=(
            "Host to bind (default: 127.0.0.1). The server has no authentication, "
            "so binding a non-loopback address exposes the memory store to anyone "
            "who can reach the port."
        ),
    )
    serve_parser.add_argument(
        "--port", "-p", type=int, default=8000, help="Port to listen on (default: 8000)"
    )
    serve_parser.add_argument(
        "--reload", action="store_true", help="Enable auto-reload for development"
    )
    serve_parser.add_argument(
        "--policy",
        choices=["permissive", "strict", "tiered"],
        default="strict",
        help="Default policy for the guard (default: strict)",
    )

    # --- check subcommand (single text check) ---
    check_parser = sub.add_parser(
        "check",
        help="Check a single text value for threats",
        description="Run all detectors against a single text input and report results.",
    )
    check_parser.add_argument("text", help="Text to check for threats")
    check_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )

    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute the scan command."""
    from agent_memory_guard.scanner import MemorySecurityScanner, Severity

    scan_path = Path(args.path)
    if not scan_path.exists():
        print(f"Error: Path '{args.path}' does not exist.", file=sys.stderr)
        return 1

    include_patterns = [p.strip() for p in args.include.split(",")]
    exclude_patterns = [p.strip() for p in args.exclude.split(",")]
    min_severity = Severity(args.severity)

    scanner = MemorySecurityScanner(
        min_severity=min_severity,
        include_patterns=include_patterns,
        exclude_patterns=exclude_patterns,
    )

    result = scanner.scan_directory(scan_path)

    # Format output
    from agent_memory_guard.scanner import format_json, format_sarif, format_text

    if args.format == "json":
        output = format_json(result)
    elif args.format == "sarif":
        output = format_sarif(result)
    else:
        output = format_text(result)

    # Write or print
    if args.output:
        Path(args.output).write_text(output)
        print(f"Report written to {args.output}")
    else:
        print(output)

    # Exit code
    if args.fail_on_findings and result.findings:
        return 1
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Execute the serve command."""
    try:
        import uvicorn
    except ImportError:
        print(
            "Error: uvicorn is required for the API server.\n"
            "Install with: pip install agent-memory-guard[server]",
            file=sys.stderr,
        )
        return 1

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            f"WARNING: binding {args.host} exposes this server beyond localhost, and it "
            "ships no authentication. Anyone who can reach this port can read and write "
            "the guarded memory store. Put it behind an authenticating proxy or keep it "
            "on 127.0.0.1."
        )
    print(f"Starting Agent Memory Guard API server on {args.host}:{args.port}")
    print(f"Policy: {args.policy}")
    print(f"Docs: http://{args.host}:{args.port}/docs")

    uvicorn.run(
        "agent_memory_guard.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Execute the check command."""
    from agent_memory_guard import MemoryGuard, Policy

    guard = MemoryGuard(policy=Policy.strict())
    action = guard.write("_cli_check", args.text, source="cli")

    events = guard.events
    if args.format == "json":
        data: dict[str, Any] = {
            "text": args.text[:100],
            "action": action.value,
            "threats_detected": len(events),
            "events": [
                {
                    "detector": e.detector,
                    "severity": e.severity.value,
                    "action": e.action.value,
                    "message": e.message,
                }
                for e in events
            ],
        }
        print(json.dumps(data, indent=2))
    else:
        if not events:
            print("✓ No threats detected.")
        else:
            print(f"⚠ {len(events)} threat(s) detected:\n")
            for e in events:
                icon = {"info": "ℹ", "low": "🔵", "medium": "🟡", "high": "🟠", "critical": "🔴"}.get(
                    e.severity.value, "⚠"
                )
                print(f"  {icon} [{e.detector}] {e.message}")
                print(f"    Severity: {e.severity.value} | Action: {e.action.value}")
                print()

    return 0 if action.value == "allow" else 1


def main() -> int:
    """Main CLI entry point."""
    parser = _build_parser()
    args = parser.parse_args()

    if args.version:
        from agent_memory_guard import __version__

        print(f"agent-memory-guard {__version__}")
        return 0

    if args.command is None:
        parser.print_help()
        return 0

    commands = {
        "scan": cmd_scan,
        "serve": cmd_serve,
        "check": cmd_check,
    }

    handler = commands.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
