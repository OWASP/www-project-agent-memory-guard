"""OWASP Agent Memory Guard — MCP Server.

Wraps the Agent Memory Guard scanner as an MCP server so any
MCP-compatible agent (Claude, GPT, Gemini, etc.) can validate
memory entries in real-time.

Usage:
    uv run amg-mcp-server
    # or
    python -m amg_mcp_server
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mcp.server.fastmcp import FastMCP


class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    SECRET_LEAKAGE = "secret_leakage"
    INTEGRITY_TAMPERING = "integrity_tampering"
    ROLE_HIJACKING = "role_hijacking"
    INSTRUCTION_OVERRIDE = "instruction_override"
    DATA_EXFILTRATION = "data_exfiltration"


@dataclass
class ScanResult:
    is_safe: bool
    threats: list[dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    entry_text: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_safe": self.is_safe,
            "risk_score": round(self.risk_score, 3),
            "threats_found": len(self.threats),
            "threats": self.threats,
            "scanned_text_preview": self.entry_text[:200] + "..."
            if len(self.entry_text) > 200
            else self.entry_text,
        }


_INJECTION_PATTERNS = [
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I), "instruction_override", 0.95),
    (re.compile(r"you\s+are\s+now\s+(?:a|an|the)\s+", re.I), "role_hijacking", 0.85),
    (re.compile(r"system\s*:\s*", re.I), "prompt_injection", 0.80),
    (re.compile(r"<\|im_start\|>|<\|im_end\|>", re.I), "prompt_injection", 0.95),
    (re.compile(r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>", re.I), "prompt_injection", 0.90),
    (re.compile(r"forget\s+(everything|all|what)\s+(you|I)", re.I), "instruction_override", 0.85),
    (re.compile(r"new\s+instructions?\s*:", re.I), "instruction_override", 0.90),
    (re.compile(r"do\s+not\s+follow\s+(any\s+)?(previous|prior|earlier)", re.I), "instruction_override", 0.90),
    (re.compile(r"pretend\s+(you\s+are|to\s+be)", re.I), "role_hijacking", 0.80),
    (re.compile(r"act\s+as\s+(if\s+you\s+are|a|an)", re.I), "role_hijacking", 0.75),
    (re.compile(r"from\s+now\s+on\s*,?\s*(you|your|always)", re.I), "instruction_override", 0.85),
    (re.compile(r"override\s+(your|the|all)\s+(rules|instructions|guidelines)", re.I), "instruction_override", 0.95),
    (re.compile(r"jailbreak|DAN\s*mode|developer\s*mode", re.I), "prompt_injection", 0.95),
]

_SECRET_PATTERNS = [
    (re.compile(r"(?:api[_-]?key|apikey)\s*[:=]\s*\S{10,}", re.I), "api_key_exposure", 0.90),
    (re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*\S{6,}", re.I), "password_exposure", 0.85),
    (re.compile(r"(?:secret|token|bearer)\s*[:=]\s*\S{10,}", re.I), "token_exposure", 0.90),
    (re.compile(r"(?:aws_access_key_id|aws_secret_access_key)\s*[:=]\s*\S+", re.I), "aws_credential", 0.95),
    (re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", re.I), "private_key", 0.99),
    (re.compile(r"ghp_[A-Za-z0-9]{36,}", re.I), "github_token", 0.95),
    (re.compile(r"sk-[A-Za-z0-9]{32,}", re.I), "openai_key", 0.95),
    (re.compile(r"xox[baprs]-[A-Za-z0-9\-]+", re.I), "slack_token", 0.90),
]

_EXFILTRATION_PATTERNS = [
    (re.compile(r"send\s+(all|this|the)\s+(data|info|information|content)\s+to", re.I), "data_exfiltration", 0.85),
    (re.compile(r"(curl|wget|fetch)\s+https?://", re.I), "data_exfiltration", 0.70),
    (re.compile(r"base64\s*(encode|decode)", re.I), "obfuscation_attempt", 0.60),
]


def scan_entry(text: str) -> ScanResult:
    if not text or not text.strip():
        return ScanResult(is_safe=True, entry_text=text or "")
    threats = []
    max_score = 0.0
    for pattern, category, confidence in _INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            threats.append({"category": category, "confidence": confidence, "matched_text": match.group(0)[:100]})
            max_score = max(max_score, confidence)
    for pattern, category, confidence in _SECRET_PATTERNS:
        match = pattern.search(text)
        if match:
            threats.append({"category": "secret_leakage", "subcategory": category, "confidence": confidence})
            max_score = max(max_score, confidence)
    for pattern, category, confidence in _EXFILTRATION_PATTERNS:
        match = pattern.search(text)
        if match:
            threats.append({"category": "data_exfiltration", "subcategory": category, "confidence": confidence})
            max_score = max(max_score, confidence)
    return ScanResult(is_safe=len(threats) == 0, threats=threats, risk_score=max_score, entry_text=text)


mcp = FastMCP("OWASP Agent Memory Guard", instructions="Runtime defense for AI agent memory stores.")


@mcp.tool()
def scan_memory_entry(text: str) -> str:
    """Scan a single memory entry for security threats."""
    result = scan_entry(text)
    return json.dumps(result.to_dict(), indent=2)


@mcp.tool()
def scan_memory_batch(entries: list[str]) -> str:
    """Scan multiple memory entries in batch."""
    results = []
    blocked = 0
    for i, entry in enumerate(entries):
        r = scan_entry(entry)
        results.append({"index": i, **r.to_dict()})
        if not r.is_safe:
            blocked += 1
    return json.dumps({"total": len(entries), "blocked": blocked, "results": results}, indent=2)


@mcp.tool()
def validate_before_store(text: str, user_id: str = "unknown") -> str:
    """Validate a memory entry before storing. Returns ALLOW or BLOCK."""
    result = scan_entry(text)
    action = "ALLOW" if result.is_safe else "BLOCK"
    return json.dumps({"action": action, "risk_score": result.risk_score, "threats": result.threats}, indent=2)


@mcp.tool()
def validate_before_recall(text: str) -> str:
    """Validate a recalled memory entry before injecting into context."""
    result = scan_entry(text)
    action = "ALLOW" if result.is_safe else "BLOCK"
    return json.dumps({"action": action, "risk_score": result.risk_score, "threats": result.threats}, indent=2)


@mcp.tool()
def get_threat_categories() -> str:
    """List all threat categories that Agent Memory Guard detects."""
    return json.dumps([c.value for c in ThreatCategory])


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
