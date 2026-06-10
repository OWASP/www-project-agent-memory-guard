"""Tool Output Validator — scan responses from external tools before agent processes them.

When AI agents call external tools (web search, APIs, code execution, file reads),
the responses may contain injected instructions or sensitive data that could
compromise the agent. This module validates tool outputs before they reach the agent.

Usage:
    from agent_memory_guard import scan_tool_output

    # After calling a web search tool
    search_results = web_search.run("latest AI news")
    result = scan_tool_output(search_results, tool_name="web_search")
    if not result.safe:
        print(f"Blocked: {result.threats}")

    # After executing code
    code_output = sandbox.execute("print(os.environ)")
    result = scan_tool_output(code_output, tool_name="code_exec", trust_level="low")
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Literal

from agent_memory_guard.detectors import DetectionResult
from agent_memory_guard.scan import (
    ScanResult,
    ThreatType,
    _get_detectors,
)


@dataclass
class ToolScanResult(ScanResult):
    """Extended scan result for tool outputs."""

    tool_name: str = ""
    trust_level: str = "medium"
    blocked: bool = False


_TRUST_THRESHOLDS = {
    "high": 0.9,
    "medium": 0.6,
    "low": 0.3,
    "none": 0.0,
}


def scan_tool_output(
    output: str,
    *,
    tool_name: str = "unknown",
    trust_level: Literal["high", "medium", "low", "none"] = "medium",
    max_length: int = 50_000,
) -> ToolScanResult:
    """Scan output from an external tool for threats."""
    start = time.perf_counter_ns()

    if len(output) > max_length:
        output = output[:max_length]

    detectors = _get_detectors()
    threshold = _TRUST_THRESHOLDS[trust_level]

    threats: list[ThreatType] = []
    max_confidence = 0.0

    for detector in detectors:
        result: DetectionResult = detector.detect(output)
        if result.detected and result.confidence >= threshold:
            from agent_memory_guard.detectors import (
                PromptInjectionDetector,
                SelfReinforcementDetector,
                SensitiveDataDetector,
            )
            if isinstance(detector, PromptInjectionDetector):
                threats.append(ThreatType.PROMPT_INJECTION)
            elif isinstance(detector, SensitiveDataDetector):
                threats.append(ThreatType.SECRET_LEAKAGE)
            elif isinstance(detector, SelfReinforcementDetector):
                threats.append(ThreatType.SELF_REINFORCEMENT)
            max_confidence = max(max_confidence, result.confidence)

    elapsed_us = (time.perf_counter_ns() - start) // 1000
    blocked = len(threats) > 0

    return ToolScanResult(
        safe=not blocked,
        threats=threats,
        confidence=max_confidence,
        latency_us=elapsed_us,
        text_length=len(output),
        tool_name=tool_name,
        trust_level=trust_level,
        blocked=blocked,
    )


def create_tool_scanner(
    tool_name: str,
    trust_level: Literal["high", "medium", "low", "none"] = "medium",
):
    """Create a reusable scanner function for a specific tool."""
    def scanner(output: str, **kwargs) -> ToolScanResult:
        return scan_tool_output(
            output,
            tool_name=tool_name,
            trust_level=trust_level,
            **kwargs,
        )
    scanner.__name__ = f"scan_{tool_name}"
    scanner.__doc__ = f"Scan output from {tool_name} (trust_level={trust_level})"
    return scanner
