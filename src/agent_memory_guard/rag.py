"""RAG Input Scanner — validate retrieved documents before prompt injection.

Scans documents retrieved from vector stores, knowledge bases, or any RAG
pipeline before they're injected into LLM prompts. Prevents poisoned documents
from hijacking agent behavior.

Usage:
    from agent_memory_guard import scan_rag_input, scan_rag_batch

    # Single document
    result = scan_rag_input(document.page_content, source="vectordb")
    if result.safe:
        context_window.append(document)

    # Batch of retrieved docs
    docs = retriever.get_relevant_documents(query)
    safe_docs = scan_rag_batch(docs, content_key="page_content")
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from agent_memory_guard.detectors import DetectionResult
from agent_memory_guard.scan import (
    ScanResult,
    ThreatType,
    _get_detectors,
)


@dataclass
class RAGScanResult(ScanResult):
    """Extended scan result for RAG documents."""

    source: str = ""
    chunk_index: int = -1
    contains_instructions: bool = False


def scan_rag_input(
    content: str,
    *,
    source: str = "unknown",
    chunk_index: int = -1,
    strict: bool = True,
) -> RAGScanResult:
    """Scan a single retrieved document/chunk for threats."""
    start = time.perf_counter_ns()
    detectors = _get_detectors()

    threats: list[ThreatType] = []
    max_confidence = 0.0
    contains_instructions = False

    instruction_markers = [
        "ignore previous", "ignore all", "you are now",
        "new instructions", "system prompt", "disregard",
        "override", "forget everything", "act as", "pretend to be",
    ]

    content_lower = content.lower()
    for marker in instruction_markers:
        if marker in content_lower:
            contains_instructions = True
            if strict:
                threats.append(ThreatType.PROMPT_INJECTION)
                max_confidence = max(max_confidence, 0.7)
            break

    for detector in detectors:
        result: DetectionResult = detector.detect(content)
        if result.detected:
            from agent_memory_guard.detectors import (
                PromptInjectionDetector,
                SelfReinforcementDetector,
                SensitiveDataDetector,
            )
            if isinstance(detector, PromptInjectionDetector):
                if ThreatType.PROMPT_INJECTION not in threats:
                    threats.append(ThreatType.PROMPT_INJECTION)
            elif isinstance(detector, SensitiveDataDetector):
                threats.append(ThreatType.SECRET_LEAKAGE)
            elif isinstance(detector, SelfReinforcementDetector):
                threats.append(ThreatType.SELF_REINFORCEMENT)
            max_confidence = max(max_confidence, result.confidence)

    elapsed_us = (time.perf_counter_ns() - start) // 1000

    return RAGScanResult(
        safe=len(threats) == 0,
        threats=threats,
        confidence=max_confidence,
        latency_us=elapsed_us,
        text_length=len(content),
        source=source,
        chunk_index=chunk_index,
        contains_instructions=contains_instructions,
    )


def scan_rag_batch(
    documents: Sequence[Any],
    *,
    content_key: str = "page_content",
    source: str = "batch",
    strict: bool = True,
) -> list[RAGScanResult]:
    """Scan a batch of retrieved documents."""
    results = []
    for i, doc in enumerate(documents):
        if isinstance(doc, dict):
            content = doc.get(content_key, "")
        elif hasattr(doc, content_key):
            content = getattr(doc, content_key)
        elif isinstance(doc, str):
            content = doc
        else:
            content = str(doc)

        result = scan_rag_input(content, source=source, chunk_index=i, strict=strict)
        results.append(result)

    return results


def filter_safe_documents(
    documents: Sequence[Any],
    *,
    content_key: str = "page_content",
    strict: bool = True,
) -> list[Any]:
    """Return only safe documents from a batch."""
    results = scan_rag_batch(documents, content_key=content_key, strict=strict)
    return [doc for doc, result in zip(documents, results) if result.safe]
