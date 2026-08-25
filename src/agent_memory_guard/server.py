"""OWASP Agent Memory Guard — REST API Server.

Provides a FastAPI-based REST API for runtime memory scanning.
Start with: `amg serve` or `uvicorn agent_memory_guard.server:app`

Endpoints:
  POST /scan          — Scan text for threats (stateless)
  POST /write         — Write to guarded memory store
  POST /read          — Read from guarded memory store
  GET  /events        — List recent security events
  GET  /health        — Health check
  GET  /stats         — Guard statistics
  POST /scan/file     — Scan a Python file for vulnerabilities
"""
from __future__ import annotations

import os
import time
from typing import Any

try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
except ImportError as e:
    raise ImportError(
        "FastAPI is required for the API server. "
        "Install with: pip install agent-memory-guard[server]"
    ) from e

from agent_memory_guard import (
    Action,
    MemoryGuard,
    Policy,
    __version__,
)
from agent_memory_guard.events import SourceClass

# ============================================================================
# APP SETUP
# ============================================================================

app = FastAPI(
    title="OWASP Agent Memory Guard API",
    description=(
        "Runtime defense layer that protects AI agent memory from poisoning attacks. "
        "Screens memory reads/writes for prompt injection, data leakage, "
        "privilege escalation, and cross-task contamination."
    ),
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS is opt-in, and deliberately so.
#
# This app ships no authentication. Combining that with allow_origins=["*"] and
# allow_credentials=True meant any web page the operator visited could POST to
# /write on their locally running server and put arbitrary content into the
# guarded memory store - or POST /reset and clear the guard's state. For a tool
# whose purpose is preventing untrusted writes to agent memory, shipping a
# browser-reachable unauthenticated write endpoint by default was the wrong
# default.
#
# Note that Starlette does not send a literal "*" when allow_credentials is set:
# it echoes the requesting origin back, which makes the wildcard MORE permissive
# than it looks, not less.
#
# Set AMG_CORS_ORIGINS to a comma-separated list of exact origins to enable it:
#     AMG_CORS_ORIGINS="http://localhost:3000,https://console.internal"
_cors_origins = [
    origin.strip()
    for origin in os.environ.get("AMG_CORS_ORIGINS", "").split(",")
    if origin.strip()
]
if _cors_origins:
    if "*" in _cors_origins:
        raise SystemExit(
            "AMG_CORS_ORIGINS=* is not supported. This server has no authentication, "
            "so allowing every origin would let any web page write to the memory store. "
            "List the exact origins you need."
        )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

# Initialize guard based on environment
_policy_name = os.environ.get("AMG_POLICY", "strict")
_policy_map = {
    "permissive": Policy.permissive,
    "strict": Policy.strict,
    "tiered": Policy.tiered,
}
_policy = _policy_map.get(_policy_name, Policy.strict)()
_guard = MemoryGuard(policy=_policy)
_start_time = time.time()


# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================


class ScanRequest(BaseModel):
    """Request to scan text for threats."""

    text: str = Field(..., description="Text content to scan for threats")
    key: str = Field(default="_scan", description="Memory key context (optional)")
    source: str = Field(default="api", description="Source identifier")
    source_class: str | None = Field(
        default=None,
        description="Source class: agent_authored, external_tool, user_input",
    )


class ScanResponse(BaseModel):
    """Response from threat scanning."""

    action: str = Field(..., description="Action taken: allow, block, quarantine, redact")
    threats_detected: int = Field(..., description="Number of threats found")
    events: list[dict[str, Any]] = Field(default_factory=list, description="Security events")
    safe: bool = Field(..., description="Whether the text is considered safe")


class WriteRequest(BaseModel):
    """Request to write to guarded memory."""

    key: str = Field(..., description="Memory key to write")
    value: Any = Field(..., description="Value to store")
    source: str = Field(default="api", description="Source identifier")
    source_class: str | None = Field(default=None, description="Source class")
    task_id: str | None = Field(default=None, description="Task context ID")


class WriteResponse(BaseModel):
    """Response from a guarded write."""

    action: str
    key: str
    stored: bool
    events: list[dict[str, Any]] = Field(default_factory=list)


class ReadRequest(BaseModel):
    """Request to read from guarded memory."""

    key: str = Field(..., description="Memory key to read")


class ReadResponse(BaseModel):
    """Response from a guarded read."""

    key: str
    value: Any
    found: bool
    events: list[dict[str, Any]] = Field(default_factory=list)


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "healthy"
    version: str = __version__
    policy: str = _policy_name
    uptime_seconds: float = 0.0


class StatsResponse(BaseModel):
    """Guard statistics."""

    total_events: int
    events_by_severity: dict[str, int]
    events_by_detector: dict[str, int]
    quarantined_keys: int
    memory_keys: int


class FileScanRequest(BaseModel):
    """Request to scan a file for vulnerabilities."""

    content: str = Field(..., description="Python file content to scan")
    filename: str = Field(default="scan_target.py", description="Filename for context")


class FileScanResponse(BaseModel):
    """Response from file scanning."""

    findings: list[dict[str, Any]]
    files_scanned: int = 1
    total_findings: int


# ============================================================================
# ENDPOINTS
# ============================================================================


@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version=__version__,
        policy=_policy_name,
        uptime_seconds=round(time.time() - _start_time, 2),
    )


@app.post("/scan", response_model=ScanResponse)
async def scan_text(req: ScanRequest):
    """Scan text for memory poisoning threats without storing.

    This is the primary endpoint for checking if content is safe
    before writing to agent memory.
    """
    # Use a temporary guard to avoid polluting the main store
    temp_guard = MemoryGuard(policy=_policy)

    source_cls = None
    if req.source_class:
        try:
            source_cls = SourceClass(req.source_class)
        except ValueError:
            pass

    action = temp_guard.write(
        req.key,
        req.text,
        source=req.source,
        source_class=source_cls,
    )

    events = [
        {
            "detector": e.detector,
            "severity": e.severity.value,
            "action": e.action.value,
            "message": e.message,
        }
        for e in temp_guard.events
    ]

    return ScanResponse(
        action=action.value,
        threats_detected=len(events),
        events=events,
        safe=action == Action.ALLOW,
    )


@app.post("/write", response_model=WriteResponse)
async def write_memory(req: WriteRequest):
    """Write a value to the guarded memory store.

    The value is screened through all detectors before being stored.
    """
    source_cls = None
    if req.source_class:
        try:
            source_cls = SourceClass(req.source_class)
        except ValueError:
            pass

    initial_events = len(_guard.events)
    action = _guard.write(
        req.key,
        req.value,
        source=req.source,
        source_class=source_cls,
        task_id=req.task_id,
    )

    new_events = _guard.events[initial_events:]
    events = [
        {
            "detector": e.detector,
            "severity": e.severity.value,
            "action": e.action.value,
            "message": e.message,
        }
        for e in new_events
    ]

    return WriteResponse(
        action=action.value,
        key=req.key,
        stored=action in (Action.ALLOW, Action.REDACT),
        events=events,
    )


@app.post("/read", response_model=ReadResponse)
async def read_memory(req: ReadRequest):
    """Read a value from the guarded memory store."""
    initial_events = len(_guard.events)
    value = _guard.read(req.key)

    new_events = _guard.events[initial_events:]
    events = [
        {
            "detector": e.detector,
            "severity": e.severity.value,
            "action": e.action.value,
            "message": e.message,
        }
        for e in new_events
    ]

    return ReadResponse(
        key=req.key,
        value=value,
        found=value is not None,
        events=events,
    )


@app.get("/events")
async def list_events(limit: int = 50, severity: str | None = None):
    """List recent security events."""
    events = _guard.events
    if severity:
        events = [e for e in events if e.severity.value == severity]
    events = events[-limit:]
    return {
        "total": len(_guard.events),
        "returned": len(events),
        "events": [
            {
                "detector": e.detector,
                "severity": e.severity.value,
                "action": e.action.value,
                "operation": e.operation,
                "key": e.key,
                "message": e.message,
                "metadata": e.metadata,
            }
            for e in events
        ],
    }


@app.get("/stats", response_model=StatsResponse)
async def stats():
    """Get guard statistics."""
    events = _guard.events
    by_severity: dict[str, int] = {}
    by_detector: dict[str, int] = {}
    for e in events:
        by_severity[e.severity.value] = by_severity.get(e.severity.value, 0) + 1
        by_detector[e.detector] = by_detector.get(e.detector, 0) + 1

    return StatsResponse(
        total_events=len(events),
        events_by_severity=by_severity,
        events_by_detector=by_detector,
        quarantined_keys=len(_guard.quarantine),
        memory_keys=len(list(_guard._store.keys())),
    )


@app.post("/scan/file", response_model=FileScanResponse)
async def scan_file(req: FileScanRequest):
    """Scan Python file content for memory security vulnerabilities."""
    import tempfile
    from pathlib import Path

    from agent_memory_guard.scanner import MemorySecurityScanner, Severity

    # Write content to temp file for scanning
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", prefix=req.filename.replace(".py", "_"), delete=False
    ) as f:
        f.write(req.content)
        temp_path = Path(f.name)

    try:
        scanner = MemorySecurityScanner(min_severity=Severity.LOW)
        result = scanner.scan_file(temp_path)
    finally:
        temp_path.unlink(missing_ok=True)

    findings = [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "description": f.description,
            "severity": f.severity.value,
            "line": f.line,
            "snippet": f.snippet,
            "recommendation": f.recommendation,
        }
        for f in result.findings
    ]

    return FileScanResponse(
        findings=findings,
        files_scanned=1,
        total_findings=len(findings),
    )


@app.post("/reset")
async def reset_guard():
    """Reset the guard state (for testing/demo purposes)."""
    global _guard
    _guard = MemoryGuard(policy=_policy)
    return {"status": "reset", "message": "Guard state cleared"}
