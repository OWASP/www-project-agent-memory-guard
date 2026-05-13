"""Prometheus metrics exporter for Agent Memory Guard.

Exposes security event counters, latency histograms, and detection rates.
Metrics are only enabled when ``prometheus-client`` is installed.
"""
from __future__ import annotations

from typing import Optional

_HAS_PROMETHEUS = False
try:  # pragma: no cover - optional dependency
    from prometheus_client import (  # type: ignore
        Counter,
        Gauge,
        Histogram,
        start_http_server,
    )

    _HAS_PROMETHEUS = True
except Exception:  # pragma: no cover - optional dependency
    pass


class PrometheusMetrics:
    """Expose Agent Memory Guard metrics via Prometheus endpoint."""

    def __init__(self, port: int = 9090, *, enable_server: bool = True) -> None:
        if not _HAS_PROMETHEUS:
            raise ImportError(
                "prometheus-client is required for PrometheusMetrics. "
                "Install with: pip install agent-memory-guard[metrics]"
            )

        self.port = port
        self.events_total = Counter(
            "agent_memory_guard_events_total",
            "Total security events processed",
            ["detector", "action", "severity"],
        )
        self.scan_duration = Histogram(
            "agent_memory_guard_scan_duration_seconds",
            "Time spent scanning memory operations",
            ["operation"],
        )
        self.quarantine_size = Gauge(
            "agent_memory_guard_quarantine_size",
            "Number of items currently in quarantine",
        )
        self.integrity_violations = Counter(
            "agent_memory_guard_integrity_violations_total",
            "Total integrity violations detected",
            ["detector"],
        )

        if enable_server:
            start_http_server(port)
            print(f"Prometheus metrics available at http://localhost:{port}/metrics")

    def handle_event(self, event: dict) -> None:
        """Handle a security event and update metrics."""
        detector = event.get("detector", "unknown")
        action = event.get("action", "unknown")
        severity = event.get("severity", "unknown")

        self.events_total.labels(
            detector=detector,
            action=action,
            severity=severity,
        ).inc()

        if action == "quarantine":
            self.quarantine_size.inc()
        elif action == "release":
            self.quarantine_size.dec()

        if event.get("type") == "integrity_violation":
            self.integrity_violations.labels(
                detector=detector,
            ).inc()

    def record_scan_duration(self, operation: str, duration: float) -> None:
        """Record scan duration for an operation."""
        self.scan_duration.labels(operation=operation).observe(duration)