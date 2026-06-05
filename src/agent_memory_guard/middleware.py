"""FastAPI & Flask Middleware — zero-code memory guard for web APIs.

Drop-in middleware that scans all incoming request bodies for prompt injection,
sensitive data leakage, and other threats before they reach your AI endpoints.

Usage (FastAPI):
    from fastapi import FastAPI
    from agent_memory_guard.middleware import FastAPIGuard

    app = FastAPI()
    app.add_middleware(FastAPIGuard, paths=["/api/chat", "/api/memory"])

Usage (Flask):
    from flask import Flask
    from agent_memory_guard.middleware import FlaskGuard

    app = Flask(__name__)
    FlaskGuard(app, paths=["/api/chat", "/api/memory"])
"""

from __future__ import annotations

import json
import time
from typing import Callable, Optional, Sequence

from agent_memory_guard.scan import scan, ScanResult, ThreatType


class FastAPIGuard:
    """ASGI middleware for FastAPI that scans request bodies."""

    def __init__(
        self,
        app,
        *,
        paths: Optional[Sequence[str]] = None,
        block_on_threat: bool = True,
        log_threats: bool = True,
    ):
        self.app = app
        self.paths = set(paths) if paths else None
        self.block_on_threat = block_on_threat
        self.log_threats = log_threats

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if self.paths and path not in self.paths:
            await self.app(scope, receive, send)
            return

        body_chunks = []
        async def receive_wrapper():
            message = await receive()
            if message.get("type") == "http.request":
                body = message.get("body", b"")
                body_chunks.append(body)
            return message

        # Intercept the first receive to get the body
        message = await receive()
        if message.get("type") == "http.request":
            body = message.get("body", b"")
            body_chunks.append(body)

            try:
                text = body.decode("utf-8")
                result = scan(text)

                if not result.safe and self.block_on_threat:
                    response_body = json.dumps({
                        "error": "Request blocked by Agent Memory Guard",
                        "threats": [t.value for t in result.threats],
                        "confidence": result.confidence,
                    }).encode()

                    await send({
                        "type": "http.response.start",
                        "status": 403,
                        "headers": [
                            [b"content-type", b"application/json"],
                            [b"x-amg-blocked", b"true"],
                        ],
                    })
                    await send({
                        "type": "http.response.body",
                        "body": response_body,
                    })
                    return
            except (UnicodeDecodeError, Exception):
                pass

        async def patched_receive():
            if body_chunks:
                return {"type": "http.request", "body": body_chunks.pop(0)}
            return await receive()

        await self.app(scope, patched_receive, send)


class FlaskGuard:
    """Flask extension that scans request bodies before handlers."""

    def __init__(
        self,
        app=None,
        *,
        paths: Optional[Sequence[str]] = None,
        block_on_threat: bool = True,
    ):
        self.paths = set(paths) if paths else None
        self.block_on_threat = block_on_threat
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        app.before_request(self._check_request)

    def _check_request(self):
        from flask import request, jsonify, abort

        if self.paths and request.path not in self.paths:
            return None

        body = request.get_data(as_text=True)
        if not body:
            return None

        result = scan(body)
        if not result.safe and self.block_on_threat:
            return jsonify({
                "error": "Request blocked by Agent Memory Guard",
                "threats": [t.value for t in result.threats],
                "confidence": result.confidence,
            }), 403

        return None
