"""LangChain middleware integration for OWASP Agent Memory Guard.

Provides runtime defense against AI agent memory poisoning (OWASP ASI06)
by scanning model inputs and outputs for prompt injection, secret leakage,
and other memory-based attacks.

Usage:
    from langchain_agent_memory_guard import MemoryGuardMiddleware
    from langchain.agents import create_agent

    agent = create_agent(
        "openai:gpt-4o",
        tools=[...],
        middleware=[MemoryGuardMiddleware()],
    )
"""

from __future__ import annotations

from langchain_agent_memory_guard.middleware import (
    MemoryGuardMiddleware,
    MemoryGuardViolation,
)

__all__ = ["MemoryGuardMiddleware", "MemoryGuardViolation"]
__version__ = "0.1.0"
