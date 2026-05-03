"""OWASP Agent Memory Guard middleware for LangChain agents.

This middleware intercepts model calls and tool calls to scan for memory
poisoning attacks including prompt injection, secret leakage, and
unauthorized memory modifications.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from langchain_core.messages import AIMessage, BaseMessage, ToolMessage
from langchain.agents.middleware.types import (
    AgentMiddleware,
    ModelRequest,
    ModelResponse,
)
from langgraph.prebuilt.tool_node import ToolCallRequest
from langgraph.typing import ContextT
from typing_extensions import TypeVar

from agent_memory_guard import MemoryGuard, Policy, PolicyViolation

logger = logging.getLogger(__name__)

ResponseT = TypeVar("ResponseT", default=Any)


class MemoryGuardMiddleware(AgentMiddleware):
    """LangChain middleware that applies OWASP Agent Memory Guard protections.

    Scans model inputs and outputs for:
    - Prompt injection attempts embedded in memory/context
    - Secret/credential leakage in model responses
    - Anomalous content size that may indicate stuffing attacks
    - Unauthorized modifications to protected memory keys

    Example:
        ```python
        from langchain_agent_memory_guard import MemoryGuardMiddleware
        from langchain.agents import create_agent

        # Use with default strict policy
        agent = create_agent(
            "openai:gpt-4o",
            tools=[...],
            middleware=[MemoryGuardMiddleware()],
        )

        # Use with custom policy
        from agent_memory_guard import Policy
        policy = Policy.strict()
        agent = create_agent(
            "openai:gpt-4o",
            tools=[...],
            middleware=[MemoryGuardMiddleware(policy=policy)],
        )
        ```
    """

    def __init__(
        self,
        policy: Policy | None = None,
        on_violation: str = "block",
        log_violations: bool = True,
    ) -> None:
        """Initialize the memory guard middleware.

        Args:
            policy: The security policy to enforce. Defaults to Policy.strict().
            on_violation: Action to take on violation. One of:
                - "block": Raise MemoryGuardViolation (default)
                - "warn": Log a warning and continue
                - "strip": Remove violating content and continue
            log_violations: Whether to log detected violations.
        """
        if on_violation not in ("block", "warn", "strip"):
            msg = f"on_violation must be 'block', 'warn', or 'strip', got '{on_violation}'"
            raise ValueError(msg)

        self._policy = policy or Policy.strict()
        self._on_violation = on_violation
        self._log_violations = log_violations
        self._guard = MemoryGuard(policy=self._policy)
        self._violation_count = 0

    @property
    def name(self) -> str:
        """Return the middleware name."""
        return "MemoryGuardMiddleware"

    @property
    def violation_count(self) -> int:
        """Return the total number of violations detected."""
        return self._violation_count

    def _check_content(self, text: str, source: str) -> tuple[bool, str]:
        """Check text content for security violations using MemoryGuard.write().

        The guard's write() method runs all configured detectors (injection,
        leakage, anomaly) and enforces the policy. We use a temporary key
        to test the content without persisting it.

        Args:
            text: The text content to check.
            source: Description of where the text came from (for logging).

        Returns:
            Tuple of (is_safe, violation_message). is_safe is True if no
            violations were detected.
        """
        try:
            self._guard.write(f"__scan__{source}", text, source="middleware")
            # Clean up the temporary key
            self._guard.delete(f"__scan__{source}")
            return (True, "")
        except PolicyViolation as e:
            return (False, str(e))

    def _handle_violation(self, source: str, message: str) -> None:
        """Handle a detected violation according to the configured mode.

        Args:
            source: Where the violation was detected.
            message: The violation details.

        Raises:
            MemoryGuardViolation: If on_violation is "block".
        """
        self._violation_count += 1

        if self._log_violations:
            logger.warning("Memory Guard violation in %s: %s", source, message)

        if self._on_violation == "block":
            raise MemoryGuardViolation(
                f"Security violation detected in {source}: {message}"
            )

    def _scan_message(self, msg: BaseMessage, source: str) -> bool:
        """Scan a single message. Returns True if safe, False if violation found."""
        content = msg.content if isinstance(msg.content, str) else str(msg.content)
        if not content:
            return True

        is_safe, violation_msg = self._check_content(content, source)
        if not is_safe:
            self._handle_violation(f"{source}[{msg.type}]", violation_msg)
            return False
        return True

    def before_model(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        """Scan messages in state before they are sent to the model.

        This catches prompt injection attempts that may have been injected
        into the agent's memory or context through tool outputs or
        previous interactions.
        """
        messages = (
            state.get("messages", [])
            if isinstance(state, dict)
            else getattr(state, "messages", [])
        )

        if not messages:
            return None

        if self._on_violation == "strip":
            safe_messages = []
            for msg in messages:
                content = msg.content if isinstance(msg.content, str) else str(msg.content)
                if not content:
                    safe_messages.append(msg)
                    continue
                is_safe, _ = self._check_content(content, "model_input")
                if is_safe:
                    safe_messages.append(msg)
                else:
                    self._violation_count += 1
                    if self._log_violations:
                        logger.warning(
                            "Memory Guard: stripped unsafe message from model input"
                        )

            if len(safe_messages) != len(messages):
                return {"messages": safe_messages}
        else:
            for msg in messages:
                self._scan_message(msg, "model_input")

        return None

    async def abefore_model(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        """Async version of before_model."""
        return self.before_model(state, runtime)

    def after_model(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        """Scan model output for secret leakage or injection propagation.

        This catches cases where the model may be leaking secrets or
        propagating injected instructions in its responses.
        """
        messages = (
            state.get("messages", [])
            if isinstance(state, dict)
            else getattr(state, "messages", [])
        )

        if not messages:
            return None

        # Only scan the last message (the model's response)
        last_msg = messages[-1]
        if not isinstance(last_msg, AIMessage):
            return None

        content = (
            last_msg.content
            if isinstance(last_msg.content, str)
            else str(last_msg.content)
        )
        if not content:
            return None

        self._scan_message(last_msg, "model_output")
        return None

    async def aafter_model(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        """Async version of after_model."""
        return self.after_model(state, runtime)

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage],
    ) -> ToolMessage:
        """Scan tool call results for injected content.

        Tool outputs are a primary vector for memory poisoning — an attacker
        can embed prompt injection payloads in data returned by tools (e.g.,
        web pages, database results, API responses).
        """
        result = handler(request)

        content = (
            result.content if isinstance(result.content, str) else str(result.content)
        )
        if not content:
            return result

        tool_name = request.tool_call.get("name", "unknown")
        is_safe, violation_msg = self._check_content(content, f"tool_output[{tool_name}]")

        if not is_safe:
            self._violation_count += 1
            if self._log_violations:
                logger.warning(
                    "Memory Guard violation in tool_output[%s]: %s",
                    tool_name,
                    violation_msg,
                )

            if self._on_violation == "block":
                raise MemoryGuardViolation(
                    f"Security violation in tool output [{tool_name}]: {violation_msg}"
                )
            elif self._on_violation == "strip":
                return ToolMessage(
                    content=(
                        "[Content removed by OWASP Agent Memory Guard: "
                        "security violation detected]"
                    ),
                    tool_call_id=result.tool_call_id,
                )
            # warn mode: return original result

        return result

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage]],
    ) -> ToolMessage:
        """Async version of wrap_tool_call."""
        result = await handler(request)

        content = (
            result.content if isinstance(result.content, str) else str(result.content)
        )
        if not content:
            return result

        tool_name = request.tool_call.get("name", "unknown")
        is_safe, violation_msg = self._check_content(content, f"tool_output[{tool_name}]")

        if not is_safe:
            self._violation_count += 1
            if self._log_violations:
                logger.warning(
                    "Memory Guard violation in tool_output[%s]: %s",
                    tool_name,
                    violation_msg,
                )

            if self._on_violation == "block":
                raise MemoryGuardViolation(
                    f"Security violation in tool output [{tool_name}]: {violation_msg}"
                )
            elif self._on_violation == "strip":
                return ToolMessage(
                    content=(
                        "[Content removed by OWASP Agent Memory Guard: "
                        "security violation detected]"
                    ),
                    tool_call_id=result.tool_call_id,
                )

        return result


class MemoryGuardViolation(Exception):
    """Raised when Agent Memory Guard detects a security violation.

    This exception is raised when the middleware is configured with
    on_violation="block" (the default) and a memory poisoning attempt
    is detected.
    """
