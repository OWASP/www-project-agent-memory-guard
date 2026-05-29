"""Tests for AutoGen and OpenAI Agents SDK integration adapters."""
import pytest
from agent_memory_guard.integrations.autogen import GuardedAutoGenAgent
from agent_memory_guard.integrations.openai_agents import GuardedAgentContext


def test_autogen_adapter_imports():
    """Verify the AutoGen adapter loads without autogen installed."""
    assert GuardedAutoGenAgent is not None


def test_openai_agents_adapter_imports():
    """Verify the OpenAI Agents adapter loads."""
    assert GuardedAgentContext is not None