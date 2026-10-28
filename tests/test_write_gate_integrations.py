"""Pending writes must not reach backing stores or agent inputs."""
from __future__ import annotations

import importlib.util
import sys
import types
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import agent_memory_guard
from agent_memory_guard import Action, MemoryGuard, Policy, WriteGateRule
from agent_memory_guard.integrations import autogen, langchain, llamaindex
from agent_memory_guard.integrations.agno import GuardedMemoryManager
from agent_memory_guard.integrations.crewai import GuardedMemory
from agent_memory_guard.integrations.openai_agents import GuardedAgentContext, GuardedToolOutput
from agent_memory_guard.storage import InMemoryStore

ROOT = Path(__file__).resolve().parents[1]
HELD = (Action.REQUIRE_APPROVAL, Action.REQUIRE_CORROBORATION)


class _LegacyAction(str, Enum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"
    QUARANTINE = "quarantine"


@pytest.fixture(params=HELD)
def gated(request):
    def make(initial=None):
        return MemoryGuard(
            InMemoryStore(initial),
            policy=Policy(write_gates=(WriteGateRule("hold", ("*",), action=request.param),)),
            detectors=[],
        )

    return make


def test_context_does_not_update_external_state(gated):
    guard = gated()
    context = Mock()
    wrapped = GuardedAgentContext(context, guard)
    assert wrapped.set_state("notes", "requires owner review") is False
    context.set_state.assert_not_called()
    assert len(guard.pending_writes) == 1


def test_tool_output_is_not_released(gated):
    guard = gated()
    assert GuardedToolOutput(guard).screen_tool_output("lookup", "held result") is False
    assert len(guard.pending_writes) == 1


def test_crewai_does_not_write_through_or_claim_ownership(gated):
    guard = gated()
    memory = Mock()
    wrapped = GuardedMemory(memory, guard)
    assert wrapped.write("notes", "held value") is False
    memory.write.assert_not_called()
    assert wrapped.get_owned_keys() == set()
    assert len(guard.pending_writes) == 1


def test_crewai_search_does_not_release_pending_results(gated):
    guard = gated()
    memory = Mock()
    memory.search.return_value = [{"text": "held search result"}]
    assert GuardedMemory(memory, guard).search("notes") == []
    assert len(guard.pending_writes) == 1


def test_chat_history_does_not_advance_past_pending_message(gated, monkeypatch):
    monkeypatch.setattr(langchain, "messages_to_dict", lambda messages: list(messages))
    guard = gated({"messages.s.__count__": 0})
    history = langchain.GuardedChatMessageHistory("s", guard)
    history.add_message({"type": "human", "data": {"content": "held message"}})
    assert guard.read("messages.s.__count__") == 0
    assert history.messages == []
    assert len(guard.pending_writes) == 1


@pytest.mark.parametrize("method", ["add_message", "set_messages"])
def test_chat_store_does_not_forward_pending_messages(gated, method):
    guard = gated()
    backing = Mock()
    backing.get_messages.return_value = []
    wrapped = llamaindex.GuardedChatStore(backing, guard)
    message = SimpleNamespace(model_dump=lambda: {"role": "user", "content": "held message"})
    if method == "add_message":
        wrapped.add_message("s", message)
    else:
        wrapped.set_messages("s", [message])
    backing.add_message.assert_not_called()
    backing.set_messages.assert_not_called()
    assert len(guard.pending_writes) == 1


@pytest.mark.parametrize("method", ["send", "receive"])
def test_autogen_does_not_forward_pending_messages(gated, monkeypatch, method):
    monkeypatch.setattr(autogen, "_HAS_AUTOGEN", True)
    guard = gated()
    agent = Mock(name="wrapped_agent")
    agent.name = "assistant"
    wrapped = autogen.GuardedAutoGenAgent(agent, guard, drop_blocked=False)
    if method == "send":
        wrapped.send("held message", recipient=object())
    else:
        wrapped.receive("held message", sender=object())
    agent.send.assert_not_called()
    agent.receive.assert_not_called()
    assert len(guard.pending_writes) == 1


def test_autogen_reply_hook_holds_even_when_not_dropping_violations(gated, monkeypatch):
    monkeypatch.setattr(autogen, "_HAS_AUTOGEN", True)
    guard = gated()
    agent = Mock()
    autogen.install_guard(agent, guard, drop_blocked=False)
    hook = agent.register_reply.call_args.args[1]
    assert hook(agent, [{"content": "held message"}], SimpleNamespace(name="user"), {}) == (True, "")
    assert len(guard.pending_writes) == 1


def test_group_manager_does_not_record_pending_message_as_committed(gated):
    guard = gated()
    manager = autogen.GuardedGroupChatManager(object(), guard)
    assert manager.record_message("assistant", {"content": "held message"}) is False
    assert manager._agent_keys == {}
    assert len(guard.pending_writes) == 1


def test_agno_screen_does_not_release_pending_memory(gated):
    guard = gated()
    owner = SimpleNamespace(guard=guard, _drop_blocked=False, _default_source_class="agent_authored")
    memory = SimpleNamespace(user_id="user", memory_id="note", memory="held value")
    assert GuardedMemoryManager._screen(owner, memory) is None
    assert len(guard.pending_writes) == 1


def _load(monkeypatch, name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("mode", ["block", "warn", "strip", "quarantine"])
def test_distributed_autogen_hook_never_releases_pending_content(gated, monkeypatch, mode):
    package = "autogen_agent_memory_guard"
    directory = ROOT / "integrations/autogen-agent-memory-guard" / package
    parent = types.ModuleType(package)
    parent.__path__ = [str(directory)]
    monkeypatch.setitem(sys.modules, package, parent)
    exceptions = _load(monkeypatch, package + ".exceptions", directory / "exceptions.py")
    module = _load(monkeypatch, package + ".hook", directory / "hook.py")
    hook = module.MemoryGuardHook(on_violation=mode)
    hook._guard = gated()
    with pytest.raises(exceptions.MemoryGuardViolation) as caught:
        hook.scan_message("held private content", sender="assistant")
    assert "held private content" not in str(caught.value)
    assert len(hook._guard.pending_writes) == 1


class _Message:
    type = "human"

    def __init__(self, content, tool_call_id="tool"):
        self.content = content
        self.tool_call_id = tool_call_id


def _load_middleware(monkeypatch):
    """Load the real adapter with minimal framework interface stand-ins."""
    paths = (
        "langchain_core", "langchain_core.messages", "langchain", "langchain.agents",
        "langchain.agents.middleware", "langchain.agents.middleware.types",
        "langgraph", "langgraph.prebuilt", "langgraph.prebuilt.tool_node", "langgraph.typing",
    )
    modules = {name: types.ModuleType(name) for name in paths}
    for name, module in modules.items():
        module.__path__ = []
        monkeypatch.setitem(sys.modules, name, module)
    for name in ("AIMessage", "BaseMessage", "ToolMessage"):
        setattr(modules["langchain_core.messages"], name, _Message)
    for name in ("AgentMiddleware", "ModelRequest", "ModelResponse"):
        setattr(modules["langchain.agents.middleware.types"], name, object)
    modules["langgraph.prebuilt.tool_node"].ToolCallRequest = object
    modules["langgraph.typing"].ContextT = object
    return _load(
        monkeypatch, "amg_pending_middleware",
        ROOT / "integrations/langchain-agent-memory-guard/langchain_agent_memory_guard/middleware.py",
    )


@pytest.mark.parametrize("mode", ["block", "warn", "strip"])
def test_distributed_middleware_does_not_forward_pending_model_input(gated, monkeypatch, mode):
    module = _load_middleware(monkeypatch)
    middleware = module.MemoryGuardMiddleware(on_violation=mode)
    middleware._guard = gated()
    with pytest.raises(module.MemoryGuardViolation) as caught:
        middleware.before_model({"messages": [_Message("held private content")]}, None)
    assert "held private content" not in str(caught.value)
    assert len(middleware._guard.pending_writes) == 1


@pytest.mark.parametrize("mode", ["block", "warn", "strip"])
def test_distributed_middleware_does_not_forward_pending_tool_result(gated, monkeypatch, mode):
    module = _load_middleware(monkeypatch)
    middleware = module.MemoryGuardMiddleware(on_violation=mode)
    middleware._guard = gated()
    request = SimpleNamespace(tool_call={"name": "lookup"})
    with pytest.raises(module.MemoryGuardViolation):
        middleware.wrap_tool_call(request, lambda _: _Message("held private content"))
    assert len(middleware._guard.pending_writes) == 1


def test_distributed_middleware_remains_compatible_with_older_core_actions(monkeypatch):
    monkeypatch.setattr(agent_memory_guard, "Action", _LegacyAction)
    module = _load_middleware(monkeypatch)
    middleware = module.MemoryGuardMiddleware()
    middleware._guard = Mock()
    middleware._guard.write.return_value = _LegacyAction.ALLOW
    assert middleware._check_content("ordinary content", "model_input") == (True, "")
    middleware._guard.delete.assert_called_once_with("__scan__model_input")


def test_distributed_autogen_hook_remains_compatible_with_older_core_actions(monkeypatch):
    monkeypatch.setattr(agent_memory_guard, "Action", _LegacyAction)
    package = "autogen_agent_memory_guard"
    directory = ROOT / "integrations/autogen-agent-memory-guard" / package
    parent = types.ModuleType(package)
    parent.__path__ = [str(directory)]
    monkeypatch.setitem(sys.modules, package, parent)
    _load(monkeypatch, package + ".exceptions", directory / "exceptions.py")
    module = _load(monkeypatch, package + ".hook", directory / "hook.py")
    hook = module.MemoryGuardHook()
    hook._guard = Mock()
    hook._guard.write.return_value = _LegacyAction.ALLOW
    result = hook.scan_message("ordinary content")
    assert result.allowed is True
    assert result.message_content == "ordinary content"
