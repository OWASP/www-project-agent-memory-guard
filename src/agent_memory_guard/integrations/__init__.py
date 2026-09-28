from agent_memory_guard.integrations.langchain import GuardedChatMessageHistory

__all__ = ["GuardedChatMessageHistory"]

try:
    from agent_memory_guard.integrations.autogen import (
        GuardedAutoGenAgent,
        GuardedGroupChatManager,
        install_guard,
    )
except ImportError:  # pragma: no cover - optional dependency
    pass
else:
    __all__ += [
        "GuardedAutoGenAgent",
        "GuardedGroupChatManager",
        "install_guard",
    ]

try:
    from agent_memory_guard.integrations.openai_agents import (
        GuardedAgentContext,
        GuardedHandoff,
        GuardedToolOutput,
    )
except ImportError:  # pragma: no cover - optional dependency
    pass
else:
    __all__ += ["GuardedAgentContext", "GuardedHandoff", "GuardedToolOutput"]
