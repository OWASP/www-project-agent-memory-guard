# Test cases for semgrep/agent-memory-unguarded.yaml
# Run: semgrep --test semgrep/


# --- unguarded-agent-memory-write ---------------------------------------

def store_tool_output(agent_memory, tool_response):
    # ruleid: unguarded-agent-memory-write
    agent_memory["session.context"] = tool_response


def merge_scratchpad(scratchpad, updates):
    # ruleid: unguarded-agent-memory-write
    scratchpad.update(updates)


def init_state(state, key, default):
    # ruleid: unguarded-agent-memory-write
    state.setdefault(key, default)


def store_config(settings, key, value):
    # ok: unguarded-agent-memory-write
    settings[key] = value


def store_guarded(guard, agent_memory, key, value):
    guard.write(key, value)
    # ok: unguarded-agent-memory-write
    agent_memory[key] = value


# --- unguarded-mem0-add --------------------------------------------------

def persist_memory(mem0_client, content, user_id):
    # ruleid: unguarded-mem0-add
    mem0_client.add(content, user_id=user_id)


def persist_generic_memory(memory, fact):
    # ruleid: unguarded-mem0-add
    memory.add(fact)


def collect(results, item):
    # ok: unguarded-mem0-add
    results.add(item)


def persist_guarded(guard, mem0_client, content, user_id):
    guard.write("mem0.entry", content, source="mem0")
    # ok: unguarded-mem0-add
    mem0_client.add(content, user_id=user_id)


# --- unguarded-langchain-history-append ----------------------------------

def record_user_turn(chat_history, text):
    # ruleid: unguarded-langchain-history-append
    chat_history.add_user_message(text)


def record_ai_turn(history, text):
    # ruleid: unguarded-langchain-history-append
    history.add_ai_message(text)


def record_message(message_history, msg):
    # ruleid: unguarded-langchain-history-append
    message_history.add_message(msg)


def enqueue(dispatcher, msg):
    # ok: unguarded-langchain-history-append
    dispatcher.add_message(msg)


def record_guarded(guard, chat_history, text):
    guard.write("turn", text, source="user")
    # ok: unguarded-langchain-history-append
    chat_history.add_user_message(text)


# --- unguarded-autogen-history-append ------------------------------------

def append_turn(chat_history, msg):
    # ruleid: unguarded-autogen-history-append
    chat_history.append(msg)


def append_agent_message(conversation, msg):
    # ruleid: unguarded-autogen-history-append
    conversation.append(msg)


def append_result(results, item):
    # ok: unguarded-autogen-history-append
    results.append(item)


def append_guarded(guard, history, msg):
    guard.write("msg.next", msg["content"], source=msg["role"])
    # ok: unguarded-autogen-history-append
    history.append(msg)
