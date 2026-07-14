import pytest

from mirage.types import AssistantTurn, ToolCall
from mirage.backends import ScriptedBackend, RealBackend


def test_scripted_backend_returns_turns_in_order():
    t1 = AssistantTurn(tool_calls=[ToolCall(id="1", name="search", arguments={})])
    t2 = AssistantTurn(content="done")
    backend = ScriptedBackend([t1, t2])
    assert backend.complete([], []) is t1
    assert backend.complete([], []) is t2


def test_scripted_backend_raises_when_exhausted():
    backend = ScriptedBackend([AssistantTurn(content="x")])
    backend.complete([], [])
    with pytest.raises(RuntimeError):
        backend.complete([], [])


def test_real_backend_parses_tool_calls():
    data = {
        "choices": [{
            "message": {
                "content": None,
                "tool_calls": [{
                    "id": "call_1",
                    "function": {"name": "send_email", "arguments": '{"to": "a@b.com"}'},
                }],
            }
        }]
    }
    turn = RealBackend._parse(data)
    assert turn.content is None
    assert len(turn.tool_calls) == 1
    assert turn.tool_calls[0].name == "send_email"
    assert turn.tool_calls[0].arguments == {"to": "a@b.com"}


def test_real_backend_parses_plain_text():
    data = {"choices": [{"message": {"content": "hello", "tool_calls": None}}]}
    turn = RealBackend._parse(data)
    assert turn.content == "hello"
    assert turn.tool_calls == []


def test_real_backend_recovers_tool_call_from_content():
    # some models (qwen via Ollama) put the tool call as JSON in content
    data = {"choices": [{"message": {
        "content": '{"name": "send_email", "arguments": {"to": "a@b.com"}}',
        "tool_calls": None,
    }}]}
    turn = RealBackend._parse(data)
    assert turn.content is None
    assert len(turn.tool_calls) == 1
    assert turn.tool_calls[0].name == "send_email"
    assert turn.tool_calls[0].arguments == {"to": "a@b.com"}


def test_real_backend_plain_json_content_is_not_a_tool_call():
    # JSON without a "name" key stays as content, not a spurious tool call
    data = {"choices": [{"message": {"content": '{"result": 42}', "tool_calls": None}}]}
    turn = RealBackend._parse(data)
    assert turn.tool_calls == []
    assert turn.content == '{"result": 42}'
