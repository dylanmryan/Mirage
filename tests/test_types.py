from mirage.types import (
    Provenance, Privilege, Verdict,
    Message, ToolCall, AssistantTurn, ToolResult, TaintState, GateDecision,
)


def test_enums_have_expected_values():
    assert Provenance.TRUSTED.value == "trusted"
    assert Provenance.UNTRUSTED.value == "untrusted"
    assert Privilege.READ_ONLY.value == "read_only"
    assert Privilege.PRIVILEGED.value == "privileged"
    assert Verdict.ALLOW.value == "allow"
    assert Verdict.DENY.value == "deny"


def test_dataclass_defaults():
    m = Message(role="user", content="hi")
    assert m.provenance is None
    turn = AssistantTurn()
    assert turn.content is None
    assert turn.tool_calls == []
    taint = TaintState()
    assert taint.tainted is False and taint.source is None
    d = GateDecision(verdict=Verdict.ALLOW, tool="x", reason="r")
    assert d.taint_source is None
    tc = ToolCall(id="1", name="send", arguments={"to": "a"})
    assert tc.arguments["to"] == "a"
    assert ToolResult(tool="send", content="ok").content == "ok"
