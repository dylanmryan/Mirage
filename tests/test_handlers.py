from mirage.types import GateDecision, Privilege, ToolCall, Verdict
from mirage.registry import ToolRegistry
from mirage.handlers import AllowHandler, DenyHandler, HandlerContext


def _registry():
    reg = ToolRegistry()
    reg.register("send_email", Privilege.PRIVILEGED, lambda args: "sent")
    return reg


def test_allow_handler_executes_tool():
    reg = _registry()
    call = ToolCall(id="1", name="send_email", arguments={})
    decision = GateDecision(Verdict.ALLOW, "send_email", "ok")
    effect = AllowHandler().handle(decision, HandlerContext(registry=reg, tool_call=call))
    assert effect.executed is True
    assert effect.gated is False
    assert effect.tool_result.content == "sent"
    assert effect.gated_action is None


def test_deny_handler_does_not_execute_and_records():
    reg = _registry()
    call = ToolCall(id="1", name="send_email", arguments={})
    decision = GateDecision(Verdict.DENY, "send_email", "blocked", "tool[2]")
    effect = DenyHandler().handle(decision, HandlerContext(registry=reg, tool_call=call))
    assert effect.executed is False
    assert effect.gated is True
    assert effect.tool_result is None
    assert effect.gated_action == {
        "tool": "send_email", "reason": "blocked", "taint_source": "tool[2]",
    }
