from mirage.types import AssistantTurn, Message, Privilege, Provenance, ToolCall
from mirage.registry import ToolRegistry
from mirage.backends import ScriptedBackend
from mirage.ledger import Ledger
from mirage.orchestrator import AgentOrchestrator


def _registry():
    reg = ToolRegistry()
    reg.register("send_email", Privilege.PRIVILEGED, lambda a: "email sent")
    reg.register("read_secrets", Privilege.PRIVILEGED, lambda a: "SECRET=hunter2")
    return reg


def _tainted():
    return [
        Message(role="user", content="do it", provenance=Provenance.TRUSTED),
        Message(role="tool", content="untrusted doc", provenance=Provenance.UNTRUSTED),
    ]


def _kinds(ledger, sid):
    return [e["kind"] for e in ledger.read(sid)]


def test_capability_authorizes_privileged_action_under_taint():
    backend = ScriptedBackend([
        AssistantTurn(tool_calls=[ToolCall(id="1", name="send_email", arguments={})]),
        AssistantTurn(content="done"),
    ])
    ledger = Ledger(":memory:")
    orch = AgentOrchestrator(backend=backend, registry=_registry(), ledger=ledger)
    resp = orch.run("s1", _tainted(), capabilities=["send_email"])

    assert resp["mirage"]["action_gated"] is False
    assert resp["mirage"]["authorized_actions"] == ["send_email"]
    assert "tool_execution" in _kinds(ledger, "s1")       # the real tool ran
    assert "capability_grant" in _kinds(ledger, "s1")


def test_capability_is_single_use():
    backend = ScriptedBackend([
        AssistantTurn(tool_calls=[ToolCall(id="1", name="send_email", arguments={})]),
        AssistantTurn(tool_calls=[ToolCall(id="2", name="send_email", arguments={})]),
        AssistantTurn(content="done"),
    ])
    ledger = Ledger(":memory:")
    orch = AgentOrchestrator(backend=backend, registry=_registry(), ledger=ledger)
    resp = orch.run("s2", _tainted(), capabilities=["send_email"])  # only one grant

    assert resp["mirage"]["authorized_actions"] == ["send_email"]   # first authorized
    assert resp["mirage"]["action_gated"] is True                   # second gated
    assert len(resp["mirage"]["gated_actions"]) == 1


def test_capability_for_other_tool_does_not_authorize():
    backend = ScriptedBackend([
        AssistantTurn(tool_calls=[ToolCall(id="1", name="send_email", arguments={})]),
        AssistantTurn(content="done"),
    ])
    ledger = Ledger(":memory:")
    orch = AgentOrchestrator(backend=backend, registry=_registry(), ledger=ledger)
    resp = orch.run("s3", _tainted(), capabilities=["read_secrets"])  # wrong tool

    assert resp["mirage"]["action_gated"] is True
    assert resp["mirage"]["authorized_actions"] == []


def test_no_capabilities_preserves_gate_behavior():
    backend = ScriptedBackend([
        AssistantTurn(tool_calls=[ToolCall(id="1", name="send_email", arguments={})]),
        AssistantTurn(content="done"),
    ])
    ledger = Ledger(":memory:")
    orch = AgentOrchestrator(backend=backend, registry=_registry(), ledger=ledger)
    resp = orch.run("s4", _tainted())  # no capabilities

    assert resp["mirage"]["action_gated"] is True
    assert resp["mirage"]["authorized_actions"] == []


def test_registry_schemas_shape():
    reg = ToolRegistry()
    reg.register("send_email", Privilege.PRIVILEGED, lambda a: "x",
                 description="Send an email.",
                 parameters={"type": "object", "properties": {"to": {"type": "string"}}})
    schemas = reg.schemas()
    assert schemas == [{
        "type": "function",
        "function": {
            "name": "send_email",
            "description": "Send an email.",
            "parameters": {"type": "object", "properties": {"to": {"type": "string"}}},
        },
    }]
