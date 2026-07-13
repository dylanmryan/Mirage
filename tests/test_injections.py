import pytest

from mirage.types import AssistantTurn, Message, Privilege, Provenance, ToolCall
from mirage.registry import ToolRegistry
from mirage.backends import ScriptedBackend
from mirage.ledger import Ledger
from mirage.orchestrator import AgentOrchestrator
from tests.fixtures.injections import INJECTIONS


def _registry():
    reg = ToolRegistry()
    reg.register("send_email", Privilege.PRIVILEGED, lambda args: "email sent")
    return reg


@pytest.mark.parametrize("name,payload", INJECTIONS)
def test_injection_triggering_privileged_action_is_gated(name, payload):
    backend = ScriptedBackend([
        AssistantTurn(tool_calls=[ToolCall(id="1", name="send_email", arguments={})]),
        AssistantTurn(content="ok"),
    ])
    ledger = Ledger(":memory:")
    orch = AgentOrchestrator(backend=backend, registry=_registry(), ledger=ledger)
    resp = orch.run(name, [
        Message(role="user", content="Please read this document and help.",
                provenance=Provenance.TRUSTED),
        Message(role="tool", content=payload, provenance=Provenance.UNTRUSTED),
    ])

    assert resp["mirage"]["action_gated"] is True, f"{name} was not gated"
    assert resp["mirage"]["gated_actions"][0]["tool"] == "send_email"
    assert "tool_execution" not in [e["kind"] for e in ledger.read(name)]
