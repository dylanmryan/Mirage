# tests/test_phases.py
from mirage.phases import Phase, MITRE, phase_for_tool, phase_for_event


def test_tool_phase_map():
    assert phase_for_tool("search") == Phase.RECON
    assert phase_for_tool("read_secrets") == Phase.COLLECTION
    assert phase_for_tool("send_email") == Phase.EXFILTRATION
    assert phase_for_tool("http_post") == Phase.EXFILTRATION
    assert phase_for_tool("unknown_tool") == Phase.INJECTION


def test_every_phase_has_mitre_annotation():
    for p in Phase:
        assert p in MITRE and MITRE[p]


def test_phase_for_event():
    assert phase_for_event({"kind": "fork", "payload": {}}) == Phase.TRAPPED
    assert phase_for_event({"kind": "gate_decision", "payload": {"verdict": "deny"}}) == Phase.BLOCKED
    assert phase_for_event({"kind": "gate_decision", "payload": {"verdict": "allow"}}) is None
    assert phase_for_event({"kind": "tool_execution", "payload": {}}) is None
