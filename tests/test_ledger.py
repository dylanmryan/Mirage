from mirage.ledger import Ledger


def test_append_and_read_in_order():
    ledger = Ledger(":memory:")
    ledger.append("sess1", "request", {"n": 1})
    ledger.append("sess1", "gate_decision", {"tool": "send_email", "verdict": "deny"})
    events = ledger.read("sess1")
    assert [e["kind"] for e in events] == ["request", "gate_decision"]
    assert events[0]["payload"] == {"n": 1}
    assert events[1]["payload"]["verdict"] == "deny"


def test_read_isolates_by_session():
    ledger = Ledger(":memory:")
    ledger.append("a", "request", {"x": 1})
    ledger.append("b", "request", {"x": 2})
    assert ledger.read("a") == [{"kind": "request", "payload": {"x": 1}}]
    assert ledger.read("b") == [{"kind": "request", "payload": {"x": 2}}]
