# tests/test_ledger_reads.py
from mirage.ledger import Ledger


def test_session_ids_distinct_in_insertion_order():
    led = Ledger(":memory:")
    led.append("s1", "request", {})
    led.append("s2", "request", {})
    led.append("s1", "response", {})
    assert led.session_ids() == ["s1", "s2"]


def test_events_by_kind_across_sessions():
    led = Ledger(":memory:")
    led.append("a", "honeytoken_hit", {"token_id": "t1"})
    led.append("b", "gate_decision", {"tool": "x"})
    led.append("c", "honeytoken_hit", {"token_id": "t2"})
    hits = led.events_by_kind("honeytoken_hit")
    assert hits == [("a", {"token_id": "t1"}), ("c", {"token_id": "t2"})]
