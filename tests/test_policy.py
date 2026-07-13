from mirage.types import Privilege, TaintState, Verdict
from mirage.policy import Gate


def test_read_only_always_allowed():
    for taint in (TaintState(False), TaintState(True, "user[0]")):
        d = Gate().evaluate("search", Privilege.READ_ONLY, taint)
        assert d.verdict == Verdict.ALLOW
        assert d.tool == "search"


def test_privileged_untainted_allowed():
    d = Gate().evaluate("send_email", Privilege.PRIVILEGED, TaintState(False))
    assert d.verdict == Verdict.ALLOW
    assert d.taint_source is None


def test_privileged_tainted_denied_with_source():
    taint = TaintState(True, "tool[3]")
    d = Gate().evaluate("send_email", Privilege.PRIVILEGED, taint)
    assert d.verdict == Verdict.DENY
    assert d.tool == "send_email"
    assert d.taint_source == "tool[3]"
    assert "privileged" in d.reason.lower()
