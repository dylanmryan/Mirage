import pytest

from mirage.types import Privilege
from mirage.registry import ToolRegistry


def test_register_and_get():
    reg = ToolRegistry()
    reg.register("search", Privilege.READ_ONLY, lambda args: "results")
    spec = reg.get("search")
    assert spec.name == "search"
    assert spec.privilege == Privilege.READ_ONLY


def test_get_unknown_returns_none():
    assert ToolRegistry().get("nope") is None


def test_execute_calls_executor_and_wraps_result():
    reg = ToolRegistry()
    reg.register("send_email", Privilege.PRIVILEGED, lambda args: f"sent to {args['to']}")
    result = reg.execute("send_email", {"to": "a@b.com"})
    assert result.tool == "send_email"
    assert result.content == "sent to a@b.com"


def test_execute_unregistered_raises_keyerror():
    with pytest.raises(KeyError):
        ToolRegistry().execute("ghost", {})
