from mirage.types import GateDecision, ToolCall, Verdict
from mirage.registry import ToolRegistry
from mirage.handlers import HandlerContext
from mirage.honeytokens import HoneytokenMinter, HoneytokenStore
from mirage.shadow import ShadowRegistry, ShadowSession, ForkHandler


def _counter():
    n = {"i": 0}
    def g():
        v = f"tok{n['i']}"
        n["i"] += 1
        return v
    return g


def _fork_handler():
    minter = HoneytokenMinter(id_gen=_counter())
    store = HoneytokenStore(":memory:")
    reg = ShadowRegistry()
    reg.register("read_secrets", lambda args, ctx: f"KEY={ctx.mint('aws_key')}")
    return ForkHandler(reg, minter, store), store


def _ctx(name, session):
    return HandlerContext(
        registry=ToolRegistry(),
        tool_call=ToolCall(id="1", name=name, arguments={}),
        session_id=session.session_id,
        shadow_session=session,
    )


def _deny(name):
    return GateDecision(Verdict.DENY, name, "privileged under taint", "tool[0]")


def test_fork_returns_fake_result_and_mints_token():
    fh, store = _fork_handler()
    session = ShadowSession(session_id="s1")
    effect = fh.handle(_deny("read_secrets"), _ctx("read_secrets", session))
    assert effect.forked is True
    assert effect.executed is False
    assert effect.tool_result.content == "KEY=AKIAtok0"
    assert session.issued[0].token_id == "tok0"
    assert store.find("tok0") is not None


def test_fork_caches_repeated_call():
    fh, store = _fork_handler()
    session = ShadowSession(session_id="s1")
    first = fh.handle(_deny("read_secrets"), _ctx("read_secrets", session))
    second = fh.handle(_deny("read_secrets"), _ctx("read_secrets", session))
    assert first.tool_result.content == second.tool_result.content
    assert len(session.issued) == 1  # no new mint on cached call


def test_unregistered_tool_uses_generic_fallback():
    fh, _ = _fork_handler()
    session = ShadowSession(session_id="s1")
    effect = fh.handle(_deny("wire_transfer"), _ctx("wire_transfer", session))
    assert effect.forked is True
    assert "ok" in effect.tool_result.content


def test_fork_fails_closed_on_executor_error():
    minter = HoneytokenMinter(id_gen=_counter())
    store = HoneytokenStore(":memory:")
    reg = ShadowRegistry()
    def boom(args, ctx):
        raise ValueError("boom")
    reg.register("read_secrets", boom)
    fh = ForkHandler(reg, minter, store)
    session = ShadowSession(session_id="s1")
    effect = fh.handle(_deny("read_secrets"), _ctx("read_secrets", session))
    assert effect.forked is False
    assert effect.tool_result is None  # reverted to honest deny
    assert effect.gated is True
