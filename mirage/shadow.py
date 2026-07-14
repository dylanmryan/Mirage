from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from mirage.handlers import DenyHandler, HandlerContext, HandlerEffect, OutcomeHandler
from mirage.honeytokens import HoneytokenMinter, HoneytokenStore
from mirage.types import GateDecision, ToolResult


@dataclass
class ShadowSession:
    session_id: str
    cache: dict = field(default_factory=dict)          # tool name -> fake content
    issued: list = field(default_factory=list)         # list[Honeytoken]


@dataclass
class ShadowContext:
    minter: HoneytokenMinter
    store: HoneytokenStore
    session: ShadowSession
    tool: str

    def mint(self, template: str) -> str:
        token = self.minter.mint(template, self.session.session_id, self.tool)
        self.store.record(token)
        self.session.issued.append(token)
        return token.value


ShadowExecutor = Callable[[dict, ShadowContext], str]


def _generic_success(args: dict, ctx: ShadowContext) -> str:
    return f"{ctx.tool}: ok"


class ShadowRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ShadowExecutor] = {}

    def register(self, name: str, executor: ShadowExecutor) -> None:
        self._tools[name] = executor

    def get(self, name: str) -> ShadowExecutor:
        return self._tools.get(name, _generic_success)  # never None


class ForkHandler(OutcomeHandler):
    def __init__(self, shadow_registry: ShadowRegistry,
                 minter: HoneytokenMinter, store: HoneytokenStore):
        self.shadow_registry = shadow_registry
        self.minter = minter
        self.store = store

    def handle(self, decision: GateDecision, ctx: HandlerContext) -> HandlerEffect:
        session = ctx.shadow_session
        tool = ctx.tool_call.name
        gated_action = {
            "tool": decision.tool,
            "reason": decision.reason,
            "taint_source": decision.taint_source,
        }
        try:
            if session is not None and tool in session.cache:
                content = session.cache[tool]
            else:
                executor = self.shadow_registry.get(tool)
                shadow_ctx = ShadowContext(self.minter, self.store, session, tool)
                content = executor(ctx.tool_call.arguments, shadow_ctx)
                if session is not None:
                    session.cache[tool] = content
            return HandlerEffect(
                executed=False, gated=True, forked=True,
                tool_result=ToolResult(tool=tool, content=content),
                gated_action=gated_action,
            )
        except Exception:
            # fail-closed: revert to honest deny (no real execution, no crash, no leak)
            return DenyHandler().handle(decision, ctx)
