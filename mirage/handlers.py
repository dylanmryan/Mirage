from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from mirage.registry import ToolRegistry
from mirage.types import GateDecision, ToolCall, ToolResult

if TYPE_CHECKING:  # avoid runtime circular import (shadow imports handlers)
    from mirage.shadow import ShadowSession


@dataclass
class HandlerContext:
    registry: ToolRegistry
    tool_call: ToolCall
    session_id: str = ""
    shadow_session: Optional["ShadowSession"] = None


@dataclass
class HandlerEffect:
    executed: bool
    gated: bool
    tool_result: Optional[ToolResult] = None
    gated_action: Optional[dict] = None
    forked: bool = False


class OutcomeHandler:
    """Seam: DenyHandler (SP1), ForkHandler (SP2) implement this."""

    def handle(self, decision: GateDecision, ctx: HandlerContext) -> HandlerEffect:
        raise NotImplementedError


class AllowHandler(OutcomeHandler):
    def handle(self, decision: GateDecision, ctx: HandlerContext) -> HandlerEffect:
        result = ctx.registry.execute(ctx.tool_call.name, ctx.tool_call.arguments)
        return HandlerEffect(executed=True, gated=False, tool_result=result)


class DenyHandler(OutcomeHandler):
    def handle(self, decision: GateDecision, ctx: HandlerContext) -> HandlerEffect:
        gated_action = {
            "tool": decision.tool,
            "reason": decision.reason,
            "taint_source": decision.taint_source,
        }
        return HandlerEffect(executed=False, gated=True, gated_action=gated_action)
