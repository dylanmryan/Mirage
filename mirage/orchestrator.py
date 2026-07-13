from __future__ import annotations

from typing import Optional

from mirage.backends import LLMBackend
from mirage.handlers import AllowHandler, DenyHandler, HandlerContext
from mirage.ledger import Ledger
from mirage.policy import Gate
from mirage.provenance import ProvenanceResolver
from mirage.registry import ToolRegistry
from mirage.types import GateDecision, Message, Provenance, TaintState, Verdict


class AgentOrchestrator:
    def __init__(
        self,
        backend: LLMBackend,
        registry: ToolRegistry,
        ledger: Ledger,
        gate: Optional[Gate] = None,
        resolver: Optional[ProvenanceResolver] = None,
        max_iters: int = 8,
    ):
        self.backend = backend
        self.registry = registry
        self.ledger = ledger
        self.gate = gate or Gate()
        self.resolver = resolver or ProvenanceResolver()
        self.allow = AllowHandler()
        self.deny = DenyHandler()
        self.max_iters = max_iters

    def run(self, session_id: str, messages: list[Message]) -> dict:
        pmap = self.resolver.resolve(messages)
        taint = TaintState(tainted=pmap.tainted)
        if taint.tainted:
            idx = pmap.first_untrusted()
            taint.source = f"{messages[idx].role}[{idx}]"

        self.ledger.append(session_id, "request",
                           {"messages": [{"role": m.role, "content": m.content} for m in messages]})
        self.ledger.append(session_id, "provenance",
                           {"entries": [e.value for e in pmap.entries]})

        context = list(messages)
        gated_actions: list[dict] = []
        final_content = ""
        hit_limit = True

        for _ in range(self.max_iters):
            turn = self.backend.complete(context, [])
            if turn.content is not None:
                final_content = turn.content
            if not turn.tool_calls:
                hit_limit = False
                break

            context.append(Message(role="assistant", content=turn.content or "",
                                   provenance=Provenance.TRUSTED))
            for call in turn.tool_calls:
                spec = self.registry.get(call.name)
                if spec is None:
                    decision = GateDecision(Verdict.DENY, call.name,
                                            "unregistered tool; denied", taint.source)
                else:
                    decision = self.gate.evaluate(call.name, spec.privilege, taint)

                self.ledger.append(session_id, "gate_decision", {
                    "tool": decision.tool,
                    "verdict": decision.verdict.value,
                    "reason": decision.reason,
                    "taint_source": decision.taint_source,
                })

                ctx = HandlerContext(registry=self.registry, tool_call=call)
                if decision.verdict == Verdict.ALLOW:
                    effect = self.allow.handle(decision, ctx)
                    self.ledger.append(session_id, "tool_execution",
                                       {"tool": call.name, "content": effect.tool_result.content})
                    context.append(Message(role="tool", content=effect.tool_result.content,
                                           provenance=Provenance.UNTRUSTED))
                    if not taint.tainted:
                        taint.tainted = True
                        taint.source = f"tool_result:{call.name}"
                else:
                    effect = self.deny.handle(decision, ctx)
                    gated_actions.append(effect.gated_action)
                    context.append(Message(role="tool",
                                           content="Action gated by Mirage policy; not executed.",
                                           provenance=Provenance.TRUSTED))

        if hit_limit:
            final_content = final_content or "[mirage] max iterations reached."

        response = {
            "choices": [{"message": {"role": "assistant", "content": final_content}}],
            "mirage": {
                "action_gated": bool(gated_actions),
                "gated_actions": gated_actions,
                "session_id": session_id,
            },
        }
        self.ledger.append(session_id, "response", response)
        return response
