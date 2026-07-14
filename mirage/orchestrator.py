from __future__ import annotations

from typing import Optional

from mirage.backends import LLMBackend
from mirage.handlers import AllowHandler, DenyHandler, HandlerContext, OutcomeHandler
from mirage.honeytokens import HoneytokenStore
from mirage.ledger import Ledger
from mirage.policy import Gate
from mirage.provenance import ProvenanceResolver
from mirage.registry import ToolRegistry
from mirage.shadow import ShadowSession
from mirage.types import GateDecision, Message, Privilege, Provenance, TaintState, Verdict


class AgentOrchestrator:
    def __init__(
        self,
        backend: LLMBackend,
        registry: ToolRegistry,
        ledger: Ledger,
        gate: Optional[Gate] = None,
        resolver: Optional[ProvenanceResolver] = None,
        max_iters: int = 8,
        denied_handler: Optional[OutcomeHandler] = None,
        store: Optional[HoneytokenStore] = None,
        mode: str = "deny",
    ):
        self.backend = backend
        self.registry = registry
        self.ledger = ledger
        self.gate = gate or Gate()
        self.resolver = resolver or ProvenanceResolver()
        self.allow = AllowHandler()
        self.denied_handler = denied_handler or DenyHandler()  # mode switch
        self.store = store
        self.mode = mode
        self.max_iters = max_iters

    def run(self, session_id: str, messages: list[Message],
            capabilities: Optional[list[str]] = None) -> dict:
        pmap = self.resolver.resolve(messages)
        taint = TaintState(tainted=pmap.tainted)
        if taint.tainted:
            idx = pmap.first_untrusted()
            taint.source = f"{messages[idx].role}[{idx}]"

        # Trusted-plane, single-use authorizations for specific privileged tools
        # this turn. Capabilities ride the trusted channel only (never model output
        # or untrusted content) — the operator's explicit acceptance of residual risk.
        caps: dict[str, int] = {}
        for tool in capabilities or []:
            caps[tool] = caps.get(tool, 0) + 1
        authorized_actions: list[str] = []

        self.ledger.append(session_id, "request",
                           {"messages": [{"role": m.role, "content": m.content} for m in messages]})
        self.ledger.append(session_id, "provenance",
                           {"entries": [e.value for e in pmap.entries]})

        honeytoken_hits = self._scan_reappearance(session_id, messages, pmap)

        context = list(messages)
        shadow_session = ShadowSession(session_id=session_id)
        gated_actions: list[dict] = []
        honeytokens_issued: list[str] = []
        forked = False
        final_content = ""
        hit_limit = True

        for _ in range(self.max_iters):
            turn = self.backend.complete(context, self.registry.schemas())
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
                    # A trusted-plane capability overrides a taint denial for this
                    # specific privileged tool, consuming one grant.
                    if (decision.verdict == Verdict.DENY
                            and spec.privilege == Privilege.PRIVILEGED
                            and caps.get(call.name, 0) > 0):
                        caps[call.name] -= 1
                        authorized_actions.append(call.name)
                        self.ledger.append(session_id, "capability_grant",
                                           {"tool": call.name, "remaining": caps[call.name]})
                        decision = GateDecision(Verdict.ALLOW, call.name,
                                                "authorized by trusted-plane capability")

                self.ledger.append(session_id, "gate_decision", {
                    "tool": decision.tool,
                    "verdict": decision.verdict.value,
                    "reason": decision.reason,
                    "taint_source": decision.taint_source,
                })

                if decision.verdict == Verdict.ALLOW:
                    ctx = HandlerContext(registry=self.registry, tool_call=call)
                    effect = self.allow.handle(decision, ctx)
                    self.ledger.append(session_id, "tool_execution",
                                       {"tool": call.name, "content": effect.tool_result.content})
                    context.append(Message(role="tool", content=effect.tool_result.content,
                                           provenance=Provenance.UNTRUSTED))
                    if not taint.tainted:
                        taint.tainted = True
                        taint.source = f"tool_result:{call.name}"
                else:
                    ctx = HandlerContext(registry=self.registry, tool_call=call,
                                         session_id=session_id, shadow_session=shadow_session)
                    before = len(shadow_session.issued)
                    effect = self.denied_handler.handle(decision, ctx)
                    gated_actions.append(effect.gated_action)
                    if effect.tool_result is not None:  # fork produced a fake success
                        forked = True
                        new_tokens = shadow_session.issued[before:]
                        token_ids = [t.token_id for t in new_tokens]
                        self.ledger.append(session_id, "fork", {
                            "tool": call.name,
                            "reason": decision.reason,
                            "taint_source": decision.taint_source,
                            "fake_result_summary": effect.tool_result.content[:120],
                            "token_ids": token_ids,
                        })
                        for t in new_tokens:
                            self.ledger.append(session_id, "honeytoken_issued", {
                                "token_id": t.token_id, "template": t.template,
                                "session_id": t.session_id, "tool": t.tool,
                            })
                        honeytokens_issued.extend(token_ids)
                        context.append(Message(role="tool", content=effect.tool_result.content,
                                               provenance=Provenance.UNTRUSTED))
                    else:  # honest deny (SP1 behavior)
                        context.append(Message(role="tool",
                                               content="Action gated by Mirage policy; not executed.",
                                               provenance=Provenance.TRUSTED))

        if hit_limit:
            final_content = final_content or "[mirage] max iterations reached."

        response = {
            "choices": [{"message": {"role": "assistant", "content": final_content}}],
            "mirage": {
                "mode": self.mode,
                "action_gated": bool(gated_actions),
                "forked": forked,
                "gated_actions": gated_actions,
                "authorized_actions": authorized_actions,
                "honeytokens_issued": honeytokens_issued,
                "honeytoken_hits": honeytoken_hits,
                "session_id": session_id,
            },
        }
        self.ledger.append(session_id, "response", response)
        return response

    def _scan_reappearance(self, session_id: str, messages: list[Message], pmap) -> list[str]:
        hits: list[str] = []
        if self.store is None:
            return hits
        for msg, prov in zip(messages, pmap.entries):
            if prov != Provenance.UNTRUSTED:
                continue
            for token in self.store.scan(msg.content):
                if token.session_id != session_id:  # a token from a prior/other session resurfaced
                    self.ledger.append(session_id, "honeytoken_hit", {
                        "token_id": token.token_id,
                        "issued_session": token.session_id,
                        "current_session": session_id,
                        "template": token.template,
                    })
                    hits.append(token.token_id)
        return hits
