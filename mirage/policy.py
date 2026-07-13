from __future__ import annotations

from mirage.types import GateDecision, Privilege, TaintState, Verdict


class Gate:
    """Pure decision function. Rule A (SP1): PRIVILEGED under taint is denied.

    Does not attempt to attribute causation from model output (impossible per the
    inseparability theorem) — enforces a static conservative policy instead.
    """

    def evaluate(self, tool: str, privilege: Privilege, taint: TaintState) -> GateDecision:
        if privilege == Privilege.READ_ONLY:
            return GateDecision(Verdict.ALLOW, tool, "read-only tool; not gated")
        if not taint.tainted:
            return GateDecision(Verdict.ALLOW, tool, "privileged tool; context untainted")
        return GateDecision(
            Verdict.DENY,
            tool,
            "privileged tool invoked under untrusted taint",
            taint.source,
        )
