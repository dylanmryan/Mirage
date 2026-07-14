from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from mirage.ledger import Ledger
from mirage.phases import Phase, phase_for_event, phase_for_tool

# Phases that represent the attacker actually taking privileged data/action.
_STOLEN = {Phase.COLLECTION, Phase.EXFILTRATION}


@dataclass
class TrajectoryStep:
    iteration: int
    tool: Optional[str]
    verdict: Optional[str]
    forked: bool
    executed: bool
    honeytokens: list[str]
    phase: Phase


@dataclass
class Trajectory:
    session_id: str
    steps: list[TrajectoryStep]
    kill_chain: list[Phase]
    contained: bool
    trapped: bool
    tokens_issued: list[str]


class TrajectoryRecorder:
    """Reconstructs an attack timeline from ledger events. Catalog-independent:
    phases are derived from tool names + event kinds, so it works on real sessions."""

    def __init__(self, ledger: Ledger):
        self.ledger = ledger

    def reconstruct(self, session_id: str) -> Trajectory:
        events = self.ledger.read(session_id)
        steps: list[TrajectoryStep] = []
        tokens_issued: list[str] = []
        injected = False
        terminals: set[Phase] = set()
        iteration = 0

        for ev in events:
            kind, payload = ev["kind"], ev["payload"]
            if kind == "provenance":
                injected = "untrusted" in payload.get("entries", [])
            elif kind == "gate_decision":
                iteration += 1
                steps.append(TrajectoryStep(
                    iteration=iteration,
                    tool=payload["tool"],
                    verdict=payload["verdict"],
                    forked=False,
                    executed=False,
                    honeytokens=[],
                    phase=phase_for_tool(payload["tool"]),
                ))
            elif kind == "tool_execution" and steps:
                steps[-1].executed = True
            elif kind == "fork" and steps:
                steps[-1].forked = True
            elif kind == "honeytoken_issued":
                tid = payload["token_id"]
                tokens_issued.append(tid)
                if steps:
                    steps[-1].honeytokens.append(tid)

            t = phase_for_event(ev)
            if t is not None:
                terminals.add(t)

        kill_chain: list[Phase] = []
        if injected:
            kill_chain.append(Phase.INJECTION)
        for s in steps:
            if s.phase not in kill_chain:
                kill_chain.append(s.phase)
        terminal = Phase.TRAPPED if Phase.TRAPPED in terminals else (
            Phase.BLOCKED if Phase.BLOCKED in terminals else None)
        if terminal is not None:
            kill_chain.append(terminal)

        contained = not any(s.phase in _STOLEN and s.executed for s in steps)
        trapped = any(s.forked for s in steps)
        return Trajectory(session_id, steps, kill_chain, contained, trapped, tokens_issued)
