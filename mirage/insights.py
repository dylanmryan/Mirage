# mirage/insights.py
from __future__ import annotations

from dataclasses import dataclass

from mirage.ledger import Ledger
from mirage.phases import Phase
from mirage.trajectory import TrajectoryRecorder


@dataclass
class SessionSummary:
    session_id: str
    mode: str
    action_gated: bool
    forked: bool
    kill_chain: list[Phase]
    tokens_issued: list[str]


@dataclass
class Campaign:
    id: int
    sessions: list[str]
    token_ids: list[str]
    hit_count: int


def list_sessions(ledger: Ledger) -> list[SessionSummary]:
    recorder = TrajectoryRecorder(ledger)
    out: list[SessionSummary] = []
    for sid in ledger.session_ids():
        traj = recorder.reconstruct(sid)
        response = next((e["payload"] for e in ledger.read(sid) if e["kind"] == "response"), {})
        mirage = response.get("mirage", {})
        out.append(SessionSummary(
            session_id=sid,
            mode=mirage.get("mode", "?"),
            action_gated=mirage.get("action_gated", False),
            forked=mirage.get("forked", False),
            kill_chain=traj.kill_chain,
            tokens_issued=traj.tokens_issued,
        ))
    return out


def _union_find(hits: list[dict]) -> dict:
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        parent[find(a)] = find(b)

    for h in hits:
        union(h["issued_session"], h["current_session"])
    return parent


def campaigns(ledger: Ledger) -> list[Campaign]:
    hits = [p for _sid, p in ledger.events_by_kind("honeytoken_hit")]
    if not hits:
        return []
    parent = _union_find(hits)

    groups: dict[str, set[str]] = {}
    for node in parent:
        root = node
        while parent[root] != root:
            root = parent[root]
        groups.setdefault(root, set()).add(node)

    out: list[Campaign] = []
    cid = 0
    for root, sessions in groups.items():
        if len(sessions) < 2:
            continue
        member_hits = [h for h in hits
                       if h["issued_session"] in sessions or h["current_session"] in sessions]
        token_ids = sorted({h["token_id"] for h in member_hits})
        out.append(Campaign(id=cid, sessions=sorted(sessions),
                            token_ids=token_ids, hit_count=len(member_hits)))
        cid += 1
    return out


def graph(ledger: Ledger) -> dict:
    hits = [p for _sid, p in ledger.events_by_kind("honeytoken_hit")]
    edges = [{"from": h["issued_session"], "to": h["current_session"], "token_id": h["token_id"]}
             for h in hits]
    nodes = sorted({h["issued_session"] for h in hits} | {h["current_session"] for h in hits})
    return {"nodes": nodes, "edges": edges}
