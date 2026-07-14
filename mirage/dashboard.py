# mirage/dashboard.py
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from mirage.harness import build_orchestrator, scripted_for
from mirage.insights import campaigns, graph, list_sessions
from mirage.ledger import Ledger
from mirage.phases import MITRE
from mirage.techniques import CATALOG
from mirage.trajectory import TrajectoryRecorder
from mirage.types import Message, Provenance

_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@dataclass
class DemoView:
    technique_id: str
    payload: str
    attacker_fakes: list
    final_response: str
    trajectory: object
    tokens: list


def run_demo(technique_id: str = "data_exfil") -> DemoView:
    technique = next((t for t in CATALOG if t.id == technique_id), CATALOG[0])
    ledger = Ledger(":memory:")
    orch = build_orchestrator("mirage", ledger, scripted_for(technique))
    messages = [
        Message(role="user", content="Please read this document and assist.",
                provenance=Provenance.TRUSTED),
        Message(role=technique.delivery, content=technique.payload, provenance=Provenance.UNTRUSTED),
    ]
    response = orch.run(technique.id, messages)
    trajectory = TrajectoryRecorder(ledger).reconstruct(technique.id)
    events = ledger.read(technique.id)
    attacker_fakes = [e["payload"]["fake_result_summary"] for e in events if e["kind"] == "fork"]
    final = response["choices"][0]["message"]["content"]
    return DemoView(technique_id=technique.id, payload=technique.payload,
                    attacker_fakes=attacker_fakes, final_response=final,
                    trajectory=trajectory, tokens=trajectory.tokens_issued)


def _graph_context(g: dict) -> dict:
    pos = {n: 60 + i * 160 for i, n in enumerate(g["nodes"])}
    nodes = [{"id": n, "x": x} for n, x in pos.items()]
    edges = [{"x1": pos[e["from"]], "x2": pos[e["to"]]} for e in g["edges"]]
    return {"nodes": nodes, "edges": edges}


def build_dashboard_router(db_path: str) -> APIRouter:
    router = APIRouter()

    def _ledger() -> Ledger:
        return Ledger(db_path)

    @router.get("/dashboard", response_class=HTMLResponse)
    def dashboard(request: Request):
        led = _ledger()
        sessions = list_sessions(led)
        camps = campaigns(led)
        return _TEMPLATES.TemplateResponse(request, "dashboard.html", {
            "request": request,
            "sessions": sessions,
            "gated_count": sum(1 for s in sessions if s.action_gated),
            "forked_count": sum(1 for s in sessions if s.forked),
            "campaign_count": len(camps),
        })

    @router.get("/dashboard/feed", response_class=HTMLResponse)
    def feed(request: Request):
        return _TEMPLATES.TemplateResponse(request, "feed.html", {
            "request": request, "sessions": list_sessions(_ledger()),
        })

    @router.get("/dashboard/sessions/{session_id}", response_class=HTMLResponse)
    def session(request: Request, session_id: str):
        led = _ledger()
        if session_id not in led.session_ids():
            return _TEMPLATES.TemplateResponse(
                request, "not_found.html", {"request": request, "message": f"no session {session_id}"},
                status_code=404)
        summary = next(s for s in list_sessions(led) if s.session_id == session_id)
        trajectory = TrajectoryRecorder(led).reconstruct(session_id)
        request_event = next((e["payload"] for e in led.read(session_id) if e["kind"] == "request"), {})
        provenance = next((e["payload"] for e in led.read(session_id) if e["kind"] == "provenance"), {})
        entries = provenance.get("entries", [])
        msgs = request_event.get("messages", [])
        untrusted = [m["content"] for m, prov in zip(msgs, entries) if prov == "untrusted"]
        return _TEMPLATES.TemplateResponse(request, "session.html", {
            "request": request, "summary": summary, "trajectory": trajectory,
            "mitre": MITRE, "untrusted_messages": untrusted,
        })

    @router.get("/dashboard/campaigns", response_class=HTMLResponse)
    def campaigns_view(request: Request):
        led = _ledger()
        ctx = _graph_context(graph(led))
        return _TEMPLATES.TemplateResponse(request, "campaigns.html", {
            "request": request, "campaigns": campaigns(led),
            "nodes": ctx["nodes"], "edges": ctx["edges"],
        })

    @router.get("/demo", response_class=HTMLResponse)
    def demo(request: Request, technique: str = "data_exfil"):
        view = run_demo(technique)
        return _TEMPLATES.TemplateResponse(request, "demo.html", {
            "request": request,
            "technique_id": view.technique_id, "payload": view.payload,
            "attacker_fakes": view.attacker_fakes, "final_response": view.final_response,
            "trajectory": view.trajectory, "tokens": view.tokens,
        })

    return router
