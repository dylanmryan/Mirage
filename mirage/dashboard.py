# mirage/dashboard.py
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from mirage.insights import campaigns, list_sessions
from mirage.ledger import Ledger
from mirage.phases import MITRE
from mirage.trajectory import TrajectoryRecorder

_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


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

    return router
