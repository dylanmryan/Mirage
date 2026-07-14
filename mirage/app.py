from __future__ import annotations

import uuid
from typing import Literal, Optional

from fastapi import FastAPI
from pydantic import BaseModel

from mirage.orchestrator import AgentOrchestrator
from mirage.types import Message, Provenance


class ChatMessage(BaseModel):
    role: str
    content: str
    provenance: Optional[Literal["trusted", "untrusted"]] = None


class ChatRequest(BaseModel):
    model: str = "mirage-demo"
    messages: list[ChatMessage]


def create_app(orchestrator: AgentOrchestrator, db_path: Optional[str] = None) -> FastAPI:
    app = FastAPI(title="Mirage", version="0.1.0")

    @app.get("/healthz")
    def health() -> dict:
        return {"status": "ok"}

    @app.post("/v1/chat/completions")
    def chat(req: ChatRequest) -> dict:
        messages = [
            Message(
                role=m.role,
                content=m.content,
                provenance=Provenance(m.provenance) if m.provenance else None,
            )
            for m in req.messages
        ]
        session_id = str(uuid.uuid4())
        return orchestrator.run(session_id, messages)

    if db_path:
        from pathlib import Path
        from fastapi.staticfiles import StaticFiles
        from mirage.dashboard import build_dashboard_router
        app.include_router(build_dashboard_router(db_path))
        app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

    return app
