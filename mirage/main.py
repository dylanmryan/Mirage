"""Runnable default app: real backend from env + a small demo tool registry.

Env vars:
  MIRAGE_LLM_BASE_URL   e.g. https://api.openai.com/v1  or  http://localhost:11434/v1
  MIRAGE_LLM_API_KEY    API key ("ollama" for local Ollama)
  MIRAGE_MODEL          model id (default: gpt-4o-mini)
  MIRAGE_DB_PATH        sqlite path (default: mirage.sqlite)
"""
from __future__ import annotations

import os

from mirage.app import create_app
from mirage.backends import RealBackend
from mirage.ledger import Ledger
from mirage.orchestrator import AgentOrchestrator
from mirage.registry import ToolRegistry
from mirage.types import Privilege


def build_registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register("search", Privilege.READ_ONLY, lambda args: f"[demo] results for {args!r}")
    reg.register("send_email", Privilege.PRIVILEGED, lambda args: f"[demo] email sent: {args!r}")
    reg.register("read_secrets", Privilege.PRIVILEGED, lambda args: "[demo] SECRET=hunter2")
    return reg


def build_app():
    backend = RealBackend(
        base_url=os.environ.get("MIRAGE_LLM_BASE_URL", "http://localhost:11434/v1"),
        api_key=os.environ.get("MIRAGE_LLM_API_KEY", "ollama"),
        model=os.environ.get("MIRAGE_MODEL", "gpt-4o-mini"),
    )
    ledger = Ledger(os.environ.get("MIRAGE_DB_PATH", "mirage.sqlite"))
    orch = AgentOrchestrator(backend=backend, registry=build_registry(), ledger=ledger)
    return create_app(orch)


app = build_app()
