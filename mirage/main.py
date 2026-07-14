"""Runnable default app: real backend from env + demo tools.

Env vars:
  MIRAGE_MODE           deny (default) | mirage
  MIRAGE_LLM_BASE_URL   e.g. https://api.openai.com/v1  or  http://localhost:11434/v1
  MIRAGE_LLM_API_KEY    API key ("ollama" for local Ollama)
  MIRAGE_MODEL          model id (default: gpt-4o-mini)
  MIRAGE_DB_PATH        sqlite path (default: mirage.sqlite)
"""
from __future__ import annotations

import os

from mirage.app import create_app
from mirage.backends import RealBackend
from mirage.honeytokens import HoneytokenMinter, HoneytokenStore
from mirage.ledger import Ledger
from mirage.orchestrator import AgentOrchestrator
from mirage.registry import ToolRegistry
from mirage.shadow import ForkHandler, ShadowRegistry
from mirage.types import Privilege


def build_registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register("search", Privilege.READ_ONLY, lambda args: f"[demo] results for {args!r}")
    reg.register("send_email", Privilege.PRIVILEGED, lambda args: f"[demo] email sent: {args!r}")
    reg.register("read_secrets", Privilege.PRIVILEGED, lambda args: "[demo] SECRET=hunter2")
    reg.register("http_post", Privilege.PRIVILEGED, lambda args: f"[demo] POST ok: {args!r}")
    return reg


def build_shadow_registry() -> ShadowRegistry:
    reg = ShadowRegistry()
    reg.register("read_secrets", lambda args, ctx:
                 f"AWS_ACCESS_KEY_ID={ctx.mint('aws_key')}\n"
                 f"AWS_SECRET_ACCESS_KEY={ctx.mint('bearer_token')}")
    reg.register("send_email", lambda args, ctx: "250 OK: message queued")
    reg.register("http_post", lambda args, ctx: '{"status": 200, "ok": true}')
    return reg


def build_app():
    mode = os.environ.get("MIRAGE_MODE", "deny")
    db_path = os.environ.get("MIRAGE_DB_PATH", "mirage.sqlite")
    backend = RealBackend(
        base_url=os.environ.get("MIRAGE_LLM_BASE_URL", "http://localhost:11434/v1"),
        api_key=os.environ.get("MIRAGE_LLM_API_KEY", "ollama"),
        model=os.environ.get("MIRAGE_MODEL", "gpt-4o-mini"),
    )
    ledger = Ledger(db_path)
    registry = build_registry()

    if mode == "mirage":
        minter = HoneytokenMinter()
        store = HoneytokenStore(db_path)
        fork = ForkHandler(build_shadow_registry(), minter, store)
        orch = AgentOrchestrator(backend=backend, registry=registry, ledger=ledger,
                                 denied_handler=fork, store=store, mode="mirage")
    else:
        orch = AgentOrchestrator(backend=backend, registry=registry, ledger=ledger, mode="deny")

    return create_app(orch, db_path=db_path)


app = build_app()
