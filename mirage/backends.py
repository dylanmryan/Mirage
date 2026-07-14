from __future__ import annotations

import json
from typing import Protocol

from mirage.types import AssistantTurn, Message, ToolCall


def _tool_calls_from_content(content: str) -> list[ToolCall]:
    """Recover tool calls a model emitted as JSON in the content field.
    Accepts a single {"name","arguments"} object or a list of them."""
    try:
        obj = json.loads(content.strip())
    except (ValueError, AttributeError):
        return []
    items = obj if isinstance(obj, list) else [obj]
    calls: list[ToolCall] = []
    for it in items:
        if isinstance(it, dict) and "name" in it:
            args = it.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except ValueError:
                    args = {}
            calls.append(ToolCall(id="", name=it["name"], arguments=args or {}))
    return calls


class LLMBackend(Protocol):
    def complete(self, messages: list[Message], tools: list[dict]) -> AssistantTurn: ...


class ScriptedBackend:
    """Deterministic backend for tests and the demo. Returns canned turns in order."""

    def __init__(self, turns: list[AssistantTurn]):
        self._turns = list(turns)
        self._i = 0

    def complete(self, messages: list[Message], tools: list[dict]) -> AssistantTurn:
        if self._i >= len(self._turns):
            raise RuntimeError("ScriptedBackend exhausted")
        turn = self._turns[self._i]
        self._i += 1
        return turn


class RealBackend:
    """Calls an OpenAI-compatible /chat/completions endpoint. `client` is injectable
    (an httpx.Client-like object) so parsing can be tested without the network."""

    def __init__(self, base_url: str, api_key: str, model: str, client=None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self._client = client

    def complete(self, messages: list[Message], tools: list[dict]) -> AssistantTurn:
        import httpx

        client = self._client or httpx.Client(timeout=30)
        payload = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "tools": tools,
        }
        resp = client.post(
            f"{self.base_url}/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {self.api_key}"},
        )
        return self._parse(resp.json())

    @staticmethod
    def _parse(data: dict) -> AssistantTurn:
        msg = data["choices"][0]["message"]
        calls: list[ToolCall] = []
        for tc in msg.get("tool_calls") or []:
            fn = tc["function"]
            args = fn.get("arguments") or "{}"
            parsed = json.loads(args) if isinstance(args, str) else args
            calls.append(ToolCall(id=tc.get("id", ""), name=fn["name"], arguments=parsed))
        content = msg.get("content")
        # Fallback: some models (e.g. qwen via Ollama) emit the tool call as a JSON
        # object in `content` instead of the structured tool_calls array.
        if not calls and content:
            calls = _tool_calls_from_content(content)
            if calls:
                content = None
        return AssistantTurn(content=content, tool_calls=calls)
