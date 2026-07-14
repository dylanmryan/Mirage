from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from mirage.types import Privilege, ToolResult

Executor = Callable[[dict], str]

_EMPTY_PARAMS = {"type": "object", "properties": {}}


@dataclass
class ToolSpec:
    name: str
    privilege: Privilege
    executor: Executor
    description: str = ""
    parameters: dict = field(default_factory=lambda: dict(_EMPTY_PARAMS))


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, name: str, privilege: Privilege, executor: Executor,
                 description: str = "", parameters: Optional[dict] = None) -> None:
        self._tools[name] = ToolSpec(
            name=name, privilege=privilege, executor=executor,
            description=description or f"The {name} tool.",
            parameters=parameters or dict(_EMPTY_PARAMS),
        )

    def get(self, name: str) -> Optional[ToolSpec]:
        return self._tools.get(name)

    def execute(self, name: str, args: dict) -> ToolResult:
        spec = self._tools[name]  # raises KeyError if unregistered
        return ToolResult(tool=name, content=spec.executor(args))

    def schemas(self) -> list[dict]:
        """OpenAI-format tool definitions so a real model knows the tools exist
        and can emit tool calls. Scripted backends ignore these."""
        return [
            {"type": "function", "function": {
                "name": s.name, "description": s.description, "parameters": s.parameters,
            }}
            for s in self._tools.values()
        ]
