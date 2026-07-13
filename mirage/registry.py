from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from mirage.types import Privilege, ToolResult

Executor = Callable[[dict], str]


@dataclass
class ToolSpec:
    name: str
    privilege: Privilege
    executor: Executor


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, name: str, privilege: Privilege, executor: Executor) -> None:
        self._tools[name] = ToolSpec(name=name, privilege=privilege, executor=executor)

    def get(self, name: str) -> Optional[ToolSpec]:
        return self._tools.get(name)

    def execute(self, name: str, args: dict) -> ToolResult:
        spec = self._tools[name]  # raises KeyError if unregistered
        return ToolResult(tool=name, content=spec.executor(args))
