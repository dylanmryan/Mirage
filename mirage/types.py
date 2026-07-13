from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Provenance(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class Privilege(str, Enum):
    READ_ONLY = "read_only"
    PRIVILEGED = "privileged"


class Verdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class Message:
    role: str
    content: str
    provenance: Optional[Provenance] = None  # explicit marker; None triggers inference


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict


@dataclass
class AssistantTurn:
    content: Optional[str] = None
    tool_calls: list[ToolCall] = field(default_factory=list)


@dataclass
class ToolResult:
    tool: str
    content: str


@dataclass
class TaintState:
    tainted: bool = False
    source: Optional[str] = None


@dataclass
class GateDecision:
    verdict: Verdict
    tool: str
    reason: str
    taint_source: Optional[str] = None
