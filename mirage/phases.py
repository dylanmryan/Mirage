# mirage/phases.py
from __future__ import annotations

from enum import Enum
from typing import Optional


class Phase(str, Enum):
    RECON = "recon"
    INJECTION = "injection"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    TRAPPED = "trapped"
    BLOCKED = "blocked"


# Bespoke injection phases annotated with the nearest MITRE ATT&CK tactic.
MITRE = {
    Phase.RECON: "Reconnaissance",
    Phase.INJECTION: "Initial Access",
    Phase.COLLECTION: "Collection",
    Phase.EXFILTRATION: "Exfiltration",
    Phase.TRAPPED: "Deception (defensive)",
    Phase.BLOCKED: "Mitigation (defensive)",
}

_TOOL_PHASE = {
    "search": Phase.RECON,
    "read_secrets": Phase.COLLECTION,
    "send_email": Phase.EXFILTRATION,
    "http_post": Phase.EXFILTRATION,
}


def phase_for_tool(name: str) -> Phase:
    return _TOOL_PHASE.get(name, Phase.INJECTION)


def phase_for_event(event: dict) -> Optional[Phase]:
    kind = event.get("kind")
    if kind == "fork":
        return Phase.TRAPPED
    if kind == "gate_decision" and event.get("payload", {}).get("verdict") == "deny":
        return Phase.BLOCKED
    return None
