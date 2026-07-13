from __future__ import annotations

from typing import Optional

from mirage.types import Message, Provenance

# Convenience heuristic for plain chat only. External data (web pages, tool
# results, RAG docs, emails) MUST be marked untrusted by the app via a marker;
# the heuristic never upgrades an unmarked or unexpected-shape message to trusted.
_HEURISTIC = {
    "system": Provenance.TRUSTED,
    "user": Provenance.TRUSTED,
    "assistant": Provenance.TRUSTED,
    "tool": Provenance.UNTRUSTED,
}


class ProvenanceMap:
    def __init__(self, entries: list[Provenance]):
        self.entries = entries

    @property
    def tainted(self) -> bool:
        return any(e == Provenance.UNTRUSTED for e in self.entries)

    def first_untrusted(self) -> Optional[int]:
        for i, e in enumerate(self.entries):
            if e == Provenance.UNTRUSTED:
                return i
        return None


class ProvenanceResolver:
    def resolve(self, messages: list[Message]) -> ProvenanceMap:
        entries: list[Provenance] = []
        for m in messages:
            if m.provenance is not None:
                entries.append(m.provenance)
            else:
                entries.append(_HEURISTIC.get(m.role, Provenance.UNTRUSTED))
        return ProvenanceMap(entries)
