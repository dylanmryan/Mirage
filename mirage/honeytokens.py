from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class Honeytoken:
    token_id: str
    template: str
    value: str
    session_id: str
    tool: str


# Each template embeds the raw token_id verbatim so HoneytokenStore.scan can match it.
_TEMPLATES: dict[str, Callable[[str], str]] = {
    "aws_key": lambda tid: f"AKIA{tid}",
    "bearer_token": lambda tid: f"sk-{tid}",
    "pii_email": lambda tid: f"{tid}@examplecorp.com",
}


class HoneytokenMinter:
    def __init__(self, id_gen: Optional[Callable[[], str]] = None):
        self._id_gen = id_gen or (lambda: uuid.uuid4().hex)

    def mint(self, template: str, session_id: str, tool: str) -> Honeytoken:
        tid = self._id_gen()
        value = _TEMPLATES[template](tid)  # KeyError on unknown template -> caller fails closed
        return Honeytoken(token_id=tid, template=template, value=value,
                          session_id=session_id, tool=tool)


class HoneytokenStore:
    """Persists honeytokens and scans text for known ones. Own sqlite connection
    (shares the ledger DB file in production; :memory: per instance in tests)."""

    def __init__(self, db_path: str = ":memory:"):
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS honeytokens ("
            "  token_id TEXT PRIMARY KEY,"
            "  template TEXT NOT NULL,"
            "  value TEXT NOT NULL,"
            "  session_id TEXT NOT NULL,"
            "  tool TEXT NOT NULL,"
            "  ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
            ")"
        )
        self._conn.commit()

    def record(self, token: Honeytoken) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO honeytokens (token_id, template, value, session_id, tool) "
            "VALUES (?, ?, ?, ?, ?)",
            (token.token_id, token.template, token.value, token.session_id, token.tool),
        )
        self._conn.commit()

    def find(self, token_id: str) -> Optional[Honeytoken]:
        row = self._conn.execute(
            "SELECT token_id, template, value, session_id, tool FROM honeytokens WHERE token_id = ?",
            (token_id,),
        ).fetchone()
        return Honeytoken(*row) if row else None

    def scan(self, text: str) -> list[Honeytoken]:
        # ponytail: O(n) table walk — fine at SP2 scale; SP4 indexes if it grows.
        hits: list[Honeytoken] = []
        for row in self._conn.execute(
            "SELECT token_id, template, value, session_id, tool FROM honeytokens"
        ).fetchall():
            if row[0] in text:
                hits.append(Honeytoken(*row))
        return hits
