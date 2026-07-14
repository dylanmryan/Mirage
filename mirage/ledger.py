from __future__ import annotations

import json
import sqlite3


class Ledger:
    """Append-only event log. The provenance ledger and substrate for SP3/SP4."""

    def __init__(self, db_path: str = ":memory:"):
        # check_same_thread=False: the app serves requests from a threadpool.
        # ponytail: fine for SP1 (autocommit per statement); add a lock if SP3+ writes concurrently.
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS events ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  session_id TEXT NOT NULL,"
            "  kind TEXT NOT NULL,"
            "  payload TEXT NOT NULL,"
            "  ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
            ")"
        )
        self._conn.commit()

    def append(self, session_id: str, kind: str, payload: dict) -> None:
        self._conn.execute(
            "INSERT INTO events (session_id, kind, payload) VALUES (?, ?, ?)",
            (session_id, kind, json.dumps(payload)),
        )
        self._conn.commit()

    def read(self, session_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT kind, payload FROM events WHERE session_id = ? ORDER BY id",
            (session_id,),
        ).fetchall()
        return [{"kind": k, "payload": json.loads(p)} for k, p in rows]

    def session_ids(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT session_id FROM events GROUP BY session_id ORDER BY MIN(id)"
        ).fetchall()
        return [r[0] for r in rows]

    def events_by_kind(self, kind: str) -> list[tuple[str, dict]]:
        rows = self._conn.execute(
            "SELECT session_id, payload FROM events WHERE kind = ? ORDER BY id",
            (kind,),
        ).fetchall()
        return [(sid, json.loads(p)) for sid, p in rows]
