from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS enrichments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    overall_verdict TEXT NOT NULL,
    overall_score INTEGER,
    sources_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_enrichments_ts ON enrichments(ts);
CREATE INDEX IF NOT EXISTS idx_enrichments_target ON enrichments(target);
"""


class EnrichmentStore:
    def __init__(self, db_path: Path):
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(SCHEMA)
            try:
                conn.execute("ALTER TABLE enrichments ADD COLUMN source TEXT NOT NULL DEFAULT 'manual'")
            except sqlite3.OperationalError:
                pass
            conn.commit()
        finally:
            conn.close()

    def record(
        self,
        target: str,
        target_type: str,
        overall_verdict: str,
        overall_score: int | None,
        sources: dict[str, Any],
        source: str = "manual",
    ) -> int:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "INSERT INTO enrichments (ts, target, target_type, overall_verdict, overall_score, sources_json, source) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (time.time(), target, target_type, overall_verdict, overall_score, json.dumps(sources), source),
                )
                conn.commit()
                return cur.lastrowid
            finally:
                conn.close()

    def known_targets(self, target_type: str | None = None) -> set[str]:
        """All targets ever recorded - used to seed the auto-enrich "already
        checked" set at startup so a restart doesn't re-enrich everything."""
        conn = self._connect()
        try:
            if target_type is not None:
                rows = conn.execute(
                    "SELECT DISTINCT target FROM enrichments WHERE target_type = ?", (target_type,)
                ).fetchall()
            else:
                rows = conn.execute("SELECT DISTINCT target FROM enrichments").fetchall()
        finally:
            conn.close()
        return {row[0] for row in rows}

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "ts": row["ts"],
            "target": row["target"],
            "type": row["target_type"],
            "overall_verdict": row["overall_verdict"],
            "overall_score": row["overall_score"],
            "sources": json.loads(row["sources_json"]),
            "source": row["source"] if "source" in row.keys() else "manual",
        }

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, ts, target, target_type, overall_verdict, overall_score, sources_json, source "
                "FROM enrichments ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        finally:
            conn.close()
        return [self._row_to_dict(row) for row in rows]

    def history_for(self, target: str, limit: int = 20) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, ts, target, target_type, overall_verdict, overall_score, sources_json, source "
                "FROM enrichments WHERE target = ? ORDER BY id DESC LIMIT ?",
                (target, limit),
            ).fetchall()
        finally:
            conn.close()
        return [self._row_to_dict(row) for row in rows]
