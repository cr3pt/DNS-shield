# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    client_ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_log(username);
"""


class AuditLog:
    def __init__(self, db_path: Path, config_store=None):
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._config = config_store
        self._stop_event = threading.Event()
        self._init_schema()

        if config_store is not None:
            self._cleanup_thread = threading.Thread(target=self._cleanup_loop, name="audit-cleanup", daemon=True)
            self._cleanup_thread.start()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()

    def record(self, username: str, action: str, client_ip: str = "") -> None:
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO audit_log (ts, username, action, client_ip) VALUES (?, ?, ?, ?)",
                (time.time(), username, action, client_ip),
            )
            conn.commit()
        finally:
            conn.close()

    def list(self, limit: int = 200, before_id: int | None = None) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            if before_id is not None:
                rows = conn.execute(
                    "SELECT * FROM audit_log WHERE id < ? ORDER BY id DESC LIMIT ?", (before_id, limit)
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        finally:
            conn.close()
        return [dict(row) for row in rows]

    def _cleanup_loop(self) -> None:
        while not self._stop_event.wait(3600):
            self._prune()

    def _prune(self) -> None:
        retention_days = float(self._config.get("logging", "retention_days", default=30))
        cutoff = time.time() - retention_days * 86400
        conn = self._connect()
        try:
            conn.execute("DELETE FROM audit_log WHERE ts < ?", (cutoff,))
            conn.commit()
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            conn.close()

    def stop(self) -> None:
        self._stop_event.set()
