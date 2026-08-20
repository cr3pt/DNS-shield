"""Query log storage, backed by a local SQLite database.

Every resolved query is written to a `queries` table in an SQLite file on
the local /data volume. Nothing here ever leaves the host: there is no
upstream analytics or telemetry endpoint, this is purely local storage so
the web UI can show stats/history that survive a container restart.

Writes come from many DNS-handler threads at once (dnslib's server runs
each request in its own thread), so record() only ever pushes onto a
thread-safe queue.Queue - the actual INSERTs happen serially on a single
background writer thread, batched for throughput. Reads (snapshot) use
their own short-lived connection, which SQLite's WAL mode allows to run
concurrently with the writer without blocking either side.
"""

from __future__ import annotations

import queue
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    domain TEXT NOT NULL,
    qtype TEXT NOT NULL,
    client TEXT NOT NULL,
    blocked INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_queries_ts ON queries(ts);
CREATE INDEX IF NOT EXISTS idx_queries_domain ON queries(domain);
CREATE INDEX IF NOT EXISTS idx_queries_blocked ON queries(blocked);
"""


class Stats:
    def __init__(self, db_path: Path, retention_days: float = 30.0, flush_interval: float = 1.0):
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._retention_days = retention_days
        self._flush_interval = flush_interval
        self._queue: "queue.Queue[tuple[float, str, str, str, int]]" = queue.Queue()
        self._started_at = time.time()
        self._stop_event = threading.Event()

        self._init_schema()

        self._writer_thread = threading.Thread(target=self._writer_loop, name="stats-writer", daemon=True)
        self._writer_thread.start()

        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, name="stats-cleanup", daemon=True)
        self._cleanup_thread.start()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()

    # -- writing ------------------------------------------------------
    def record(self, qname: str, blocked: bool, client_ip: str, qtype: str) -> None:
        """Non-blocking: just hands the row to the writer thread."""
        self._queue.put((time.time(), qname, qtype, client_ip, int(blocked)))

    def _writer_loop(self) -> None:
        conn = self._connect()
        try:
            while not self._stop_event.is_set():
                try:
                    batch = [self._queue.get(timeout=self._flush_interval)]
                except queue.Empty:
                    continue
                while True:
                    try:
                        batch.append(self._queue.get_nowait())
                    except queue.Empty:
                        break
                conn.executemany(
                    "INSERT INTO queries (ts, domain, qtype, client, blocked) VALUES (?, ?, ?, ?, ?)",
                    batch,
                )
                conn.commit()
        finally:
            conn.close()

    def stop(self) -> None:
        self._stop_event.set()

    # -- retention ------------------------------------------------------
    def _cleanup_loop(self) -> None:
        while not self._stop_event.wait(3600):
            self._prune()

    def _prune(self) -> None:
        cutoff = time.time() - self._retention_days * 86400
        conn = self._connect()
        try:
            conn.execute("DELETE FROM queries WHERE ts < ?", (cutoff,))
            conn.commit()
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            conn.close()

    # -- reading ----------------------------------------------------------
    def snapshot(self, top_n: int = 25, log_n: int = 200) -> dict[str, Any]:
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            total = conn.execute("SELECT COUNT(*) AS c FROM queries").fetchone()["c"]
            blocked = conn.execute("SELECT COUNT(*) AS c FROM queries WHERE blocked = 1").fetchone()["c"]
            top_domains = conn.execute(
                "SELECT domain, COUNT(*) AS c FROM queries GROUP BY domain ORDER BY c DESC LIMIT ?",
                (top_n,),
            ).fetchall()
            top_blocked_domains = conn.execute(
                "SELECT domain, COUNT(*) AS c FROM queries WHERE blocked = 1 "
                "GROUP BY domain ORDER BY c DESC LIMIT ?",
                (top_n,),
            ).fetchall()
            top_clients = conn.execute(
                "SELECT client, COUNT(*) AS c FROM queries GROUP BY client ORDER BY c DESC LIMIT ?",
                (top_n,),
            ).fetchall()
            recent = conn.execute(
                "SELECT ts, domain, qtype, client, blocked FROM queries ORDER BY id DESC LIMIT ?",
                (log_n,),
            ).fetchall()
        finally:
            conn.close()

        return {
            "started_at": self._started_at,
            "total_queries": total,
            "blocked_queries": blocked,
            "top_domains": [[row["domain"], row["c"]] for row in top_domains],
            "top_blocked_domains": [[row["domain"], row["c"]] for row in top_blocked_domains],
            "top_clients": [[row["client"], row["c"]] for row in top_clients],
            "recent_queries": [
                {
                    "ts": row["ts"],
                    "domain": row["domain"],
                    "qtype": row["qtype"],
                    "client": row["client"],
                    "blocked": bool(row["blocked"]),
                }
                for row in recent
            ],
        }
