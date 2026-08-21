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

from app.netmatch import ip_matches
from app.upstream import protected_hostnames

# range key -> (how far back to look, bucket width) in seconds. Bucket sizes
# are picked to keep the point count reasonable to plot (24-30 points) while
# still showing real granularity at each range.
_TIMESERIES_RANGES: dict[str, tuple[int, int]] = {
    "24h": (86400, 3600),
    "7d": (7 * 86400, 6 * 3600),
    "30d": (30 * 86400, 86400),
}

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
    def __init__(self, db_path: Path, config_store, flush_interval: float = 1.0):
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._config = config_store
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
            # "reason" was added after this table already existed in some
            # deployments - CREATE TABLE IF NOT EXISTS above is a no-op for
            # those, so add the column by hand if it's still missing.
            columns = {row[1] for row in conn.execute("PRAGMA table_info(queries)")}
            if "reason" not in columns:
                conn.execute("ALTER TABLE queries ADD COLUMN reason TEXT")
            conn.commit()
        finally:
            conn.close()

    # -- writing ------------------------------------------------------
    def record(self, qname: str, blocked: bool, client_ip: str, qtype: str, reason: str | None = None) -> None:
        """Non-blocking: just hands the row to the writer thread.

        A domain/client on logging.ignored_domains/ignored_clients is
        simply never written here - resolution and blocking already
        happened before this is called, so this only affects what shows
        up in the query log, not how the query itself was answered.
        """
        if self._is_ignored(qname, client_ip):
            return
        self._queue.put((time.time(), qname, qtype, client_ip, int(blocked), reason))

    def _is_ignored(self, qname: str, client_ip: str) -> bool:
        ignored_domains = self._config.get("logging", "ignored_domains", default=[]) or []
        if any(qname == d or qname.endswith("." + d) for d in ignored_domains):
            return True
        ignored_clients = self._config.get("logging", "ignored_clients", default=[]) or []
        if any(ip_matches(client_ip, pattern) for pattern in ignored_clients):
            return True
        # Hidden from the log by default, with no config needed: a query for
        # an upstream resolver's own hostname (e.g. resolving "dns.nextdns.io"
        # to reach a doh:// upstream) is DNS-shield's own traffic, not
        # something a user browsed to.
        protected = protected_hostnames(self._config)
        return any(qname == h or qname.endswith("." + h) for h in protected)

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
                    "INSERT INTO queries (ts, domain, qtype, client, blocked, reason) VALUES (?, ?, ?, ?, ?, ?)",
                    batch,
                )
                conn.commit()
        finally:
            conn.close()

    def stop(self) -> None:
        self._stop_event.set()

    # -- clearing -----------------------------------------------------------
    def clear(self) -> None:
        """Wipes every stored query log entry. Irreversible - the caller
        (the web UI) is expected to confirm with the user first.
        """
        conn = self._connect()
        try:
            conn.execute("DELETE FROM queries")
            conn.commit()
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            conn.close()

    # -- retention ------------------------------------------------------
    def _cleanup_loop(self) -> None:
        while not self._stop_event.wait(3600):
            self._prune()

    def _prune(self) -> None:
        retention_days = float(self._config.get("logging", "retention_days", default=30))
        cutoff = time.time() - retention_days * 86400
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
            qtype_counts = conn.execute(
                "SELECT qtype, COUNT(*) AS c FROM queries GROUP BY qtype ORDER BY c DESC"
            ).fetchall()
            block_reasons = conn.execute(
                "SELECT reason, COUNT(*) AS c FROM queries WHERE blocked = 1 AND reason IS NOT NULL "
                "GROUP BY reason ORDER BY c DESC LIMIT ?",
                (top_n,),
            ).fetchall()
            recent = conn.execute(
                "SELECT ts, domain, qtype, client, blocked, reason FROM queries ORDER BY id DESC LIMIT ?",
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
            "qtype_counts": [[row["qtype"], row["c"]] for row in qtype_counts],
            "block_reasons": [[row["reason"], row["c"]] for row in block_reasons],
            "recent_queries": [
                {
                    "ts": row["ts"],
                    "domain": row["domain"],
                    "qtype": row["qtype"],
                    "client": row["client"],
                    "blocked": bool(row["blocked"]),
                    "reason": row["reason"],
                }
                for row in recent
            ],
        }

    def query_log(
        self,
        domain: str | None = None,
        client_like: str | None = None,
        client_ips: list[str] | None = None,
        qtype: str | None = None,
        blocked: bool | None = None,
        since: float | None = None,
        until: float | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        """Search the full retained history (not just the in-memory tail).

        client_ips (exact IPs, e.g. resolved from a hostname search) and
        client_like (a substring against the stored IP) are OR'd together
        when both are given, so a client filter can match either an IP
        fragment or a resolved display name.
        """
        where: list[str] = []
        params: list[Any] = []

        if domain:
            where.append("domain LIKE ?")
            params.append(f"%{domain.lower()}%")
        if qtype:
            where.append("qtype = ?")
            params.append(qtype)
        if blocked is not None:
            where.append("blocked = ?")
            params.append(int(blocked))
        if since is not None:
            where.append("ts >= ?")
            params.append(since)
        if until is not None:
            where.append("ts <= ?")
            params.append(until)

        client_clauses = []
        if client_ips:
            client_clauses.append("client IN (%s)" % ",".join("?" for _ in client_ips))
            params_client = list(client_ips)
        else:
            params_client = []
        if client_like:
            client_clauses.append("client LIKE ?")
            params_client.append(f"%{client_like}%")
        if client_clauses:
            where.append("(" + " OR ".join(client_clauses) + ")")
            params.extend(params_client)

        where_sql = f"WHERE {' AND '.join(where)}" if where else ""

        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            total = conn.execute(f"SELECT COUNT(*) AS c FROM queries {where_sql}", params).fetchone()["c"]
            rows = conn.execute(
                f"SELECT ts, domain, qtype, client, blocked, reason FROM queries {where_sql} "
                "ORDER BY id DESC LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()
        finally:
            conn.close()

        return (
            [
                {
                    "ts": row["ts"],
                    "domain": row["domain"],
                    "qtype": row["qtype"],
                    "client": row["client"],
                    "blocked": bool(row["blocked"]),
                    "reason": row["reason"],
                }
                for row in rows
            ],
            total,
        )

    # -- time-series trend (Stats tab chart) -------------------------------
    def timeseries(self, range_key: str = "24h") -> list[dict[str, Any]]:
        """Total/blocked query counts bucketed over the given range, for the
        Stats tab's trend chart. Always returns one entry per bucket over
        the full range, zero-filled where there's no data, so the chart has
        a continuous, evenly-spaced x-axis regardless of gaps in traffic.
        """
        window_seconds, bucket_seconds = _TIMESERIES_RANGES.get(range_key, _TIMESERIES_RANGES["24h"])
        since = time.time() - window_seconds

        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT CAST((ts - ?) / ? AS INTEGER) AS bucket, COUNT(*) AS total, SUM(blocked) AS blocked "
                "FROM queries WHERE ts >= ? GROUP BY bucket",
                (since, bucket_seconds, since),
            ).fetchall()
        finally:
            conn.close()

        by_bucket = {row["bucket"]: (row["total"], row["blocked"] or 0) for row in rows}
        num_buckets = window_seconds // bucket_seconds
        return [
            {
                "bucket_start": since + i * bucket_seconds,
                "total": by_bucket.get(i, (0, 0))[0],
                "blocked": by_bucket.get(i, (0, 0))[1],
            }
            for i in range(num_buckets)
        ]
