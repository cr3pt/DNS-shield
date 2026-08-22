from __future__ import annotations

import queue
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from app.netmatch import ip_matches
from app.upstream import protected_hostnames

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
        self._queue: "queue.Queue[tuple[float, str, str, str, int, str | None, str | None, str | None]]" = queue.Queue()
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
            columns = {row[1] for row in conn.execute("PRAGMA table_info(queries)")}
            if "reason" not in columns:
                conn.execute("ALTER TABLE queries ADD COLUMN reason TEXT")
            if "answer_ip" not in columns:
                conn.execute("ALTER TABLE queries ADD COLUMN answer_ip TEXT")
            if "alert_rule" not in columns:
                conn.execute("ALTER TABLE queries ADD COLUMN alert_rule TEXT")
            conn.commit()
        finally:
            conn.close()

    def record(
        self,
        qname: str,
        blocked: bool,
        client_ip: str,
        qtype: str,
        reason: str | None = None,
        answer_ip: str | None = None,
        alert_rule: str | None = None,
    ) -> None:
        if self._is_ignored(qname, client_ip):
            return
        self._queue.put((time.time(), qname, qtype, client_ip, int(blocked), reason, answer_ip, alert_rule))

    def _is_ignored(self, qname: str, client_ip: str) -> bool:
        ignored_domains = self._config.get("logging", "ignored_domains", default=[]) or []
        if any(qname == d or qname.endswith("." + d) for d in ignored_domains):
            return True
        ignored_clients = self._config.get("logging", "ignored_clients", default=[]) or []
        if any(ip_matches(client_ip, pattern) for pattern in ignored_clients):
            return True
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
                    "INSERT INTO queries (ts, domain, qtype, client, blocked, reason, answer_ip, alert_rule) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    batch,
                )
                conn.commit()
        finally:
            conn.close()

    def stop(self) -> None:
        self._stop_event.set()

    def clear(self) -> None:
        conn = self._connect()
        try:
            conn.execute("DELETE FROM queries")
            conn.commit()
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            conn.close()

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

    def distinct_clients(self) -> list[str]:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT DISTINCT client FROM queries").fetchall()
        finally:
            conn.close()
        return [row[0] for row in rows]

    def snapshot(self, top_n: int = 25, log_n: int = 200, client_ips: list[str] | None = None) -> dict[str, Any]:
        where_clients = ""
        base_params: list[Any] = []
        if client_ips is not None:
            if not client_ips:
                where_clients = "WHERE 0"
            else:
                where_clients = "WHERE client IN (%s)" % ",".join("?" for _ in client_ips)
                base_params = list(client_ips)

        def _and_clients(extra: str = "") -> str:
            if not where_clients:
                return f"WHERE {extra}" if extra else ""
            return f"{where_clients} AND {extra}" if extra else where_clients

        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            total = conn.execute(f"SELECT COUNT(*) AS c FROM queries {where_clients}", base_params).fetchone()["c"]
            blocked = conn.execute(
                f"SELECT COUNT(*) AS c FROM queries {_and_clients('blocked = 1')}", base_params
            ).fetchone()["c"]
            top_domains = conn.execute(
                f"SELECT domain, COUNT(*) AS c FROM queries {where_clients} GROUP BY domain ORDER BY c DESC LIMIT ?",
                base_params + [top_n],
            ).fetchall()
            top_blocked_domains = conn.execute(
                f"SELECT domain, COUNT(*) AS c FROM queries {_and_clients('blocked = 1')} "
                "GROUP BY domain ORDER BY c DESC LIMIT ?",
                base_params + [top_n],
            ).fetchall()
            top_clients = conn.execute(
                f"SELECT client, COUNT(*) AS c FROM queries {where_clients} GROUP BY client ORDER BY c DESC LIMIT ?",
                base_params + [top_n],
            ).fetchall()
            qtype_counts = conn.execute(
                f"SELECT qtype, COUNT(*) AS c FROM queries {where_clients} GROUP BY qtype ORDER BY c DESC",
                base_params,
            ).fetchall()
            block_reasons = conn.execute(
                f"SELECT reason, COUNT(*) AS c FROM queries {_and_clients('blocked = 1 AND reason IS NOT NULL')} "
                "GROUP BY reason ORDER BY c DESC LIMIT ?",
                base_params + [top_n],
            ).fetchall()
            recent = conn.execute(
                f"SELECT ts, domain, qtype, client, blocked, reason, answer_ip, alert_rule FROM queries {where_clients} "
                "ORDER BY id DESC LIMIT ?",
                base_params + [log_n],
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
                    "answer_ip": row["answer_ip"],
                    "alert_rule": row["alert_rule"],
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
        restrict_client_ips: list[str] | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        where: list[str] = []
        params: list[Any] = []

        if restrict_client_ips is not None:
            if not restrict_client_ips:
                where.append("0")
            else:
                where.append("client IN (%s)" % ",".join("?" for _ in restrict_client_ips))
                params.extend(restrict_client_ips)
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
                f"SELECT ts, domain, qtype, client, blocked, reason, answer_ip, alert_rule FROM queries {where_sql} "
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
                    "answer_ip": row["answer_ip"],
                    "alert_rule": row["alert_rule"],
                }
                for row in rows
            ],
            total,
        )

    def client_activity(self, window_seconds: float, until_ts: float | None = None) -> list[dict[str, Any]]:
        until_ts = time.time() if until_ts is None else until_ts
        since = until_ts - window_seconds
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT client, COUNT(*) AS total, SUM(blocked) AS blocked, "
                "COUNT(DISTINCT domain) AS distinct_domains, "
                "COUNT(DISTINCT CASE WHEN blocked = 1 THEN domain END) AS distinct_blocked_domains "
                "FROM queries WHERE ts >= ? AND ts < ? GROUP BY client",
                (since, until_ts),
            ).fetchall()
        finally:
            conn.close()
        return [
            {
                "client": row["client"],
                "total": row["total"],
                "blocked": row["blocked"] or 0,
                "distinct_domains": row["distinct_domains"],
                "distinct_blocked_domains": row["distinct_blocked_domains"],
            }
            for row in rows
        ]

    def client_domains(self, window_seconds: float, until_ts: float | None = None) -> dict[str, list[str]]:
        until_ts = time.time() if until_ts is None else until_ts
        since = until_ts - window_seconds
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT DISTINCT client, domain FROM queries WHERE ts >= ? AND ts < ?", (since, until_ts)
            ).fetchall()
        finally:
            conn.close()
        by_client: dict[str, list[str]] = {}
        for row in rows:
            by_client.setdefault(row["client"], []).append(row["domain"])
        return by_client

    def max_query_id(self) -> int:
        conn = self._connect()
        try:
            row = conn.execute("SELECT MAX(id) FROM queries").fetchone()
            return row[0] or 0
        finally:
            conn.close()

    def alert_hits_since(self, last_id: int, limit: int = 500) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, ts, domain, client, alert_rule FROM queries "
                "WHERE id > ? AND alert_rule IS NOT NULL ORDER BY id ASC LIMIT ?",
                (last_id, limit),
            ).fetchall()
        finally:
            conn.close()
        return [
            {"id": row["id"], "ts": row["ts"], "domain": row["domain"], "client": row["client"], "alert_rule": row["alert_rule"]}
            for row in rows
        ]

    def domains_for_client_window(
        self, client: str, since_ts: float, until_ts: float, blocked_only: bool = False
    ) -> list[str]:
        where_blocked = "AND blocked = 1" if blocked_only else ""
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                f"SELECT DISTINCT domain FROM queries WHERE client = ? AND ts >= ? AND ts < ? {where_blocked} "
                "ORDER BY domain",
                (client, since_ts, until_ts),
            ).fetchall()
        finally:
            conn.close()
        return [row["domain"] for row in rows]

    def timeseries(self, range_key: str = "24h", client_ips: list[str] | None = None) -> list[dict[str, Any]]:
        window_seconds, bucket_seconds = _TIMESERIES_RANGES.get(range_key, _TIMESERIES_RANGES["24h"])
        since = time.time() - window_seconds

        where_clients = ""
        client_params: list[Any] = []
        if client_ips is not None:
            if not client_ips:
                where_clients = "AND 0"
            else:
                where_clients = "AND client IN (%s)" % ",".join("?" for _ in client_ips)
                client_params = list(client_ips)

        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT CAST((ts - ?) / ? AS INTEGER) AS bucket, COUNT(*) AS total, SUM(blocked) AS blocked "
                f"FROM queries WHERE ts >= ? {where_clients} GROUP BY bucket",
                [since, bucket_seconds, since] + client_params,
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
