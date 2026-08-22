"""Local, heuristic anomaly detection over the query log.

Runs periodically on its own background thread, reading recent per-client
activity from Stats (app/stats.py) and flagging simple statistical red
flags - no ML, no cloud call, nothing beyond arithmetic over data already
sitting in stats.db. Off by default (anomaly.enabled); when off the loop
still ticks but does nothing, same "always exists, no-ops when disabled"
pattern as DNSCache/ClientNameResolver/UpstreamStats.

Three heuristics, evaluated independently per client on every check:
  - high_blocked_ratio: a large fraction of a client's queries in the
    window are blocked - a compromised app/device hammering ad/tracker/
    malware domains typically looks like this.
  - domain_burst: a client resolves an unusually large number of
    *distinct* domains in the window - typical of DGA (domain generation
    algorithm) malware cycling through candidate C2 domains.
  - blocked_domain_burst: a client hits an unusually large number of
    distinct *blocked* domains in the window - a stronger signal than the
    ratio check alone, since it can't be explained by one noisy ad-heavy
    page reloading the same handful of ad domains.

A bug in this module can, at worst, stop producing new anomaly alerts -
it never touches DNS resolution. check_once() only reads from stats.db on
a timer and writes to its own anomalies.db; the background loop wraps it
in try/except so a heuristic bug can't take the process down.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("dnsshield.anomaly")

SCHEMA = """
CREATE TABLE IF NOT EXISTS anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    client TEXT NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    details_json TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_anomalies_ts ON anomalies(ts);
CREATE INDEX IF NOT EXISTS idx_anomalies_client_kind ON anomalies(client, kind);
CREATE INDEX IF NOT EXISTS idx_anomalies_ack ON anomalies(acknowledged);
"""

KIND_LABELS = {
    "high_blocked_ratio": "High blocked-query ratio",
    "domain_burst": "Unusually many distinct domains",
    "blocked_domain_burst": "Unusually many distinct blocked domains",
}


class AnomalyDetector:
    def __init__(self, config_store, stats, db_path: Path):
        self._config = config_store
        self._stats = stats
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

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

    # -- background thread -------------------------------------------------
    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="anomaly-detector", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            interval_minutes = self._config.get("anomaly", "check_interval_minutes", default=5) or 5
            interval = max(float(interval_minutes), 1.0) * 60
            if self._stop_event.wait(interval):
                return
            if not self._config.get("anomaly", "enabled", default=False):
                continue
            try:
                self.check_once()
            except Exception:  # noqa: BLE001 - a heuristic bug must never take the process down
                logger.exception("anomaly check failed")

    # -- detection ------------------------------------------------------
    def check_once(self) -> list[dict[str, Any]]:
        """Runs one detection pass over the current window and stores any
        newly-flagged anomalies (subject to a per-client/kind cooldown so a
        persistent condition doesn't spam a fresh row every cycle). Returns
        what was newly recorded. Safe to call directly (e.g. a dashboard
        "Check now" button), not just from the background loop.
        """
        window_minutes = float(self._config.get("anomaly", "window_minutes", default=15) or 15)
        min_queries = int(self._config.get("anomaly", "min_queries", default=20) or 20)
        blocked_ratio_threshold = float(self._config.get("anomaly", "blocked_ratio_threshold", default=0.5) or 0.5)
        domain_burst_threshold = int(self._config.get("anomaly", "domain_burst_threshold", default=50) or 50)
        blocked_domain_burst_threshold = int(
            self._config.get("anomaly", "blocked_domain_burst_threshold", default=15) or 15
        )
        cooldown_minutes = float(self._config.get("anomaly", "cooldown_minutes", default=60) or 60)
        cooldown_seconds = max(cooldown_minutes, 1.0) * 60

        activity = self._stats.client_activity(window_minutes * 60)
        now = time.time()
        found: list[dict[str, Any]] = []

        with self._lock:
            conn = self._connect()
            try:
                conn.row_factory = sqlite3.Row
                # Last time each (client, kind) pair fired, read from the DB
                # rather than kept in memory - so the cooldown survives a
                # process restart instead of re-firing immediately after one.
                last_fired = {
                    (row["client"], row["kind"]): row["last_ts"]
                    for row in conn.execute(
                        "SELECT client, kind, MAX(ts) AS last_ts FROM anomalies GROUP BY client, kind"
                    ).fetchall()
                }

                for row in activity:
                    client = row["client"]
                    total = row["total"]
                    blocked = row["blocked"]
                    distinct_domains = row["distinct_domains"]
                    distinct_blocked_domains = row["distinct_blocked_domains"]

                    candidates: list[tuple[str, str, str]] = []  # (kind, severity, summary)

                    if total >= min_queries and blocked / total >= blocked_ratio_threshold:
                        pct = round(100 * blocked / total)
                        severity = "high" if blocked / total >= 0.8 else "medium"
                        candidates.append((
                            "high_blocked_ratio", severity,
                            f"{pct}% of {total} queries blocked in the last {window_minutes:g} min",
                        ))

                    if distinct_domains >= domain_burst_threshold:
                        severity = "high" if distinct_domains >= domain_burst_threshold * 2 else "medium"
                        candidates.append((
                            "domain_burst", severity,
                            f"{distinct_domains} distinct domains queried in the last {window_minutes:g} min",
                        ))

                    if distinct_blocked_domains >= blocked_domain_burst_threshold:
                        severity = "high" if distinct_blocked_domains >= blocked_domain_burst_threshold * 2 else "medium"
                        candidates.append((
                            "blocked_domain_burst", severity,
                            f"{distinct_blocked_domains} distinct blocked domains hit in the last {window_minutes:g} min",
                        ))

                    for kind, severity, summary in candidates:
                        last = last_fired.get((client, kind))
                        if last is not None and now - last < cooldown_seconds:
                            continue
                        details = {
                            "total_queries": total,
                            "blocked_queries": blocked,
                            "distinct_domains": distinct_domains,
                            "distinct_blocked_domains": distinct_blocked_domains,
                            "window_minutes": window_minutes,
                        }
                        conn.execute(
                            "INSERT INTO anomalies (ts, client, kind, severity, summary, details_json, acknowledged) "
                            "VALUES (?, ?, ?, ?, ?, ?, 0)",
                            (now, client, kind, severity, summary, json.dumps(details)),
                        )
                        last_fired[(client, kind)] = now
                        found.append({
                            "ts": now, "client": client, "kind": kind,
                            "severity": severity, "summary": summary,
                        })

                conn.commit()
            finally:
                conn.close()

        if found:
            logger.info("anomaly check: %d new anomal%s flagged", len(found), "y" if len(found) == 1 else "ies")
        return found

    # -- reading/managing -------------------------------------------------
    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "ts": row["ts"],
            "client": row["client"],
            "kind": row["kind"],
            "kind_label": KIND_LABELS.get(row["kind"], row["kind"]),
            "severity": row["severity"],
            "summary": row["summary"],
            "details": json.loads(row["details_json"]),
            "acknowledged": bool(row["acknowledged"]),
        }

    def list(self, include_acknowledged: bool = True, limit: int = 200) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            where = "" if include_acknowledged else "WHERE acknowledged = 0"
            rows = conn.execute(
                f"SELECT * FROM anomalies {where} ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        finally:
            conn.close()
        return [self._row_to_dict(row) for row in rows]

    def unacknowledged_count(self) -> int:
        conn = self._connect()
        try:
            return conn.execute("SELECT COUNT(*) FROM anomalies WHERE acknowledged = 0").fetchone()[0]
        finally:
            conn.close()

    def acknowledge(self, anomaly_id: int) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute("UPDATE anomalies SET acknowledged = 1 WHERE id = ?", (anomaly_id,))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def delete(self, anomaly_id: int) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute("DELETE FROM anomalies WHERE id = ?", (anomaly_id,))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def clear(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM anomalies")
                conn.commit()
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                conn.close()
