from __future__ import annotations

import ipaddress
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS leases (
    mac TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    scope TEXT NOT NULL,
    hostname TEXT,
    client_id TEXT,
    expires_at REAL NOT NULL,
    static INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_leases_ip ON leases(ip);
CREATE INDEX IF NOT EXISTS idx_leases_scope ON leases(scope);

CREATE TABLE IF NOT EXISTS declined_ips (
    ip TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    declined_at REAL NOT NULL,
    cooldown_until REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS known_macs (
    mac TEXT PRIMARY KEY,
    first_seen REAL NOT NULL
);
"""


def find_free_ip(
    pool_start: str,
    pool_end: str,
    taken: set[str],
    excluded: set[str],
    preferred: str | None = None,
) -> str | None:
    start = int(ipaddress.IPv4Address(pool_start))
    end = int(ipaddress.IPv4Address(pool_end))
    unavailable = taken | excluded

    if preferred and preferred not in unavailable:
        preferred_int = int(ipaddress.IPv4Address(preferred))
        if start <= preferred_int <= end:
            return preferred

    for value in range(start, end + 1):
        candidate = str(ipaddress.IPv4Address(value))
        if candidate not in unavailable:
            return candidate
    return None


class LeaseStore:
    def __init__(self, db_path: Path):
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()

    def get_by_mac(self, mac: str) -> dict[str, Any] | None:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT * FROM leases WHERE mac = ?", (mac,)).fetchone()
            finally:
                conn.close()
        return dict(row) if row else None

    def get_by_ip(self, ip: str) -> dict[str, Any] | None:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT * FROM leases WHERE ip = ?", (ip,)).fetchone()
            finally:
                conn.close()
        return dict(row) if row else None

    def taken_ips(self, scope: str, exclude_mac: str | None = None, now: float | None = None) -> set[str]:
        now = time.time() if now is None else now
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT mac, ip FROM leases WHERE scope = ? AND expires_at > ?", (scope, now)
                ).fetchall()
            finally:
                conn.close()
        return {row["ip"] for row in rows if row["mac"] != exclude_mac}

    def declined_ips(self, scope: str, now: float | None = None) -> set[str]:
        now = time.time() if now is None else now
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT ip FROM declined_ips WHERE scope = ? AND cooldown_until > ?", (scope, now)
                ).fetchall()
            finally:
                conn.close()
        return {row["ip"] for row in rows}

    def commit_lease(
        self,
        mac: str,
        ip: str,
        scope: str,
        hostname: str | None,
        client_id: str | None,
        lease_seconds: float,
        static: bool = False,
        now: float | None = None,
    ) -> None:
        now = time.time() if now is None else now
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO leases (mac, ip, scope, hostname, client_id, expires_at, static) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(mac) DO UPDATE SET ip = excluded.ip, scope = excluded.scope, "
                    "hostname = excluded.hostname, client_id = excluded.client_id, "
                    "expires_at = excluded.expires_at, static = excluded.static",
                    (mac, ip, scope, hostname, client_id, now + lease_seconds, int(static)),
                )
                conn.commit()
            finally:
                conn.close()

    def release(self, mac: str) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM leases WHERE mac = ?", (mac,))
                conn.commit()
            finally:
                conn.close()

    def decline(self, ip: str, scope: str, cooldown_seconds: float = 3600, now: float | None = None) -> None:
        now = time.time() if now is None else now
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO declined_ips (ip, scope, declined_at, cooldown_until) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(ip) DO UPDATE SET declined_at = excluded.declined_at, "
                    "cooldown_until = excluded.cooldown_until",
                    (ip, scope, now, now + cooldown_seconds),
                )
                conn.commit()
            finally:
                conn.close()

    def all_active(self, now: float | None = None) -> list[dict[str, Any]]:
        now = time.time() if now is None else now
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM leases WHERE expires_at > ? ORDER BY expires_at DESC", (now,)
                ).fetchall()
            finally:
                conn.close()
        return [dict(row) for row in rows]

    def expire_sweep(self, now: float | None = None) -> int:
        now = time.time() if now is None else now
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute("DELETE FROM leases WHERE expires_at <= ? AND static = 0", (now,))
                conn.execute("DELETE FROM declined_ips WHERE cooldown_until <= ?", (now,))
                conn.commit()
                return cur.rowcount
            finally:
                conn.close()

    def mark_known(self, mac: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute("INSERT OR IGNORE INTO known_macs (mac, first_seen) VALUES (?, ?)", (mac, now))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def reset_known_macs(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM known_macs")
                conn.commit()
            finally:
                conn.close()
