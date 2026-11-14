# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import copy
import json
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

import yaml

APP_DIR = Path(__file__).resolve().parent
REPO_DIR = APP_DIR.parent
EXAMPLE_CONFIG = REPO_DIR / "config" / "config.example.yaml"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    data TEXT NOT NULL,
    updated_at REAL NOT NULL
);
"""


def _default_db_path() -> Path:
    return Path(os.environ.get("DNSSHIELD_CONFIG_DB", "/data/config.db"))


def _default_backup_path() -> Path:
    return Path(os.environ.get("DNSSHIELD_CONFIG_BACKUP", "/data/config.backup.yaml"))


def _default_legacy_yaml_path() -> Path:
    return Path(os.environ.get("DNSSHIELD_CONFIG", "/data/config.yaml"))



def _id_lists(data: dict[str, Any]) -> list[list[Any]]:
    """Every config list whose dict entries the API addresses one by one."""

    def _list(node: Any, *keys: str) -> list[Any]:
        for key in keys:
            node = node.get(key) if isinstance(node, dict) else None
        return node if isinstance(node, list) else []

    lists = [
        _list(data, "blocklists", "sources"),
        _list(data, "blocklists", "allow_sources"),
        _list(data, "blocked_answer_ip_sources"),
        _list(data, "client_groups"),
        _list(data, "dhcp", "scopes"),
        _list(data, "domain_upstreams"),
        _list(data, "dns_rewrites"),
        _list(data, "alert_rules", "sources"),
        _list(data, "notifications", "webhooks"),
    ]
    for group in _list(data, "client_groups"):
        lists.append(_list(group, "blocklist_sources"))
    return lists


def ensure_item_ids(data: dict[str, Any]) -> bool:
    """Give every addressable list entry a stable `id`, so the API can name an
    entry without relying on its position (which shifts when another admin
    adds or removes an entry in between). Returns True if anything changed."""
    changed = False
    for items in _id_lists(data):
        seen: set[str] = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            item_id = item.get("id")
            if not isinstance(item_id, str) or not item_id or item_id in seen:
                item_id = secrets.token_hex(4)
                while item_id in seen:
                    item_id = secrets.token_hex(4)
                item["id"] = item_id
                changed = True
            seen.add(item_id)
    return changed

class ConfigStore:
    def __init__(self, db_path: Path | None = None, backup_path: Path | None = None):
        self.db_path = db_path or _default_db_path()
        self.backup_path = backup_path or _default_backup_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.RLock()
        self._db_lock = threading.Lock()
        self._stop_event = threading.Event()

        self._init_schema()
        self._data = self._load_initial()
        if ensure_item_ids(self._data):
            self._save_to_db(self._data)
        self._version = 0

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()

    def _load_initial(self) -> dict[str, Any]:
        with self._db_lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT data FROM config WHERE id = 1").fetchone()
            finally:
                conn.close()
        if row is not None:
            return json.loads(row[0])

        data = self._seed_data()
        self._save_to_db(data)
        return data

    def _seed_data(self) -> dict[str, Any]:
        for path in (self.backup_path, _default_legacy_yaml_path()):
            if path.exists():
                with open(path, "r", encoding="utf-8") as fh:
                    return yaml.safe_load(fh) or {}
        with open(EXAMPLE_CONFIG, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}

    def _save_to_db(self, data: dict[str, Any]) -> None:
        payload = json.dumps(data)
        with self._db_lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO config (id, data, updated_at) VALUES (1, ?, ?) "
                    "ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
                    (payload, time.time()),
                )
                conn.commit()
            finally:
                conn.close()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._data)

    def get(self, *keys: str, default: Any = None) -> Any:
        with self._lock:
            node: Any = self._data
            for key in keys:
                if not isinstance(node, dict) or key not in node:
                    return default
                node = node[key]
            return default if node is None else node

    def mutate(self, fn) -> Any:
        """Apply `fn` to a private copy of the config, save it, then swap it in.

        Copy-on-write: readers on other threads (every DNS query reads the
        config) only ever see a complete old or a complete new version - never
        a list or dict that's being changed under them - and a failing `fn`
        leaves the live config untouched."""
        with self._lock:
            data = copy.deepcopy(self._data)
            result = fn(data)
            ensure_item_ids(data)
            self._save_to_db(data)
            self._data = data
            self._version += 1
            return result

    @property
    def version(self) -> int:
        """Increases on every change (local mutate, or a reload that found a
        different config), so callers can cache values derived from it."""
        return self._version

    def reload(self) -> None:
        with self._lock:
            data = self._load_initial()
            if data != self._data:
                self._data = data
                self._version += 1

    def start_reload_thread(self, interval_seconds: float = 5.0) -> None:
        def _loop() -> None:
            while not self._stop_event.wait(interval_seconds):
                self.reload()

        threading.Thread(target=_loop, name="config-reload", daemon=True).start()

    def write_backup(self) -> None:
        with self._lock:
            data = copy.deepcopy(self._data)
        self.backup_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.backup_path.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(data, fh, sort_keys=False)
        tmp_path.replace(self.backup_path)

    def start_backup_thread(self, interval_hours: float = 12.0) -> None:
        self.write_backup()

        def _loop() -> None:
            while not self._stop_event.wait(interval_hours * 3600):
                self.write_backup()

        threading.Thread(target=_loop, name="config-backup", daemon=True).start()

    def stop(self) -> None:
        self._stop_event.set()
