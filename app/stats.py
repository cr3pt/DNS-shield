"""Query statistics and log, kept entirely on local disk.

No query data ever leaves the host: this module only ever writes to the
local /data volume. There is no upstream analytics or telemetry endpoint.
"""

from __future__ import annotations

import json
import threading
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any


class Stats:
    def __init__(self, snapshot_path: Path, max_log_entries: int = 5000):
        self._snapshot_path = snapshot_path
        self._max_log_entries = max_log_entries
        self._lock = threading.Lock()
        self._total = 0
        self._blocked = 0
        self._domain_counts: Counter[str] = Counter()
        self._blocked_domain_counts: Counter[str] = Counter()
        self._client_counts: Counter[str] = Counter()
        self._log: deque[dict[str, Any]] = deque(maxlen=max_log_entries)
        self._started_at = time.time()
        self._dirty = False
        self._load()

    def record(self, qname: str, blocked: bool, client_ip: str, qtype: str) -> None:
        with self._lock:
            self._total += 1
            self._domain_counts[qname] += 1
            self._client_counts[client_ip] += 1
            if blocked:
                self._blocked += 1
                self._blocked_domain_counts[qname] += 1
            self._log.append(
                {
                    "ts": time.time(),
                    "domain": qname,
                    "qtype": qtype,
                    "client": client_ip,
                    "blocked": blocked,
                }
            )
            self._dirty = True

    def snapshot(self, top_n: int = 25, log_n: int = 200) -> dict[str, Any]:
        with self._lock:
            return {
                "started_at": self._started_at,
                "total_queries": self._total,
                "blocked_queries": self._blocked,
                "top_domains": self._domain_counts.most_common(top_n),
                "top_blocked_domains": self._blocked_domain_counts.most_common(top_n),
                "top_clients": self._client_counts.most_common(top_n),
                "recent_queries": list(self._log)[-log_n:][::-1],
            }

    # -- persistence --------------------------------------------------
    def _load(self) -> None:
        if not self._snapshot_path.exists():
            return
        try:
            data = json.loads(self._snapshot_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return
        self._total = data.get("total_queries", 0)
        self._blocked = data.get("blocked_queries", 0)
        self._domain_counts = Counter(dict(data.get("top_domains", [])))
        self._blocked_domain_counts = Counter(dict(data.get("top_blocked_domains", [])))
        self._client_counts = Counter(dict(data.get("top_clients", [])))
        self._log.extend(data.get("recent_queries", [])[::-1])

    def save_if_dirty(self) -> None:
        with self._lock:
            if not self._dirty:
                return
            snapshot = {
                "total_queries": self._total,
                "blocked_queries": self._blocked,
                "top_domains": self._domain_counts.most_common(500),
                "top_blocked_domains": self._blocked_domain_counts.most_common(500),
                "top_clients": self._client_counts.most_common(200),
                "recent_queries": list(self._log)[-self._max_log_entries :],
            }
            self._dirty = False
        self._snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._snapshot_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(snapshot), encoding="utf-8")
        tmp_path.replace(self._snapshot_path)

    def start_autosave(self, interval_seconds: float = 30.0) -> None:
        def _loop() -> None:
            while True:
                time.sleep(interval_seconds)
                self.save_if_dirty()

        threading.Thread(target=_loop, name="stats-autosave", daemon=True).start()
