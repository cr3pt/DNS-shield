# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import threading
import time


class DnssecCache:
    def __init__(self, ttl_seconds: float = 3600.0):
        self._ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        self._entries: dict[str, tuple[bool, float]] = {}

    def set_ttl(self, ttl_seconds: float) -> None:
        self._ttl_seconds = max(1.0, ttl_seconds)

    def record(self, qname: str, secure: bool) -> None:
        with self._lock:
            self._entries[qname] = (secure, time.time() + self._ttl_seconds)

    def status(self, qname: str) -> bool | None:
        with self._lock:
            entry = self._entries.get(qname)
        if entry is None:
            return None
        secure, expires_at = entry
        if expires_at < time.time():
            return None
        return secure

    def clear_expired(self) -> None:
        now = time.time()
        with self._lock:
            expired = [k for k, (_, expires_at) in self._entries.items() if expires_at < now]
            for k in expired:
                del self._entries[k]

    def counts(self) -> dict[str, int]:
        now = time.time()
        with self._lock:
            live = [secure for secure, expires_at in self._entries.values() if expires_at >= now]
        return {"secure": sum(1 for s in live if s), "insecure": sum(1 for s in live if not s)}
