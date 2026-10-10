# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import threading
import time


class LoginThrottle:
    def __init__(self, max_attempts: int = 5, lockout_seconds: float = 900.0):
        self._max_attempts = max_attempts
        self._lockout_seconds = lockout_seconds
        self._lock = threading.Lock()
        self._failures: dict[str, list[float]] = {}

    def configure(self, max_attempts: int, lockout_seconds: float) -> None:
        with self._lock:
            self._max_attempts = max(1, max_attempts)
            self._lockout_seconds = max(1.0, lockout_seconds)

    def _prune(self, key: str, now: float) -> list[float]:
        cutoff = now - self._lockout_seconds
        attempts = [t for t in self._failures.get(key, []) if t >= cutoff]
        if attempts:
            self._failures[key] = attempts
        else:
            self._failures.pop(key, None)
        return attempts

    def retry_after(self, key: str) -> float | None:
        now = time.time()
        with self._lock:
            attempts = self._prune(key, now)
            if len(attempts) < self._max_attempts:
                return None
            remaining = self._lockout_seconds - (now - attempts[-1])
            return max(0.0, remaining)

    def record_failure(self, key: str) -> None:
        now = time.time()
        with self._lock:
            self._prune(key, now)
            self._failures.setdefault(key, []).append(now)

    def record_success(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
