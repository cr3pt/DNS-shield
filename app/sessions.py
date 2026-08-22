"""In-memory login sessions.

A session is just a random token mapped to a username, held in process
memory only - nothing written to disk. A container restart signs
everyone out, which is a reasonable trade for a small self-hosted app:
no session table to migrate, no stale tokens to prune from a database.
"""

from __future__ import annotations

import secrets
import threading
import time

COOKIE_NAME = "dnsshield_session"
_DEFAULT_TTL_SECONDS = 7 * 24 * 3600


class SessionStore:
    def __init__(self, ttl_seconds: float = _DEFAULT_TTL_SECONDS):
        self._ttl = ttl_seconds
        self._sessions: dict[str, dict] = {}
        self._lock = threading.Lock()

    def create(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[token] = {"username": username, "expires_at": time.time() + self._ttl}
        return token

    def username_for(self, token: str | None) -> str | None:
        if not token:
            return None
        with self._lock:
            entry = self._sessions.get(token)
            if entry is None:
                return None
            if entry["expires_at"] < time.time():
                del self._sessions[token]
                return None
            return entry["username"]

    def destroy(self, token: str | None) -> None:
        if not token:
            return
        with self._lock:
            self._sessions.pop(token, None)

    def destroy_all_for(self, username: str) -> None:
        with self._lock:
            for token, entry in list(self._sessions.items()):
                if entry["username"] == username:
                    del self._sessions[token]
