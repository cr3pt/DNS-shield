# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import hashlib
import io
import secrets
import threading
import time

import pyotp
import qrcode
import qrcode.image.svg

_PENDING_LOGIN_TTL_SECONDS = 300.0
_BACKUP_CODE_COUNT = 8


def generate_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str, issuer: str = "DNS-shield") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def qr_svg(uri: str) -> str:
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")


def verify_code(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)
    except Exception:
        return False


def generate_backup_codes(count: int = _BACKUP_CODE_COUNT) -> list[str]:
    return [f"{secrets.token_hex(4)}-{secrets.token_hex(4)}" for _ in range(count)]


def hash_backup_code(code: str) -> str:
    return hashlib.sha256(code.strip().lower().encode("utf-8")).hexdigest()


class PendingTotpStore:
    def __init__(self, ttl_seconds: float = _PENDING_LOGIN_TTL_SECONDS):
        self._ttl = ttl_seconds
        self._pending: dict[str, dict] = {}
        self._lock = threading.Lock()

    def create(self, username: str) -> str:
        token = secrets.token_urlsafe(24)
        with self._lock:
            self._pending[token] = {"username": username, "expires_at": time.time() + self._ttl}
        return token

    def username_for(self, token: str | None) -> str | None:
        if not token:
            return None
        with self._lock:
            entry = self._pending.get(token)
            if entry is None:
                return None
            if entry["expires_at"] < time.time():
                del self._pending[token]
                return None
            return entry["username"]

    def consume(self, token: str | None) -> str | None:
        username = self.username_for(token)
        if username is not None:
            with self._lock:
                self._pending.pop(token, None)
        return username
