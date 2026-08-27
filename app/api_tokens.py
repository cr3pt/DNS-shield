from __future__ import annotations

import hashlib
import secrets

TOKEN_PREFIX = "dnss_"


def generate_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def generate_token_id() -> str:
    return secrets.token_hex(8)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_preview(token: str) -> str:
    if len(token) <= 14:
        return token
    return f"{token[:10]}...{token[-4:]}"
