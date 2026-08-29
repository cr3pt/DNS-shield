from __future__ import annotations

import secrets
import threading
import time
from typing import Any

import requests
from authlib.integrations.requests_client import OAuth2Session
from authlib.jose import JsonWebKey
from authlib.jose import jwt as jose_jwt

_STATE_TTL_SECONDS = 600
_HTTP_TIMEOUT = 10


class OIDCError(Exception):
    pass


class PendingSSOStore:
    """Tracks in-flight OIDC authorization requests, keyed by the unguessable
    `state` value so the callback can recover the nonce it must check the
    ID token against, and reject any request whose state we didn't issue."""

    def __init__(self, ttl_seconds: float = _STATE_TTL_SECONDS):
        self._ttl = ttl_seconds
        self._entries: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def create(self, nonce: str, next_url: str) -> str:
        state = secrets.token_urlsafe(24)
        with self._lock:
            self._prune()
            self._entries[state] = {"nonce": nonce, "next": next_url, "expires_at": time.time() + self._ttl}
        return state

    def consume(self, state: str | None) -> dict[str, Any] | None:
        if not state:
            return None
        with self._lock:
            entry = self._entries.pop(state, None)
        if entry is None or entry["expires_at"] < time.time():
            return None
        return entry

    def _prune(self) -> None:
        now = time.time()
        for key in [k for k, v in self._entries.items() if v["expires_at"] < now]:
            del self._entries[key]


def discover(issuer: str) -> dict[str, Any]:
    issuer = (issuer or "").strip().rstrip("/")
    if not issuer:
        raise OIDCError("No OIDC issuer configured")
    url = f"{issuer}/.well-known/openid-configuration"
    try:
        resp = requests.get(url, timeout=_HTTP_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        raise OIDCError(f"Could not reach the identity provider's discovery document: {exc}") from exc


def build_authorization_url(cfg: dict[str, Any], redirect_uri: str, state: str, nonce: str) -> str:
    metadata = discover(cfg.get("issuer", ""))
    session = OAuth2Session(
        cfg.get("client_id", ""),
        cfg.get("client_secret") or None,
        scope=cfg.get("scopes") or "openid email profile",
        redirect_uri=redirect_uri,
    )
    try:
        uri, _ = session.create_authorization_url(
            metadata["authorization_endpoint"], state=state, nonce=nonce
        )
    except KeyError as exc:
        raise OIDCError("Identity provider's discovery document is missing authorization_endpoint") from exc
    return uri


def exchange_code(cfg: dict[str, Any], redirect_uri: str, code: str) -> tuple[dict[str, Any], dict[str, Any]]:
    metadata = discover(cfg.get("issuer", ""))
    session = OAuth2Session(cfg.get("client_id", ""), cfg.get("client_secret") or None, redirect_uri=redirect_uri)
    try:
        token = session.fetch_token(
            metadata["token_endpoint"], code=code, grant_type="authorization_code"
        )
    except KeyError as exc:
        raise OIDCError("Identity provider's discovery document is missing token_endpoint") from exc
    except Exception as exc:
        raise OIDCError(f"Token exchange with the identity provider failed: {exc}") from exc
    return token, metadata


def verify_id_token(id_token: str, metadata: dict[str, Any], cfg: dict[str, Any], nonce: str) -> dict[str, Any]:
    jwks_uri = metadata.get("jwks_uri")
    if not jwks_uri:
        raise OIDCError("Identity provider's discovery document is missing jwks_uri")
    try:
        resp = requests.get(jwks_uri, timeout=_HTTP_TIMEOUT)
        resp.raise_for_status()
        jwks = JsonWebKey.import_key_set(resp.json())
        claims = jose_jwt.decode(
            id_token,
            jwks,
            claims_options={
                "iss": {"essential": True, "value": metadata.get("issuer")},
                "aud": {"essential": True, "value": cfg.get("client_id", "")},
            },
        )
        claims.validate()
    except Exception as exc:
        raise OIDCError(f"ID token verification failed: {exc}") from exc
    if claims.get("nonce") != nonce:
        raise OIDCError("ID token nonce did not match - possible replay attempt")
    return dict(claims)
