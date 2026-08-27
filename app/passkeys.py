from __future__ import annotations

import secrets
import threading
import time
from typing import Any

import webauthn
from webauthn.helpers import base64url_to_bytes, options_to_json
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

_CHALLENGE_TTL_SECONDS = 300.0


def registration_options_json(rp_id: str, rp_name: str, username: str, exclude_credential_ids: list[str]) -> tuple[str, bytes]:
    options = webauthn.generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_name=username,
        user_display_name=username,
        exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(cid)) for cid in exclude_credential_ids],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    return options_to_json(options), options.challenge


def verify_registration(credential: dict, expected_challenge: bytes, rp_id: str, origin: str):
    return webauthn.verify_registration_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id=rp_id,
        expected_origin=origin,
    )


def authentication_options_json(rp_id: str, allow_credential_ids: list[str]) -> tuple[str, bytes]:
    options = webauthn.generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(cid)) for cid in allow_credential_ids] or None,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return options_to_json(options), options.challenge


def verify_authentication(credential: dict, expected_challenge: bytes, rp_id: str, origin: str, public_key: bytes, sign_count: int):
    return webauthn.verify_authentication_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id=rp_id,
        expected_origin=origin,
        credential_public_key=public_key,
        credential_current_sign_count=sign_count,
    )


def generate_passkey_id() -> str:
    return secrets.token_hex(8)


class PendingChallengeStore:
    """Short-lived server-side memory of a WebAuthn ceremony's challenge, keyed by an opaque token."""

    def __init__(self, ttl_seconds: float = _CHALLENGE_TTL_SECONDS):
        self._ttl = ttl_seconds
        self._store: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def new_token(self, username: str, challenge: bytes) -> str:
        token = secrets.token_urlsafe(24)
        self.set(token, username, challenge)
        return token

    def set(self, token: str, username: str, challenge: bytes) -> None:
        with self._lock:
            self._store[token] = {"username": username, "challenge": challenge, "expires_at": time.time() + self._ttl}

    def get(self, token: str | None) -> tuple[str, bytes] | None:
        if not token:
            return None
        with self._lock:
            entry = self._store.get(token)
            if entry is None:
                return None
            if entry["expires_at"] < time.time():
                del self._store[token]
                return None
            return entry["username"], entry["challenge"]

    def pop(self, token: str | None) -> tuple[str, bytes] | None:
        result = self.get(token)
        if result is not None and token:
            with self._lock:
                self._store.pop(token, None)
        return result
