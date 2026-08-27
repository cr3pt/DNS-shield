from __future__ import annotations

import base64
import time
from typing import Any

from app.api_tokens import generate_token, generate_token_id, hash_token
from app.auth import hash_password, verify_password
from app.passkeys import generate_passkey_id
from app.two_factor import (
    generate_backup_codes,
    generate_secret,
    hash_backup_code,
    provisioning_uri,
    verify_code,
)

_TOKEN_TOUCH_MIN_INTERVAL = 60.0

DEFAULT_PERMISSIONS: dict[str, Any] = {
    "allowed_clients": [],
    "allowed_groups": [],
    "view_threat_intel": False,
    "view_anomalies": False,
    "can_block": False,
    "can_whitelist": False,
}


def _normalized_permissions(raw: dict[str, Any] | None) -> dict[str, Any]:
    raw = raw or {}
    return {
        "allowed_clients": list(raw.get("allowed_clients") or []),
        "allowed_groups": list(raw.get("allowed_groups") or []),
        "view_threat_intel": bool(raw.get("view_threat_intel", False)),
        "view_anomalies": bool(raw.get("view_anomalies", False)),
        "can_block": bool(raw.get("can_block", False)),
        "can_whitelist": bool(raw.get("can_whitelist", False)),
    }


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "username": user["username"],
        "role": user["role"],
        "permissions": _normalized_permissions(user.get("permissions")),
        "totp_enabled": bool(user.get("totp_enabled", False)),
        "has_passkeys": bool(user.get("webauthn_credentials")),
    }


def public_token(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": record["id"],
        "name": record.get("name", ""),
        "created_at": record.get("created_at"),
        "last_used_at": record.get("last_used_at"),
    }


def public_passkey(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": record["id"],
        "name": record.get("name", ""),
        "created_at": record.get("created_at"),
        "last_used_at": record.get("last_used_at"),
    }


class UserStore:
    def __init__(self, config_store):
        self._config = config_store
        self.ensure_default_admin()

    def ensure_default_admin(self) -> None:
        def _mutate(data: dict[str, Any]) -> None:
            users = data.get("users")
            if users:
                return
            web_cfg = data.get("web", {}) or {}
            username = str(web_cfg.get("username") or "admin")
            existing_password = str(web_cfg.get("password") or "changeme")
            data["users"] = [
                {
                    "username": username,
                    "password_hash": hash_password(existing_password),
                    "role": "admin",
                    "permissions": dict(DEFAULT_PERMISSIONS),
                }
            ]
            web_cfg.pop("password", None)
            web_cfg.pop("username", None)
            data["web"] = web_cfg

        self._config.mutate(_mutate)

    def list(self) -> list[dict[str, Any]]:
        return self._config.get("users", default=[]) or []

    def get(self, username: str) -> dict[str, Any] | None:
        for user in self.list():
            if user.get("username") == username:
                return user
        return None

    def verify_login(self, username: str, password: str) -> dict[str, Any] | None:
        user = self.get(username)
        if user is None:
            return None
        if not verify_password(password, user.get("password_hash", "")):
            return None
        return user

    def create(
        self,
        username: str,
        password: str,
        role: str,
        permissions: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        username = username.strip()
        if not username:
            raise ValueError("Username is required")
        if role not in ("admin", "user"):
            raise ValueError('Role must be "admin" or "user"')
        if not password:
            raise ValueError("Password is required")

        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            users = data.setdefault("users", [])
            if any(u.get("username") == username for u in users):
                raise ValueError(f'A user named "{username}" already exists')
            user = {
                "username": username,
                "password_hash": hash_password(password),
                "role": role,
                "permissions": _normalized_permissions(permissions),
            }
            users.append(user)
            return user

        return self._config.mutate(_mutate)

    def update(
        self,
        username: str,
        password: str | None = None,
        role: str | None = None,
        permissions: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if role is not None and role not in ("admin", "user"):
            raise ValueError('Role must be "admin" or "user"')

        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            users = data.setdefault("users", [])
            for user in users:
                if user.get("username") == username:
                    if password:
                        user["password_hash"] = hash_password(password)
                    if role is not None:
                        if role != "admin" and _admin_count(users) <= 1 and user.get("role") == "admin":
                            raise ValueError("Can't demote the last remaining administrator")
                        user["role"] = role
                    if permissions is not None:
                        user["permissions"] = _normalized_permissions(permissions)
                    return user
            raise ValueError(f'No such user: "{username}"')

        return self._config.mutate(_mutate)

    def delete(self, username: str) -> None:
        def _mutate(data: dict[str, Any]) -> None:
            users = data.setdefault("users", [])
            target = next((u for u in users if u.get("username") == username), None)
            if target is None:
                raise ValueError(f'No such user: "{username}"')
            if target.get("role") == "admin" and _admin_count(users) <= 1:
                raise ValueError("Can't delete the last remaining administrator")
            users.remove(target)

        self._config.mutate(_mutate)

    def list_tokens(self, username: str) -> list[dict[str, Any]]:
        user = self.get(username)
        if user is None:
            raise ValueError(f'No such user: "{username}"')
        return [public_token(t) for t in (user.get("api_tokens") or [])]

    def create_token(self, username: str, name: str) -> tuple[str, dict[str, Any]]:
        name = (name or "").strip()
        if not name:
            raise ValueError("Token name is required")
        token = generate_token()
        record = {
            "id": generate_token_id(),
            "name": name,
            "token_hash": hash_token(token),
            "created_at": time.time(),
            "last_used_at": None,
        }

        def _mutate(data: dict[str, Any]) -> None:
            for user in data.setdefault("users", []):
                if user.get("username") == username:
                    user.setdefault("api_tokens", []).append(record)
                    return
            raise ValueError(f'No such user: "{username}"')

        self._config.mutate(_mutate)
        return token, public_token(record)

    def revoke_token(self, username: str, token_id: str) -> None:
        def _mutate(data: dict[str, Any]) -> None:
            for user in data.setdefault("users", []):
                if user.get("username") != username:
                    continue
                tokens = user.setdefault("api_tokens", [])
                remaining = [t for t in tokens if t.get("id") != token_id]
                if len(remaining) == len(tokens):
                    raise ValueError("No such token")
                user["api_tokens"] = remaining
                return
            raise ValueError(f'No such user: "{username}"')

        self._config.mutate(_mutate)

    def find_by_token(self, token: str) -> dict[str, Any] | None:
        if not token:
            return None
        thash = hash_token(token)
        for user in self.list():
            for record in user.get("api_tokens") or []:
                if record.get("token_hash") == thash:
                    self._touch_token(user["username"], record.get("id"), record.get("last_used_at"))
                    return user
        return None

    def _touch_token(self, username: str, token_id: str | None, last_used_at: float | None) -> None:
        if token_id is None:
            return
        now = time.time()
        if last_used_at and now - last_used_at < _TOKEN_TOUCH_MIN_INTERVAL:
            return

        def _mutate(data: dict[str, Any]) -> None:
            for user in data.get("users", []):
                if user.get("username") != username:
                    continue
                for record in user.get("api_tokens") or []:
                    if record.get("id") == token_id:
                        record["last_used_at"] = now
                        return

        self._config.mutate(_mutate)

    def has_second_factor(self, username: str) -> bool:
        user = self.get(username)
        if user is None:
            return False
        return bool(user.get("totp_enabled")) or bool(user.get("webauthn_credentials"))

    def list_passkeys(self, username: str) -> list[dict[str, Any]]:
        user = self.get(username)
        if user is None:
            raise ValueError(f'No such user: "{username}"')
        return [public_passkey(p) for p in (user.get("webauthn_credentials") or [])]

    def passkey_credential_ids(self, username: str) -> list[str]:
        user = self.get(username)
        if user is None:
            return []
        return [p["credential_id"] for p in (user.get("webauthn_credentials") or [])]

    def find_passkey_by_credential_id(self, username: str, credential_id: str) -> dict[str, Any] | None:
        user = self.get(username)
        if user is None:
            return None
        for p in user.get("webauthn_credentials") or []:
            if p.get("credential_id") == credential_id:
                return p
        return None

    def add_passkey(self, username: str, name: str, credential_id: str, public_key: bytes, sign_count: int) -> dict[str, Any]:
        name = (name or "").strip() or "Passkey"
        record = {
            "id": generate_passkey_id(),
            "name": name,
            "credential_id": credential_id,
            "public_key": base64.b64encode(public_key).decode("ascii"),
            "sign_count": sign_count,
            "created_at": time.time(),
            "last_used_at": None,
        }

        def _mutate(data: dict[str, Any]) -> None:
            for u in data.setdefault("users", []):
                if u.get("username") == username:
                    u.setdefault("webauthn_credentials", []).append(record)
                    return
            raise ValueError(f'No such user: "{username}"')

        self._config.mutate(_mutate)
        return public_passkey(record)

    def remove_passkey(self, username: str, passkey_id: str) -> None:
        def _mutate(data: dict[str, Any]) -> None:
            for u in data.setdefault("users", []):
                if u.get("username") != username:
                    continue
                creds = u.setdefault("webauthn_credentials", [])
                remaining = [c for c in creds if c.get("id") != passkey_id]
                if len(remaining) == len(creds):
                    raise ValueError("No such passkey")
                u["webauthn_credentials"] = remaining
                return
            raise ValueError(f'No such user: "{username}"')

        self._config.mutate(_mutate)

    def record_passkey_use(self, username: str, credential_id: str, sign_count: int) -> None:
        def _mutate(data: dict[str, Any]) -> None:
            for u in data.get("users", []):
                if u.get("username") != username:
                    continue
                for p in u.get("webauthn_credentials") or []:
                    if p.get("credential_id") == credential_id:
                        p["sign_count"] = sign_count
                        p["last_used_at"] = time.time()
                        return

        self._config.mutate(_mutate)

    def begin_totp_setup(self, username: str) -> tuple[str, str]:
        user = self.get(username)
        if user is None:
            raise ValueError(f'No such user: "{username}"')
        secret = generate_secret()

        def _mutate(data: dict[str, Any]) -> None:
            for u in data.setdefault("users", []):
                if u.get("username") == username:
                    u["totp_pending_secret"] = secret
                    return
            raise ValueError(f'No such user: "{username}"')

        self._config.mutate(_mutate)
        return secret, provisioning_uri(secret, username)

    def confirm_totp_setup(self, username: str, code: str) -> list[str]:
        user = self.get(username)
        if user is None:
            raise ValueError(f'No such user: "{username}"')
        secret = user.get("totp_pending_secret")
        if not secret:
            raise ValueError("No pending TOTP setup - start setup again")
        if not verify_code(secret, code):
            raise ValueError("Incorrect code - check your authenticator app and try again")

        backup_codes = generate_backup_codes()
        backup_hashes = [hash_backup_code(c) for c in backup_codes]

        def _mutate(data: dict[str, Any]) -> None:
            for u in data.setdefault("users", []):
                if u.get("username") == username:
                    u["totp_enabled"] = True
                    u["totp_secret"] = secret
                    u.pop("totp_pending_secret", None)
                    u["totp_backup_codes"] = backup_hashes
                    return
            raise ValueError(f'No such user: "{username}"')

        self._config.mutate(_mutate)
        return backup_codes

    def disable_totp(self, username: str, password: str) -> None:
        user = self.get(username)
        if user is None:
            raise ValueError(f'No such user: "{username}"')
        if not verify_password(password, user.get("password_hash", "")):
            raise ValueError("Current password is incorrect")

        def _mutate(data: dict[str, Any]) -> None:
            for u in data.setdefault("users", []):
                if u.get("username") == username:
                    u["totp_enabled"] = False
                    u.pop("totp_secret", None)
                    u.pop("totp_pending_secret", None)
                    u.pop("totp_backup_codes", None)
                    return
            raise ValueError(f'No such user: "{username}"')

        self._config.mutate(_mutate)

    def verify_totp_or_backup_code(self, username: str, code: str) -> bool:
        user = self.get(username)
        if user is None or not user.get("totp_enabled"):
            return False
        code = (code or "").strip()
        if not code:
            return False

        if verify_code(user.get("totp_secret", ""), code):
            return True

        code_hash = hash_backup_code(code)
        backup_hashes = user.get("totp_backup_codes") or []
        if code_hash not in backup_hashes:
            return False

        def _mutate(data: dict[str, Any]) -> None:
            for u in data.setdefault("users", []):
                if u.get("username") == username:
                    u["totp_backup_codes"] = [h for h in (u.get("totp_backup_codes") or []) if h != code_hash]
                    return

        self._config.mutate(_mutate)
        return True


def _admin_count(users: list[dict[str, Any]]) -> int:
    return sum(1 for u in users if u.get("role") == "admin")
