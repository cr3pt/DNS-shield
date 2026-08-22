from __future__ import annotations

from typing import Any

from app.auth import hash_password, verify_password

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


def _admin_count(users: list[dict[str, Any]]) -> int:
    return sum(1 for u in users if u.get("role") == "admin")
