"""Multi-user accounts + role-based permissions.

Replaces the old single web.username/web.password pair with a `users`
list in the config store, each entry:

    {
      "username": str,
      "password_hash": str,        # bcrypt, never plain text
      "role": "admin" | "user",
      "permissions": {
          "allowed_clients": [str],   # IP/CIDR patterns; empty = all
          "allowed_groups": [str],    # client_group names; empty = all
          "view_threat_intel": bool,
          "view_anomalies": bool,
          "can_block": bool,
          "can_whitelist": bool,
      },
    }

"admin" always has every permission regardless of what's stored in
"permissions" - the fields there only matter for role "user". The very
first boot (or an upgrade from a version that only had web.username/
web.password) migrates that single account into one admin user here,
converting its existing plain-text password to a bcrypt hash in place -
the account and its password keep working exactly as before, just
hashed from now on.
"""

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
    """A user record with password_hash stripped, safe to send to the browser."""
    return {
        "username": user["username"],
        "role": user["role"],
        "permissions": _normalized_permissions(user.get("permissions")),
    }


class UserStore:
    def __init__(self, config_store):
        self._config = config_store
        self.ensure_default_admin()

    # -- migration from the old single web.username/web.password ---------
    def ensure_default_admin(self) -> None:
        """Idempotent: creates the migrated admin account if `users` is
        empty, otherwise a no-op. Called on startup, and again after any
        endpoint that wholesale-replaces the config (restoring an old
        backup, importing an AdGuard Home/Pi-hole config) - those can leave
        `users` empty if the source predates this feature or never had one,
        which would otherwise lock everyone out until a restart.
        """
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
            # The plain-text password is no longer the source of truth for
            # login (the hash above is) - drop it so it doesn't linger
            # in config.db/config.backup.yaml/exported backups.
            web_cfg.pop("password", None)
            web_cfg.pop("username", None)
            data["web"] = web_cfg

        self._config.mutate(_mutate)

    # -- reads --------------------------------------------------------
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

    # -- writes ---------------------------------------------------------
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
