# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""FastAPI app factory: authentication, middleware and the route modules."""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from app.login_throttle import LoginThrottle
from app.netmatch import ip_matches
from app.passkeys import PendingChallengeStore
from app.sessions import COOKIE_NAME, SessionStore
from app.sso import PendingSSOStore
from app.two_factor import PendingTotpStore
from app.users import UserStore
from app.web import routes
from app.web.common import (
    _CSRF_EXEMPT_PATHS,
    _PASSWORD_CHANGE_ALLOWED_PATHS,
    _SECURITY_HEADERS,
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
)
from app.web.context import AppContext

__all__ = ["CSRF_COOKIE_NAME", "CSRF_HEADER_NAME", "PendingSSOStore", "create_app"]


def create_app(
    config_store,
    blocklist,
    stats,
    started_at: float,
    cache=None,
    client_names=None,
    upstream_stats=None,
    enrichment_store=None,
    anomaly=None,
    notifications=None,
    users: UserStore | None = None,
    sessions: SessionStore | None = None,
    dnssec_cache=None,
    resolver=None,
    audit_log=None,
    dhcp_server=None,
    rogue_dhcp_detector=None,
    proxy_manager=None,
    client_domain_graph=None,
    data_dir: Path | None = None,
) -> FastAPI:
    app = FastAPI(title="DNS-shield", docs_url=None, redoc_url=None, openapi_url=None)
    data_dir = data_dir if data_dir is not None else Path(os.environ.get("DNSSHIELD_DATA_DIR", "/data"))

    users = users if users is not None else UserStore(config_store)
    sessions = sessions if sessions is not None else SessionStore()
    login_throttle = LoginThrottle()
    pending_totp = PendingTotpStore()
    pending_challenges = PendingChallengeStore()
    pending_sso = PendingSSOStore()

    def _configured_public_url() -> tuple[str, str] | None:
        """(origin, hostname) of web.public_url - the address people open the
        dashboard at - when it's set."""
        raw = (config_store.get("web", "public_url", default="") or "").strip()
        if not raw:
            return None
        parsed = urlparse(raw)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return None
        return f"{parsed.scheme}://{parsed.netloc}", parsed.hostname

    def _webauthn_rp_id(request: Request) -> str:
        configured = _configured_public_url()
        if configured is not None:
            return configured[1]
        return request.url.hostname or "localhost"

    def _webauthn_origin(request: Request) -> str:
        # Never the request's own Origin header: the expected origin is what
        # the browser-signed clientData is checked against, so it has to come
        # from our side - the configured public URL, else the address this
        # request was made to.
        configured = _configured_public_url()
        if configured is not None:
            return configured[0]
        return f"{request.url.scheme}://{request.url.netloc}"

    NO_CACHE = {"Cache-Control": "no-cache"}

    def _set_auth_cookies(response: Response, token: str) -> None:
        secure = bool(config_store.get("web", "https_enabled", default=False))
        response.set_cookie(
            COOKIE_NAME,
            token,
            httponly=True,
            samesite="lax",
            secure=secure,
            max_age=7 * 24 * 3600,
            path="/",
        )
        response.set_cookie(
            CSRF_COOKIE_NAME,
            secrets.token_urlsafe(32),
            httponly=False,
            samesite="lax",
            secure=secure,
            max_age=7 * 24 * 3600,
            path="/",
        )

    def _clear_auth_cookies(response: Response) -> None:
        response.delete_cookie(COOKIE_NAME, path="/")
        response.delete_cookie(CSRF_COOKIE_NAME, path="/")

    def _current_user(request: Request) -> dict[str, Any] | None:
        cookie_token = request.cookies.get(COOKIE_NAME)
        username = sessions.username_for(cookie_token)
        if username is not None:
            return users.get(username)

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return users.find_by_token(auth_header[len("Bearer ") :].strip())
        return None

    def require_auth(request: Request) -> dict[str, Any]:
        user = _current_user(request)
        if user is None:
            raise HTTPException(status_code=401, detail="Unauthorized")
        if user.get("must_change_password") and request.url.path not in _PASSWORD_CHANGE_ALLOWED_PATHS:
            raise HTTPException(
                status_code=403,
                detail="password_change_required: change the default password before using the dashboard",
            )
        return user

    def require_admin(user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
        if user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Administrator access required")
        return user

    def require_permission(flag: str):
        def _dep(user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
            if user.get("role") != "admin" and not (user.get("permissions") or {}).get(flag):
                raise HTTPException(status_code=403, detail="You don't have permission to do this")
            return user

        return _dep

    def _allowed_client_ips(user: dict[str, Any]) -> list[str] | None:
        if user.get("role") == "admin":
            return None
        perms = user.get("permissions") or {}
        patterns = list(perms.get("allowed_clients") or [])
        allowed_groups = set(perms.get("allowed_groups") or [])
        if allowed_groups:
            for group in config_store.get("client_groups", default=[]) or []:
                if group.get("name") in allowed_groups:
                    patterns.extend(group.get("match") or [])
        if not patterns:
            return []
        return [ip for ip in stats.distinct_clients() if any(ip_matches(ip, p) for p in patterns)]

    @app.middleware("http")
    async def csrf_middleware(request: Request, call_next):
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.url.path not in _CSRF_EXEMPT_PATHS:
            cookie_token = request.cookies.get(COOKIE_NAME)
            if cookie_token and sessions.username_for(cookie_token) is not None:
                csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)
                csrf_header = request.headers.get(CSRF_HEADER_NAME)
                if not csrf_cookie or not csrf_header or not secrets.compare_digest(csrf_cookie, csrf_header):
                    return JSONResponse({"detail": "Missing or invalid CSRF token"}, status_code=403)
        return await call_next(request)

    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        response = await call_next(request)
        response.headers.update(_SECURITY_HEADERS)
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    _AUDIT_EXCLUDED_PATHS = {"/api/login", "/api/login/totp", "/api/logout"}

    @app.middleware("http")
    async def audit_middleware(request: Request, call_next):
        response = await call_next(request)
        if (
            audit_log is not None
            and request.method in ("POST", "PUT", "PATCH", "DELETE")
            and request.url.path.startswith("/api/")
            and request.url.path not in _AUDIT_EXCLUDED_PATHS
            and response.status_code < 400
        ):
            user = _current_user(request)
            if user is not None:
                client_ip = _client_ip(request)
                audit_log.record(user["username"], f"{request.method} {request.url.path}", client_ip=client_ip)
        return response

    def _client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def _login_retry_after(client_ip: str) -> float | None:
        """Seconds this IP still has to wait after too many failed logins
        (None = may try now), with the limits currently configured."""
        max_attempts = int(config_store.get("web", "login_max_attempts", default=5) or 5)
        lockout_seconds = max(1.0, float(config_store.get("web", "login_lockout_minutes", default=15) or 15) * 60)
        login_throttle.configure(max_attempts, lockout_seconds)
        return login_throttle.retry_after(client_ip)

    def _enforce_login_throttle(client_ip: str) -> None:
        retry_after = _login_retry_after(client_ip)
        if retry_after is not None:
            wait_seconds = int(retry_after) + 1
            raise HTTPException(
                status_code=429,
                detail=f"Too many failed login attempts - try again in {wait_seconds}s",
                headers={"Retry-After": str(wait_seconds)},
            )

    ctx = AppContext(
        NO_CACHE=NO_CACHE,
        _allowed_client_ips=_allowed_client_ips,
        _clear_auth_cookies=_clear_auth_cookies,
        _client_ip=_client_ip,
        _current_user=_current_user,
        _enforce_login_throttle=_enforce_login_throttle,
        _login_retry_after=_login_retry_after,
        _set_auth_cookies=_set_auth_cookies,
        _webauthn_origin=_webauthn_origin,
        _webauthn_rp_id=_webauthn_rp_id,
        anomaly=anomaly,
        audit_log=audit_log,
        blocklist=blocklist,
        cache=cache,
        client_domain_graph=client_domain_graph,
        client_names=client_names,
        config_store=config_store,
        data_dir=data_dir,
        dhcp_server=dhcp_server,
        dnssec_cache=dnssec_cache,
        enrichment_store=enrichment_store,
        login_throttle=login_throttle,
        notifications=notifications,
        pending_challenges=pending_challenges,
        pending_sso=pending_sso,
        pending_totp=pending_totp,
        require_admin=require_admin,
        require_auth=require_auth,
        require_permission=require_permission,
        resolver=resolver,
        sessions=sessions,
        started_at=started_at,
        stats=stats,
        upstream_stats=upstream_stats,
        users=users,
    )
    for module in routes.MODULES:
        module.register(app, ctx)
    return app
