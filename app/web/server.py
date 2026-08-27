from __future__ import annotations

import base64
import io
import re
import sqlite3
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

import yaml
from dnslib import DNSRecord
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel

from app.auth import verify_password
from app.blocklist_catalog import BLOCKLIST_CATALOG
from app.enrichment import enrich as run_enrichment
from app.import_adguard import import_config
from app.import_pihole import import_config as import_pihole_config
from app.login_throttle import LoginThrottle
from app.metrics import render_metrics
from app.netmatch import ip_matches
from app.passkeys import PendingChallengeStore
from app import passkeys as passkeys_lib
from webauthn.helpers import bytes_to_base64url
from app.sessions import COOKIE_NAME, SessionStore
from app.two_factor import PendingTotpStore, qr_svg
from app.typosquat import DEFAULT_PROTECTED_DOMAINS
from app.upstream import address as upstream_address
from app.upstream import is_disabled as upstream_is_disabled
from app.users import UserStore, public_user

STATIC_DIR = Path(__file__).resolve().parent / "static"


def _masked_key_preview(key: str | None) -> str:
    if not key:
        return ""
    if len(key) == 1:
        return key
    if len(key) == 2:
        return f"{key[0]}*"
    return f"{key[0]}{'*' * min(len(key) - 2, 12)}{key[-1]}"


_ANOMALY_DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "check_interval_minutes": 5,
    "window_minutes": 15,
    "min_queries": 20,
    "blocked_ratio_threshold": 0.5,
    "domain_burst_threshold": 50,
    "domain_burst_min_entropy": 3.3,
    "domain_burst_min_label_length": 10,
    "domain_burst_entropy_fraction": 0.5,
    "blocked_domain_burst_threshold": 15,
    "dns_tunneling_threshold": 30,
    "dns_tunneling_min_label_length": 20,
    "dns_tunneling_min_entropy": 3.0,
    "cooldown_minutes": 60,
}


def _anomaly_settings(cfg: dict[str, Any]) -> dict[str, Any]:
    return {key: cfg.get(key, default) for key, default in _ANOMALY_DEFAULTS.items()}


_ALERT_RULES_DEFAULTS: dict[str, Any] = {
    "check_interval_seconds": 15,
    "cooldown_minutes": 15,
}


def _alert_rules_settings(cfg: dict[str, Any]) -> dict[str, Any]:
    return {key: cfg.get(key, default) for key, default in _ALERT_RULES_DEFAULTS.items()}


def _notification_email_settings(cfg: dict[str, Any]) -> dict[str, Any]:
    return {
        "enabled": bool(cfg.get("enabled", False)),
        "smtp_host": cfg.get("smtp_host", "") or "",
        "smtp_port": cfg.get("smtp_port", 587),
        "smtp_security": cfg.get("smtp_security", "starttls") or "starttls",
        "smtp_username": cfg.get("smtp_username", "") or "",
        "smtp_password_set": bool(cfg.get("smtp_password")),
        "smtp_password_preview": _masked_key_preview(cfg.get("smtp_password")),
        "from_address": cfg.get("from_address", "") or "",
        "to_addresses": cfg.get("to_addresses", []) or [],
        "min_severity": cfg.get("min_severity", "medium") or "medium",
    }


def _notification_webhook_public(cfg: dict[str, Any]) -> dict[str, Any]:
    wtype = cfg.get("type", "discord")
    result = {
        "name": cfg.get("name", "") or "",
        "type": wtype,
        "enabled": bool(cfg.get("enabled", True)),
        "min_severity": cfg.get("min_severity", "medium") or "medium",
    }
    if wtype in ("discord", "slack"):
        result["url_set"] = bool(cfg.get("url"))
        result["url_preview"] = _masked_key_preview(cfg.get("url"))
    elif wtype == "telegram":
        result["telegram_bot_token_set"] = bool(cfg.get("telegram_bot_token"))
        result["telegram_bot_token_preview"] = _masked_key_preview(cfg.get("telegram_bot_token"))
        result["telegram_chat_id"] = cfg.get("telegram_chat_id", "") or ""
    return result


class BlocklistSourceIn(BaseModel):
    name: str
    url: str
    enabled: bool = True


class DomainIn(BaseModel):
    domain: str


class ValueIn(BaseModel):
    value: str


class RegexPatternIn(BaseModel):
    pattern: str


class ClientGroupIn(BaseModel):
    name: str
    match: list[str] = []
    enabled: bool = True
    allowlist: list[str] = []
    denylist: list[str] = []
    upstreams: list[str] = []
    blocklist_sources: list[dict[str, Any]] = []
    safe_search: bool | None = None
    schedule: dict[str, Any] | None = None


class GroupSafeSearchIn(BaseModel):
    safe_search: bool | None = None


class ScheduleWindowIn(BaseModel):
    days: list[int]
    start: str
    end: str


class GroupScheduleIn(BaseModel):
    enabled: bool = False
    timezone: str = ""
    windows: list[ScheduleWindowIn] = []


class DnsSettingsIn(BaseModel):
    listen_address: str | None = None
    listen_port: int | None = None
    upstream_timeout_seconds: float | None = None
    upstream_strategy: str | None = None
    upstream_stats_window_minutes: float | None = None
    block_mode: str | None = None
    blocked_ipv4: str | None = None
    blocked_ipv6: str | None = None
    block_ipv6: bool | None = None
    block_non_latin: bool | None = None
    cache_enabled: bool | None = None
    cache_max_entries: int | None = None
    cache_min_ttl_seconds: int | None = None
    cache_max_ttl_seconds: int | None = None
    resolve_client_names: bool | None = None
    client_name_resolver: str | None = None
    client_name_cache_seconds: int | None = None
    block_page_enabled: bool | None = None
    block_page_port: int | None = None
    regex_denylist_enabled: bool | None = None
    safe_search_enabled: bool | None = None
    dnssec_enabled: bool | None = None
    dnssec_cache_seconds: float | None = None
    typosquat_enabled: bool | None = None
    typosquat_max_distance: int | None = None
    typosquat_cooldown_minutes: float | None = None
    typosquat_action: str | None = None
    typosquat_redirect_ip: str | None = None
    dot_enabled: bool | None = None
    dot_port: int | None = None


class UpstreamsIn(BaseModel):
    upstreams: list[str]


class DomainUpstreamIn(BaseModel):
    name: str
    domains: list[str] = []
    upstreams: list[str] = []


class RewriteIn(BaseModel):
    name: str
    type: str
    value: str


class WebSettingsIn(BaseModel):
    listen_address: str | None = None
    listen_port: int | None = None
    theme: str | None = None
    https_enabled: bool | None = None
    https_cert_path: str | None = None
    https_key_path: str | None = None
    login_max_attempts: int | None = None
    login_lockout_minutes: float | None = None


class LoginIn(BaseModel):
    username: str
    password: str


class UserPermissionsIn(BaseModel):
    allowed_clients: list[str] = []
    allowed_groups: list[str] = []
    view_threat_intel: bool = False
    view_anomalies: bool = False
    can_block: bool = False
    can_whitelist: bool = False


class UserCreateIn(BaseModel):
    username: str
    password: str
    role: str = "user"
    permissions: UserPermissionsIn | None = None


class UserUpdateIn(BaseModel):
    password: str | None = None
    role: str | None = None
    permissions: UserPermissionsIn | None = None


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str


class ApiTokenIn(BaseModel):
    name: str


class TotpConfirmIn(BaseModel):
    code: str


class TotpDisableIn(BaseModel):
    password: str


class TotpLoginIn(BaseModel):
    totp_token: str
    code: str


class PasskeyLoginOptionsIn(BaseModel):
    totp_token: str


class PasskeyLoginVerifyIn(BaseModel):
    totp_token: str
    credential: dict[str, Any]


class PasskeyRegisterVerifyIn(BaseModel):
    token: str
    name: str = ""
    credential: dict[str, Any]


class LoggingSettingsIn(BaseModel):
    retention_days: float | None = None


class BlocklistSettingsIn(BaseModel):
    refresh_interval_hours: float | None = None


class PauseIn(BaseModel):
    seconds: float | None = None


class EnrichmentSettingsIn(BaseModel):
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    otx_api_key: str | None = None
    public_enabled: bool | None = None
    local_enabled: bool | None = None
    local_url: str | None = None
    local_api_key: str | None = None


class EnrichIn(BaseModel):
    target: str
    type: str


class AnomalySettingsIn(BaseModel):
    enabled: bool | None = None
    check_interval_minutes: float | None = None
    window_minutes: float | None = None
    min_queries: int | None = None
    blocked_ratio_threshold: float | None = None
    domain_burst_threshold: int | None = None
    domain_burst_min_entropy: float | None = None
    domain_burst_min_label_length: int | None = None
    domain_burst_entropy_fraction: float | None = None
    blocked_domain_burst_threshold: int | None = None
    dns_tunneling_threshold: int | None = None
    dns_tunneling_min_label_length: int | None = None
    dns_tunneling_min_entropy: float | None = None
    cooldown_minutes: float | None = None


class ReanalyzeIn(BaseModel):
    hours: float


class AlertRulesSettingsIn(BaseModel):
    check_interval_seconds: float | None = None
    cooldown_minutes: float | None = None


class NotificationEmailSettingsIn(BaseModel):
    enabled: bool | None = None
    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_security: str | None = None
    smtp_username: str | None = None
    smtp_password: str | None = None
    from_address: str | None = None
    to_addresses: list[str] | None = None
    min_severity: str | None = None


class NotificationWebhookIn(BaseModel):
    name: str | None = None
    type: str | None = None
    enabled: bool | None = None
    url: str | None = None
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None
    min_severity: str | None = None


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
) -> FastAPI:
    app = FastAPI(title="DNS-shield", docs_url=None, redoc_url=None)

    users = users if users is not None else UserStore(config_store)
    sessions = sessions if sessions is not None else SessionStore()
    login_throttle = LoginThrottle()
    pending_totp = PendingTotpStore()
    pending_challenges = PendingChallengeStore()

    def _webauthn_rp_id(request: Request) -> str:
        return request.url.hostname or "localhost"

    def _webauthn_origin(request: Request) -> str:
        return request.headers.get("origin") or f"{request.url.scheme}://{request.url.netloc}"

    NO_CACHE = {"Cache-Control": "no-cache"}

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
                client_ip = request.client.host if request.client else "unknown"
                audit_log.record(user["username"], f"{request.method} {request.url.path}", client_ip=client_ip)
        return response

    @app.get("/login")
    def login_page() -> FileResponse:
        return FileResponse(STATIC_DIR / "login.html", headers=NO_CACHE)

    @app.post("/api/login")
    def login(body: LoginIn, request: Request, response: Response) -> dict[str, Any]:
        client_ip = request.client.host if request.client else "unknown"
        max_attempts = int(config_store.get("web", "login_max_attempts", default=5) or 5)
        lockout_seconds = max(1.0, float(config_store.get("web", "login_lockout_minutes", default=15) or 15) * 60)
        login_throttle.configure(max_attempts, lockout_seconds)

        retry_after = login_throttle.retry_after(client_ip)
        if retry_after is not None:
            wait_seconds = int(retry_after) + 1
            raise HTTPException(
                status_code=429,
                detail=f"Too many failed login attempts - try again in {wait_seconds}s",
                headers={"Retry-After": str(wait_seconds)},
            )

        user = users.verify_login(body.username.strip(), body.password)
        if user is None:
            login_throttle.record_failure(client_ip)
            raise HTTPException(status_code=401, detail="Invalid username or password")

        if users.has_second_factor(user["username"]):
            totp_token = pending_totp.create(user["username"])
            return {
                "ok": True,
                "totp_required": True,
                "totp_token": totp_token,
                "totp_available": bool(user.get("totp_enabled")),
                "passkey_available": bool(user.get("webauthn_credentials")),
            }

        login_throttle.record_success(client_ip)
        token = sessions.create(user["username"])
        response.set_cookie(
            COOKIE_NAME,
            token,
            httponly=True,
            samesite="lax",
            secure=bool(config_store.get("web", "https_enabled", default=False)),
            max_age=7 * 24 * 3600,
            path="/",
        )
        if audit_log is not None:
            audit_log.record(user["username"], "login", client_ip=client_ip)
        return {"ok": True, "user": public_user(user)}

    @app.post("/api/login/totp")
    def login_totp(body: TotpLoginIn, request: Request, response: Response) -> dict[str, Any]:
        client_ip = request.client.host if request.client else "unknown"
        max_attempts = int(config_store.get("web", "login_max_attempts", default=5) or 5)
        lockout_seconds = max(1.0, float(config_store.get("web", "login_lockout_minutes", default=15) or 15) * 60)
        login_throttle.configure(max_attempts, lockout_seconds)

        retry_after = login_throttle.retry_after(client_ip)
        if retry_after is not None:
            wait_seconds = int(retry_after) + 1
            raise HTTPException(
                status_code=429,
                detail=f"Too many failed login attempts - try again in {wait_seconds}s",
                headers={"Retry-After": str(wait_seconds)},
            )

        username = pending_totp.username_for(body.totp_token)
        if username is None:
            raise HTTPException(status_code=401, detail="Login session expired - sign in again")

        if not users.verify_totp_or_backup_code(username, body.code):
            login_throttle.record_failure(client_ip)
            raise HTTPException(status_code=401, detail="Incorrect authenticator code")

        pending_totp.consume(body.totp_token)
        login_throttle.record_success(client_ip)
        user = users.get(username)
        token = sessions.create(username)
        response.set_cookie(
            COOKIE_NAME,
            token,
            httponly=True,
            samesite="lax",
            secure=bool(config_store.get("web", "https_enabled", default=False)),
            max_age=7 * 24 * 3600,
            path="/",
        )
        if audit_log is not None:
            audit_log.record(username, "login (2FA)", client_ip=client_ip)
        return {"ok": True, "user": public_user(user)}

    @app.post("/api/login/passkey/options")
    def login_passkey_options(body: PasskeyLoginOptionsIn, request: Request) -> dict[str, Any]:
        username = pending_totp.username_for(body.totp_token)
        if username is None:
            raise HTTPException(status_code=401, detail="Login session expired - sign in again")
        credential_ids = users.passkey_credential_ids(username)
        if not credential_ids:
            raise HTTPException(status_code=400, detail="No passkeys registered for this account")
        options_json, challenge = passkeys_lib.authentication_options_json(_webauthn_rp_id(request), credential_ids)
        pending_challenges.set(body.totp_token, username, challenge)
        return {"options": options_json}

    @app.post("/api/login/passkey/verify")
    def login_passkey_verify(body: PasskeyLoginVerifyIn, request: Request, response: Response) -> dict[str, Any]:
        client_ip = request.client.host if request.client else "unknown"
        max_attempts = int(config_store.get("web", "login_max_attempts", default=5) or 5)
        lockout_seconds = max(1.0, float(config_store.get("web", "login_lockout_minutes", default=15) or 15) * 60)
        login_throttle.configure(max_attempts, lockout_seconds)

        retry_after = login_throttle.retry_after(client_ip)
        if retry_after is not None:
            wait_seconds = int(retry_after) + 1
            raise HTTPException(
                status_code=429,
                detail=f"Too many failed login attempts - try again in {wait_seconds}s",
                headers={"Retry-After": str(wait_seconds)},
            )

        pending_username = pending_totp.username_for(body.totp_token)
        challenge_entry = pending_challenges.get(body.totp_token)
        if pending_username is None or challenge_entry is None or challenge_entry[0] != pending_username:
            raise HTTPException(status_code=401, detail="Login session expired - sign in again")
        username, challenge = challenge_entry

        credential_id = body.credential.get("id")
        passkey = users.find_passkey_by_credential_id(username, credential_id) if credential_id else None
        if passkey is None:
            login_throttle.record_failure(client_ip)
            raise HTTPException(status_code=401, detail="Unrecognized passkey")

        try:
            result = passkeys_lib.verify_authentication(
                credential=body.credential,
                expected_challenge=challenge,
                rp_id=_webauthn_rp_id(request),
                origin=_webauthn_origin(request),
                public_key=base64.b64decode(passkey["public_key"]),
                sign_count=passkey.get("sign_count", 0),
            )
        except Exception:
            login_throttle.record_failure(client_ip)
            raise HTTPException(status_code=401, detail="Passkey verification failed")

        users.record_passkey_use(username, passkey["credential_id"], result.new_sign_count)
        pending_totp.consume(body.totp_token)
        pending_challenges.pop(body.totp_token)
        login_throttle.record_success(client_ip)
        user = users.get(username)
        token = sessions.create(username)
        response.set_cookie(
            COOKIE_NAME,
            token,
            httponly=True,
            samesite="lax",
            secure=bool(config_store.get("web", "https_enabled", default=False)),
            max_age=7 * 24 * 3600,
            path="/",
        )
        if audit_log is not None:
            audit_log.record(username, "login (passkey)", client_ip=client_ip)
        return {"ok": True, "user": public_user(user)}

    @app.post("/api/logout")
    def logout(request: Request, response: Response) -> dict[str, Any]:
        user = _current_user(request)
        sessions.destroy(request.cookies.get(COOKIE_NAME))
        response.delete_cookie(COOKIE_NAME, path="/")
        if audit_log is not None and user is not None:
            client_ip = request.client.host if request.client else "unknown"
            audit_log.record(user["username"], "logout", client_ip=client_ip)
        return {"ok": True}

    @app.get("/api/whoami")
    def whoami(request: Request) -> dict[str, Any]:
        user = _current_user(request)
        enr = config_store.get("enrichment", default={}) or {}
        public_ready = bool(enr.get("public_enabled")) and any(
            enr.get(k) for k in ("virustotal_api_key", "abuseipdb_api_key", "otx_api_key")
        )
        local_ready = bool(enr.get("local_enabled")) and bool(enr.get("local_url"))
        return {
            "user": public_user(user) if user is not None else None,
            "enrichment_available": public_ready or local_ready,
        }

    @app.get("/api/public/summary")
    def public_summary() -> dict[str, Any]:
        snap = stats.snapshot(top_n=25, log_n=0)
        return {
            "top_blocked_domains": snap["top_blocked_domains"],
            "timeseries": stats.timeseries("24h"),
        }

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"status": "ok", "uptime_seconds": time.time() - started_at}

    @app.get("/metrics")
    def metrics() -> Response:
        body = render_metrics(stats, blocklist, started_at, cache=cache, anomaly=anomaly, dnssec_cache=dnssec_cache)
        return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")

    if resolver is not None:

        class _DoHHandler:
            __slots__ = ("client_address",)

            def __init__(self, client_ip: str) -> None:
                self.client_address = (client_ip, 0)

        def _doh_client_ip(request: Request) -> str:
            return request.client.host if request.client else "?"

        def _doh_respond(wire_bytes: bytes, client_ip: str) -> Response:
            try:
                dns_request = DNSRecord.parse(wire_bytes)
            except Exception:
                raise HTTPException(status_code=400, detail="Malformed DNS message")
            dns_response = resolver.resolve(dns_request, _DoHHandler(client_ip))
            return Response(content=bytes(dns_response.pack()), media_type="application/dns-message")

        @app.get("/dns-query")
        def doh_get(request: Request, dns: str = "") -> Response:
            if not dns:
                raise HTTPException(status_code=400, detail="Missing 'dns' query parameter")
            padded = dns + "=" * (-len(dns) % 4)
            try:
                wire_bytes = base64.urlsafe_b64decode(padded)
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid base64url encoding")
            return _doh_respond(wire_bytes, _doh_client_ip(request))

        @app.post("/dns-query")
        async def doh_post(request: Request) -> Response:
            wire_bytes = await request.body()
            return _doh_respond(wire_bytes, _doh_client_ip(request))

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html", headers=NO_CACHE)

    @app.get("/api/status")
    def status(_: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
        group_names = [g.get("name", "") for g in (config_store.get("client_groups", default=[]) or [])]
        return {
            "uptime_seconds": time.time() - started_at,
            "dns_listen": f"{config_store.get('dns', 'listen_address', default='0.0.0.0')}:"
            f"{config_store.get('dns', 'listen_port', default=53)}",
            "blocklist_domains": blocklist.total_count(),
            "blocklist_sources": blocklist.source_counts(),
            "blocklist_source_formats": blocklist.source_formats(),
            "blocklist_last_refresh": blocklist.last_refresh(),
            "allowlist_domains": blocklist.allowed_count(),
            "allowlist_sources": blocklist.allow_source_counts(),
            "allowlist_source_formats": blocklist.allow_source_formats(),
            "group_blocklist_domains": {n: blocklist.group_total_count(n) for n in group_names},
            "group_blocklist_sources": {n: blocklist.group_source_counts(n) for n in group_names},
            "group_blocklist_source_formats": {n: blocklist.group_source_formats(n) for n in group_names},
            "alert_domains": blocklist.alert_total_count(),
            "alert_sources": blocklist.alert_source_counts(),
            "alert_source_formats": blocklist.alert_source_formats(),
            "answer_ip_entries": blocklist.answer_ip_total_count(),
            "answer_ip_sources": blocklist.answer_ip_source_counts(),
            "answer_ip_source_formats": blocklist.answer_ip_source_formats(),
            "cache": cache.stats() if cache is not None else None,
            "upstream_stats": upstream_stats.snapshot() if upstream_stats is not None else {},
            "dnssec": {
                "enabled": bool(config_store.get("dns", "dnssec_enabled", default=False)),
                "cached_domains": dnssec_cache.counts() if dnssec_cache is not None else {"secure": 0, "insecure": 0},
            },
            "pause": {
                "active": blocklist.is_paused(),
                "until": config_store.get("pause", "until", default=None),
            },
        }

    @app.post("/api/pause")
    def pause_blocking(body: PauseIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            pause_cfg = data.setdefault("pause", {})
            pause_cfg["active"] = True
            pause_cfg["until"] = (time.time() + body.seconds) if body.seconds else None
            return pause_cfg

        return config_store.mutate(_mutate)

    @app.post("/api/resume")
    def resume_blocking(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            pause_cfg = data.setdefault("pause", {})
            pause_cfg["active"] = False
            pause_cfg["until"] = None
            return pause_cfg

        return config_store.mutate(_mutate)

    @app.get("/api/stats")
    def get_stats(
        top_n: int = 25, log_n: int = 200, user: dict[str, Any] = Depends(require_auth)
    ) -> dict[str, Any]:
        snapshot = stats.snapshot(top_n=top_n, log_n=log_n, client_ips=_allowed_client_ips(user))
        snapshot["client_names"] = client_names.snapshot() if client_names is not None else {}
        return snapshot

    @app.get("/api/stats/timeseries")
    def get_stats_timeseries(
        range: str = "24h", user: dict[str, Any] = Depends(require_auth)
    ) -> list[dict[str, Any]]:
        if range not in ("24h", "7d", "30d"):
            range = "24h"
        return stats.timeseries(range, client_ips=_allowed_client_ips(user))

    @app.get("/api/query-log")
    def get_query_log(
        domain: str | None = None,
        client: str | None = None,
        qtype: str | None = None,
        blocked: str | None = None,
        since: float | None = None,
        until: float | None = None,
        limit: int = 100,
        offset: int = 0,
        user: dict[str, Any] = Depends(require_auth),
    ) -> dict[str, Any]:
        blocked_bool: bool | None = None
        if blocked == "true":
            blocked_bool = True
        elif blocked == "false":
            blocked_bool = False

        client_ips: list[str] | None = None
        if client and client_names is not None:
            names = client_names.snapshot()
            matches = [ip for ip, name in names.items() if client.lower() in name.lower()]
            client_ips = matches or None

        rows, total = stats.query_log(
            domain=domain,
            client_like=client,
            client_ips=client_ips,
            qtype=qtype,
            blocked=blocked_bool,
            since=since,
            until=until,
            limit=max(1, min(limit, 1000)),
            offset=max(0, offset),
            restrict_client_ips=_allowed_client_ips(user),
        )
        return {
            "rows": rows,
            "total": total,
            "client_names": client_names.snapshot() if client_names is not None else {},
        }

    @app.delete("/api/query-log")
    def clear_query_log(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        stats.clear()
        return {"ok": True}

    @app.post("/api/cache/clear")
    def clear_cache(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        if cache is None:
            raise HTTPException(status_code=404, detail="Cache is disabled")
        cache.clear()
        return {"ok": True}

    def _list_sources(field: str) -> list[dict[str, Any]]:
        return config_store.get("blocklists", field, default=[]) or []

    def _add_source(field: str, source: BlocklistSourceIn) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            sources = data.setdefault("blocklists", {}).setdefault(field, [])
            sources.append(source.model_dump())
            return sources

        result = config_store.mutate(_mutate)
        blocklist.refresh()
        return result

    def _delete_source(field: str, index: int) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            sources = data.setdefault("blocklists", {}).setdefault(field, [])
            if not 0 <= index < len(sources):
                raise HTTPException(status_code=404, detail="No such list")
            sources.pop(index)
            return sources

        result = config_store.mutate(_mutate)
        blocklist.refresh()
        return result

    def _toggle_source(field: str, index: int) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            sources = data.setdefault("blocklists", {}).setdefault(field, [])
            if not 0 <= index < len(sources):
                raise HTTPException(status_code=404, detail="No such list")
            sources[index]["enabled"] = not sources[index].get("enabled", True)
            return sources

        result = config_store.mutate(_mutate)
        blocklist.refresh()
        return result

    @app.get("/api/blocklists")
    def list_blocklists(_: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return _list_sources("sources")

    @app.post("/api/blocklists")
    def add_blocklist(source: BlocklistSourceIn, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return _add_source("sources", source)

    @app.delete("/api/blocklists/{index}")
    def delete_blocklist(index: int, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return _delete_source("sources", index)

    @app.post("/api/blocklists/{index}/toggle")
    def toggle_blocklist(index: int, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return _toggle_source("sources", index)

    @app.get("/api/allow-sources")
    def list_allow_sources(_: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return _list_sources("allow_sources")

    @app.post("/api/allow-sources")
    def add_allow_source(source: BlocklistSourceIn, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return _add_source("allow_sources", source)

    @app.delete("/api/allow-sources/{index}")
    def delete_allow_source(index: int, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return _delete_source("allow_sources", index)

    @app.post("/api/allow-sources/{index}/toggle")
    def toggle_allow_source(index: int, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return _toggle_source("allow_sources", index)

    @app.get("/api/blocklists/catalog")
    def get_blocklist_catalog(_: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        existing_urls = {s.get("url") for s in _list_sources("sources")}
        return [entry for entry in BLOCKLIST_CATALOG if entry["url"] not in existing_urls]

    @app.post("/api/blocklists/refresh")
    def refresh_blocklists(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        blocklist.refresh()
        return {"ok": True, "domains": blocklist.total_count(), "allowed": blocklist.allowed_count()}

    @app.get("/api/rules")
    def get_rules(_: dict[str, Any] = Depends(require_auth)) -> dict[str, list[str]]:
        return {
            "allowlist": config_store.get("allowlist", default=[]) or [],
            "denylist": config_store.get("denylist", default=[]) or [],
            "denylist_regex": config_store.get("denylist_regex", default=[]) or [],
            "blocked_clients": config_store.get("blocked_clients", default=[]) or [],
            "blocked_answer_ips": config_store.get("blocked_answer_ips", default=[]) or [],
        }

    def _add_rule(list_name: str, value: str, label: str = "domain") -> list[str]:
        value = value.strip().lower().rstrip(".")
        if not value:
            raise HTTPException(status_code=400, detail=f"Empty {label}")

        def _mutate(data: dict[str, Any]) -> list[str]:
            items = data.setdefault(list_name, [])
            if value not in items:
                items.append(value)
            return items

        return config_store.mutate(_mutate)

    def _remove_rule(list_name: str, value: str) -> list[str]:
        value = value.strip().lower().rstrip(".")

        def _mutate(data: dict[str, Any]) -> list[str]:
            items = data.setdefault(list_name, [])
            if value in items:
                items.remove(value)
            return items

        return config_store.mutate(_mutate)

    @app.post("/api/rules/allow")
    def add_allow(body: DomainIn, _: dict[str, Any] = Depends(require_permission("can_whitelist"))) -> list[str]:
        return _add_rule("allowlist", body.domain)

    @app.delete("/api/rules/allow/{domain}")
    def remove_allow(domain: str, _: dict[str, Any] = Depends(require_permission("can_whitelist"))) -> list[str]:
        return _remove_rule("allowlist", domain)

    @app.post("/api/rules/deny")
    def add_deny(body: DomainIn, _: dict[str, Any] = Depends(require_permission("can_block"))) -> list[str]:
        return _add_rule("denylist", body.domain)

    @app.delete("/api/rules/deny/{domain}")
    def remove_deny(domain: str, _: dict[str, Any] = Depends(require_permission("can_block"))) -> list[str]:
        return _remove_rule("denylist", domain)

    @app.post("/api/rules/deny-regex")
    def add_deny_regex(body: RegexPatternIn, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        pattern = body.pattern.strip()
        if not pattern:
            raise HTTPException(status_code=400, detail="Empty pattern")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise HTTPException(status_code=400, detail=f"Invalid regex: {exc}") from exc

        def _mutate(data: dict[str, Any]) -> list[str]:
            items = data.setdefault("denylist_regex", [])
            if pattern not in items:
                items.append(pattern)
            return items

        return config_store.mutate(_mutate)

    @app.delete("/api/rules/deny-regex/{pattern}")
    def remove_deny_regex(pattern: str, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        def _mutate(data: dict[str, Any]) -> list[str]:
            items = data.setdefault("denylist_regex", [])
            if pattern in items:
                items.remove(pattern)
            return items

        return config_store.mutate(_mutate)

    @app.post("/api/rules/deny-client")
    def add_deny_client(body: ValueIn, _: dict[str, Any] = Depends(require_permission("can_block"))) -> list[str]:
        return _add_rule("blocked_clients", body.value, label="client")

    @app.delete("/api/rules/deny-client/{client}")
    def remove_deny_client(client: str, _: dict[str, Any] = Depends(require_permission("can_block"))) -> list[str]:
        return _remove_rule("blocked_clients", client)

    @app.post("/api/rules/deny-answer-ip")
    def add_deny_answer_ip(body: ValueIn, _: dict[str, Any] = Depends(require_permission("can_block"))) -> list[str]:
        result = _add_rule("blocked_answer_ips", body.value, label="IP")
        blocklist.refresh()
        return result

    @app.delete("/api/rules/deny-answer-ip/{value}")
    def remove_deny_answer_ip(value: str, _: dict[str, Any] = Depends(require_permission("can_block"))) -> list[str]:
        result = _remove_rule("blocked_answer_ips", value)
        blocklist.refresh()
        return result

    @app.get("/api/answer-ip-sources")
    def list_answer_ip_sources(_: dict[str, Any] = Depends(require_permission("can_block"))) -> list[dict[str, Any]]:
        return config_store.get("blocked_answer_ip_sources", default=[]) or []

    @app.post("/api/answer-ip-sources")
    def add_answer_ip_source(
        source: BlocklistSourceIn, _: dict[str, Any] = Depends(require_permission("can_block"))
    ) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            sources = data.setdefault("blocked_answer_ip_sources", [])
            sources.append(source.model_dump())
            return sources

        result = config_store.mutate(_mutate)
        blocklist.refresh()
        return result

    @app.delete("/api/answer-ip-sources/{index}")
    def delete_answer_ip_source(
        index: int, _: dict[str, Any] = Depends(require_permission("can_block"))
    ) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            sources = data.setdefault("blocked_answer_ip_sources", [])
            if not 0 <= index < len(sources):
                raise HTTPException(status_code=404, detail="No such list")
            sources.pop(index)
            return sources

        result = config_store.mutate(_mutate)
        blocklist.refresh()
        return result

    @app.post("/api/answer-ip-sources/{index}/toggle")
    def toggle_answer_ip_source(
        index: int, _: dict[str, Any] = Depends(require_permission("can_block"))
    ) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            sources = data.setdefault("blocked_answer_ip_sources", [])
            if not 0 <= index < len(sources):
                raise HTTPException(status_code=404, detail="No such list")
            sources[index]["enabled"] = not sources[index].get("enabled", True)
            return sources

        result = config_store.mutate(_mutate)
        blocklist.refresh()
        return result

    def _add_nested_rule(section: str, list_name: str, value: str) -> list[str]:
        if not value.strip():
            raise HTTPException(status_code=400, detail="Empty value")

        def _mutate(data: dict[str, Any]) -> list[str]:
            items = data.setdefault(section, {}).setdefault(list_name, [])
            if value not in items:
                items.append(value)
            return items

        return config_store.mutate(_mutate)

    def _remove_nested_rule(section: str, list_name: str, value: str) -> list[str]:
        def _mutate(data: dict[str, Any]) -> list[str]:
            items = data.setdefault(section, {}).setdefault(list_name, [])
            if value in items:
                items.remove(value)
            return items

        return config_store.mutate(_mutate)

    @app.get("/api/log-ignore")
    def get_log_ignore(_: dict[str, Any] = Depends(require_admin)) -> dict[str, list[str]]:
        return {
            "domains": config_store.get("logging", "ignored_domains", default=[]) or [],
            "clients": config_store.get("logging", "ignored_clients", default=[]) or [],
        }

    @app.post("/api/log-ignore/domains")
    def add_ignored_domain(body: DomainIn, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        return _add_nested_rule("logging", "ignored_domains", body.domain.strip().lower().rstrip("."))

    @app.delete("/api/log-ignore/domains/{value}")
    def remove_ignored_domain(value: str, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        return _remove_nested_rule("logging", "ignored_domains", value.strip().lower().rstrip("."))

    @app.post("/api/log-ignore/clients")
    def add_ignored_client(body: ValueIn, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        return _add_nested_rule("logging", "ignored_clients", body.value.strip())

    @app.delete("/api/log-ignore/clients/{value}")
    def remove_ignored_client(value: str, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        return _remove_nested_rule("logging", "ignored_clients", value.strip())

    @app.get("/api/typosquat-domains")
    def get_typosquat_domains(_: dict[str, Any] = Depends(require_admin)) -> dict[str, list[str]]:
        return {
            "default": list(DEFAULT_PROTECTED_DOMAINS),
            "extra": config_store.get("dns", "typosquat_extra_domains", default=[]) or [],
        }

    @app.post("/api/typosquat-domains")
    def add_typosquat_domain(body: DomainIn, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        result = _add_nested_rule("dns", "typosquat_extra_domains", body.domain.strip().lower().rstrip("."))
        blocklist.clear_typosquat_cache()
        return result

    @app.delete("/api/typosquat-domains/{value}")
    def remove_typosquat_domain(value: str, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        result = _remove_nested_rule("dns", "typosquat_extra_domains", value.strip().lower().rstrip("."))
        blocklist.clear_typosquat_cache()
        return result

    @app.get("/api/client-groups")
    def list_client_groups(_: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return config_store.get("client_groups", default=[]) or []

    @app.post("/api/client-groups")
    def add_client_group(group: ClientGroupIn, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            groups = data.setdefault("client_groups", [])
            groups.append(group.model_dump())
            return groups

        return config_store.mutate(_mutate)

    @app.delete("/api/client-groups/{index}")
    def delete_client_group(index: int, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            groups = data.setdefault("client_groups", [])
            if not 0 <= index < len(groups):
                raise HTTPException(status_code=404, detail="No such client group")
            groups.pop(index)
            return groups

        return config_store.mutate(_mutate)

    @app.post("/api/client-groups/{index}/toggle")
    def toggle_client_group(index: int, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            groups = data.setdefault("client_groups", [])
            if not 0 <= index < len(groups):
                raise HTTPException(status_code=404, detail="No such client group")
            groups[index]["enabled"] = not groups[index].get("enabled", True)
            return groups

        return config_store.mutate(_mutate)

    def _group_mutate(index: int, fn) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            groups = data.setdefault("client_groups", [])
            if not 0 <= index < len(groups):
                raise HTTPException(status_code=404, detail="No such client group")
            return fn(groups[index])

        return config_store.mutate(_mutate)

    def _add_group_rule(index: int, list_name: str, domain: str) -> dict[str, Any]:
        domain = domain.strip().lower().rstrip(".")
        if not domain:
            raise HTTPException(status_code=400, detail="Empty domain")

        def _fn(group: dict[str, Any]) -> dict[str, Any]:
            items = group.setdefault(list_name, [])
            if domain not in items:
                items.append(domain)
            return group

        return _group_mutate(index, _fn)

    def _remove_group_rule(index: int, list_name: str, domain: str) -> dict[str, Any]:
        domain = domain.strip().lower().rstrip(".")

        def _fn(group: dict[str, Any]) -> dict[str, Any]:
            items = group.setdefault(list_name, [])
            if domain in items:
                items.remove(domain)
            return group

        return _group_mutate(index, _fn)

    @app.post("/api/client-groups/{index}/allow")
    def add_group_allow(index: int, body: DomainIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        return _add_group_rule(index, "allowlist", body.domain)

    @app.delete("/api/client-groups/{index}/allow/{domain}")
    def remove_group_allow(index: int, domain: str, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        return _remove_group_rule(index, "allowlist", domain)

    @app.post("/api/client-groups/{index}/deny")
    def add_group_deny(index: int, body: DomainIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        return _add_group_rule(index, "denylist", body.domain)

    @app.delete("/api/client-groups/{index}/deny/{domain}")
    def remove_group_deny(index: int, domain: str, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        return _remove_group_rule(index, "denylist", domain)

    @app.put("/api/client-groups/{index}/upstreams")
    def set_group_upstreams(index: int, body: UpstreamsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _fn(group: dict[str, Any]) -> dict[str, Any]:
            group["upstreams"] = body.upstreams
            return group

        return _group_mutate(index, _fn)

    @app.put("/api/client-groups/{index}/safe-search")
    def set_group_safe_search(
        index: int, body: GroupSafeSearchIn, _: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        def _fn(group: dict[str, Any]) -> dict[str, Any]:
            group["safe_search"] = body.safe_search
            return group

        return _group_mutate(index, _fn)

    @app.put("/api/client-groups/{index}/schedule")
    def set_group_schedule(
        index: int, body: GroupScheduleIn, _: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        def _fn(group: dict[str, Any]) -> dict[str, Any]:
            group["schedule"] = {
                "enabled": body.enabled,
                "timezone": body.timezone.strip(),
                "windows": [
                    {"days": sorted({d for d in w.days if 0 <= d <= 6}), "start": w.start.strip(), "end": w.end.strip()}
                    for w in body.windows
                ],
            }
            return group

        return _group_mutate(index, _fn)

    def _group_source_mutate(index: int, fn) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            groups = data.setdefault("client_groups", [])
            if not 0 <= index < len(groups):
                raise HTTPException(status_code=404, detail="No such client group")
            sources = groups[index].setdefault("blocklist_sources", [])
            return fn(sources)

        result = config_store.mutate(_mutate)
        blocklist.refresh()
        return result

    @app.get("/api/client-groups/{index}/blocklist-sources")
    def list_group_blocklist_sources(index: int, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        groups = config_store.get("client_groups", default=[]) or []
        if not 0 <= index < len(groups):
            raise HTTPException(status_code=404, detail="No such client group")
        return groups[index].get("blocklist_sources", []) or []

    @app.post("/api/client-groups/{index}/blocklist-sources")
    def add_group_blocklist_source(
        index: int, source: BlocklistSourceIn, _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        def _fn(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
            sources.append(source.model_dump())
            return sources

        return _group_source_mutate(index, _fn)

    @app.delete("/api/client-groups/{index}/blocklist-sources/{source_index}")
    def delete_group_blocklist_source(
        index: int, source_index: int, _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        def _fn(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
            if not 0 <= source_index < len(sources):
                raise HTTPException(status_code=404, detail="No such list")
            sources.pop(source_index)
            return sources

        return _group_source_mutate(index, _fn)

    @app.post("/api/client-groups/{index}/blocklist-sources/{source_index}/toggle")
    def toggle_group_blocklist_source(
        index: int, source_index: int, _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        def _fn(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
            if not 0 <= source_index < len(sources):
                raise HTTPException(status_code=404, detail="No such list")
            sources[source_index]["enabled"] = not sources[source_index].get("enabled", True)
            return sources

        return _group_source_mutate(index, _fn)

    @app.get("/api/domain-upstreams")
    def list_domain_upstreams(_: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return config_store.get("domain_upstreams", default=[]) or []

    @app.post("/api/domain-upstreams")
    def add_domain_upstream(rule: DomainUpstreamIn, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            rules = data.setdefault("domain_upstreams", [])
            rules.append(rule.model_dump())
            return rules

        return config_store.mutate(_mutate)

    @app.delete("/api/domain-upstreams/{index}")
    def delete_domain_upstream(index: int, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            rules = data.setdefault("domain_upstreams", [])
            if not 0 <= index < len(rules):
                raise HTTPException(status_code=404, detail="No such rule")
            rules.pop(index)
            return rules

        return config_store.mutate(_mutate)

    @app.get("/api/rewrites")
    def list_rewrites(_: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return config_store.get("dns_rewrites", default=[]) or []

    @app.post("/api/rewrites")
    def add_rewrite(rewrite: RewriteIn, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        name = rewrite.name.strip().lower().rstrip(".")
        rtype = rewrite.type.strip().upper()
        value = rewrite.value.strip()
        if not name or not value:
            raise HTTPException(status_code=400, detail="Name and value are required")
        if rtype not in ("A", "AAAA"):
            raise HTTPException(status_code=400, detail='Type must be "A" or "AAAA"')

        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            rewrites = data.setdefault("dns_rewrites", [])
            rewrites.append({"name": name, "type": rtype, "value": value})
            return rewrites

        return config_store.mutate(_mutate)

    @app.delete("/api/rewrites/{index}")
    def delete_rewrite(index: int, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            rewrites = data.setdefault("dns_rewrites", [])
            if not 0 <= index < len(rewrites):
                raise HTTPException(status_code=404, detail="No such rewrite")
            rewrites.pop(index)
            return rewrites

        return config_store.mutate(_mutate)

    @app.post("/api/import/adguard")
    def import_adguard(file: UploadFile = File(...), _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        raw = file.file.read()
        try:
            adguard = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise HTTPException(status_code=400, detail=f"Not valid YAML: {exc}") from exc
        if not isinstance(adguard, dict):
            raise HTTPException(status_code=400, detail="Doesn't look like an AdGuardHome.yaml (not a YAML mapping)")

        result, warnings = import_config(adguard, config_store.snapshot())

        def _mutate(data: dict[str, Any]) -> None:
            data.clear()
            data.update(result)

        config_store.mutate(_mutate)
        blocklist.refresh()

        return {"ok": True, "warnings": warnings}

    @app.post("/api/import/pihole")
    def import_pihole(file: UploadFile = File(...), _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        raw = file.file.read()
        with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
            tmp.write(raw)
            tmp.flush()
            try:
                result, warnings = import_pihole_config(Path(tmp.name), config_store.snapshot())
            except sqlite3.DatabaseError as exc:
                raise HTTPException(status_code=400, detail=f"Not a valid gravity.db (SQLite file): {exc}") from exc

        def _mutate(data: dict[str, Any]) -> None:
            data.clear()
            data.update(result)

        config_store.mutate(_mutate)
        blocklist.refresh()

        return {"ok": True, "warnings": warnings}

    _EXPORT_README = """DNS-shield configuration backup
================================

config.yaml is a full snapshot of this instance's config.db at the time of
export: blocklists, allow/deny rules, client groups, DNS/web settings,
custom DNS records - and yes, any threat-intel API keys in plain text and
every user's bcrypt password hash (same as data/config.backup.yaml already
on disk). A bcrypt hash can't be turned back into the original password,
but treat this file like a password anyway: back it up somewhere you'd
store a password, not somewhere public.

To restore into a FRESH instance (no data/config.db yet):
  cp config.yaml <your data volume>/config.backup.yaml
  # then start the container as usual - it seeds config.db from that file

To restore into an EXISTING instance (data/config.db already exists):
  docker compose down
  cp config.yaml <your data volume>/config.backup.yaml
  rm <your data volume>/config.db <your data volume>/config.db-wal <your data volume>/config.db-shm
  docker compose up -d
"""

    @app.get("/api/export")
    def export_config(_: dict[str, Any] = Depends(require_admin)) -> Response:
        snap = config_store.snapshot()
        config_yaml = yaml.safe_dump(snap, sort_keys=False)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("config.yaml", config_yaml)
            zf.writestr("README.txt", _EXPORT_README)

        filename = f"dnsshield-backup-{time.strftime('%Y%m%d-%H%M%S')}.zip"
        return Response(
            content=buf.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.post("/api/import/backup")
    def import_backup(file: UploadFile = File(...), _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        raw = file.file.read()
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                config_yaml = zf.read("config.yaml")
        except zipfile.BadZipFile as exc:
            raise HTTPException(status_code=400, detail=f"Not a valid zip file: {exc}") from exc
        except KeyError as exc:
            raise HTTPException(
                status_code=400, detail="Not a DNS-shield backup - no config.yaml inside this zip"
            ) from exc

        try:
            result = yaml.safe_load(config_yaml)
        except yaml.YAMLError as exc:
            raise HTTPException(status_code=400, detail=f"config.yaml in this backup isn't valid YAML: {exc}") from exc
        if not isinstance(result, dict):
            raise HTTPException(status_code=400, detail="config.yaml in this backup isn't a YAML mapping")

        def _mutate(data: dict[str, Any]) -> None:
            data.clear()
            data.update(result)

        config_store.mutate(_mutate)
        blocklist.refresh()
        users.ensure_default_admin()

        return {"ok": True}

    RESTART_NOTE = "Changing this requires restarting the container (docker compose restart)."

    @app.get("/api/settings")
    def get_settings(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        snap = config_store.snapshot()
        dns_cfg = dict(snap.get("dns", {}))
        upstreams = dns_cfg.pop("upstreams", [])
        web_cfg = snap.get("web", {})
        return {
            "dns": dns_cfg,
            "upstreams": upstreams,
            "web": {
                "listen_address": web_cfg.get("listen_address"),
                "listen_port": web_cfg.get("listen_port"),
                "theme": web_cfg.get("theme", "navy"),
                "https_enabled": bool(web_cfg.get("https_enabled", False)),
                "https_cert_path": web_cfg.get("https_cert_path", "") or "",
                "https_key_path": web_cfg.get("https_key_path", "") or "",
                "login_max_attempts": web_cfg.get("login_max_attempts", 5),
                "login_lockout_minutes": web_cfg.get("login_lockout_minutes", 15),
            },
            "logging": snap.get("logging", {}),
            "blocklists_refresh_interval_hours": snap.get("blocklists", {}).get("refresh_interval_hours", 24),
            "enrichment": {
                "virustotal_api_key_set": bool(snap.get("enrichment", {}).get("virustotal_api_key")),
                "virustotal_api_key_preview": _masked_key_preview(snap.get("enrichment", {}).get("virustotal_api_key")),
                "abuseipdb_api_key_set": bool(snap.get("enrichment", {}).get("abuseipdb_api_key")),
                "abuseipdb_api_key_preview": _masked_key_preview(snap.get("enrichment", {}).get("abuseipdb_api_key")),
                "otx_api_key_set": bool(snap.get("enrichment", {}).get("otx_api_key")),
                "otx_api_key_preview": _masked_key_preview(snap.get("enrichment", {}).get("otx_api_key")),
                "public_enabled": bool(snap.get("enrichment", {}).get("public_enabled", False)),
                "local_enabled": bool(snap.get("enrichment", {}).get("local_enabled", False)),
                "local_url": snap.get("enrichment", {}).get("local_url", "") or "",
                "local_api_key_set": bool(snap.get("enrichment", {}).get("local_api_key")),
                "local_api_key_preview": _masked_key_preview(snap.get("enrichment", {}).get("local_api_key")),
            },
            "anomaly": _anomaly_settings(snap.get("anomaly", {})),
            "alert_rules": _alert_rules_settings(snap.get("alert_rules", {})),
            "notifications": {
                "email": _notification_email_settings(snap.get("notifications", {}).get("email", {})),
                "webhooks": [
                    _notification_webhook_public(w) for w in (snap.get("notifications", {}).get("webhooks", []) or [])
                ],
            },
            "restart_required": [
                "dns.listen_address",
                "dns.listen_port",
                "web.listen_address",
                "web.listen_port",
                "dns.block_page_enabled",
                "dns.block_page_port",
                "web.https_enabled",
                "web.https_cert_path",
                "web.https_key_path",
                "dns.dot_enabled",
                "dns.dot_port",
            ],
            "restart_note": RESTART_NOTE,
        }

    @app.patch("/api/settings/dns")
    def update_dns_settings(body: DnsSettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            dns_cfg = data.setdefault("dns", {})
            dns_cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return {k: v for k, v in dns_cfg.items() if k != "upstreams"}

        return config_store.mutate(_mutate)

    @app.put("/api/settings/upstreams")
    def update_upstreams(body: UpstreamsIn, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        upstreams = [u.strip() for u in body.upstreams if u.strip()]

        def _mutate(data: dict[str, Any]) -> list[str]:
            data.setdefault("dns", {})["upstreams"] = upstreams
            return data["dns"]["upstreams"]

        return config_store.mutate(_mutate)

    @app.post("/api/settings/upstreams/{index}/toggle")
    def toggle_upstream(index: int, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        def _mutate(data: dict[str, Any]) -> list[str]:
            upstreams = data.setdefault("dns", {}).setdefault("upstreams", [])
            if not 0 <= index < len(upstreams):
                raise HTTPException(status_code=404, detail="No such upstream")
            entry = upstreams[index]
            upstreams[index] = upstream_address(entry) if upstream_is_disabled(entry) else "#" + entry.strip()
            return upstreams

        return config_store.mutate(_mutate)

    @app.delete("/api/settings/upstreams/{index}")
    def delete_upstream(index: int, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        def _mutate(data: dict[str, Any]) -> list[str]:
            upstreams = data.setdefault("dns", {}).setdefault("upstreams", [])
            if not 0 <= index < len(upstreams):
                raise HTTPException(status_code=404, detail="No such upstream")
            upstreams.pop(index)
            return upstreams

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/web")
    def update_web_settings(body: WebSettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            web_cfg = data.setdefault("web", {})
            payload = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
            web_cfg.update(payload)
            return web_cfg

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/logging")
    def update_logging_settings(body: LoggingSettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            logging_cfg = data.setdefault("logging", {})
            logging_cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return logging_cfg

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/blocklists")
    def update_blocklist_settings(body: BlocklistSettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            bl_cfg = data.setdefault("blocklists", {})
            bl_cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return {k: v for k, v in bl_cfg.items() if k not in ("sources", "allow_sources")}

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/enrichment")
    def update_enrichment_settings(body: EnrichmentSettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        keep_if_blank = {"virustotal_api_key", "abuseipdb_api_key", "otx_api_key", "local_api_key"}
        data_in = body.model_dump(exclude_unset=True)
        payload = {k: v for k, v in data_in.items() if (v if k in keep_if_blank else v is not None)}

        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            data.setdefault("enrichment", {}).update(payload)
            enr = data["enrichment"]
            return {
                "virustotal_api_key_set": bool(enr.get("virustotal_api_key")),
                "virustotal_api_key_preview": _masked_key_preview(enr.get("virustotal_api_key")),
                "abuseipdb_api_key_set": bool(enr.get("abuseipdb_api_key")),
                "abuseipdb_api_key_preview": _masked_key_preview(enr.get("abuseipdb_api_key")),
                "otx_api_key_set": bool(enr.get("otx_api_key")),
                "otx_api_key_preview": _masked_key_preview(enr.get("otx_api_key")),
                "public_enabled": bool(enr.get("public_enabled", False)),
                "local_enabled": bool(enr.get("local_enabled", False)),
                "local_url": enr.get("local_url", "") or "",
                "local_api_key_set": bool(enr.get("local_api_key")),
                "local_api_key_preview": _masked_key_preview(enr.get("local_api_key")),
            }

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/anomaly")
    def update_anomaly_settings(body: AnomalySettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            anomaly_cfg = data.setdefault("anomaly", {})
            anomaly_cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return _anomaly_settings(anomaly_cfg)

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/alert-rules")
    def update_alert_rules_settings(body: AlertRulesSettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            cfg = data.setdefault("alert_rules", {})
            cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return _alert_rules_settings(cfg)

        return config_store.mutate(_mutate)

    def _add_alert_domain(domain: str) -> list[str]:
        domain = domain.strip().lower().rstrip(".")
        if not domain:
            raise HTTPException(status_code=400, detail="Empty domain")

        def _mutate(data: dict[str, Any]) -> list[str]:
            domains = data.setdefault("alert_rules", {}).setdefault("domains", [])
            if domain not in domains:
                domains.append(domain)
            return domains

        result = config_store.mutate(_mutate)
        blocklist.refresh()
        return result

    def _remove_alert_domain(domain: str) -> list[str]:
        domain = domain.strip().lower().rstrip(".")

        def _mutate(data: dict[str, Any]) -> list[str]:
            domains = data.setdefault("alert_rules", {}).setdefault("domains", [])
            if domain in domains:
                domains.remove(domain)
            return domains

        result = config_store.mutate(_mutate)
        blocklist.refresh()
        return result

    @app.get("/api/alert-rules/domains")
    def list_alert_domains(_: dict[str, Any] = Depends(require_admin)) -> list[str]:
        return config_store.get("alert_rules", "domains", default=[]) or []

    @app.post("/api/alert-rules/domains")
    def add_alert_domain(body: DomainIn, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        return _add_alert_domain(body.domain)

    @app.delete("/api/alert-rules/domains/{domain}")
    def remove_alert_domain(domain: str, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        return _remove_alert_domain(domain)

    @app.get("/api/alert-rules/sources")
    def list_alert_sources(_: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return config_store.get("alert_rules", "sources", default=[]) or []

    @app.post("/api/alert-rules/sources")
    def add_alert_source(source: BlocklistSourceIn, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            sources = data.setdefault("alert_rules", {}).setdefault("sources", [])
            sources.append(source.model_dump())
            return sources

        result = config_store.mutate(_mutate)
        blocklist.refresh()
        return result

    @app.delete("/api/alert-rules/sources/{index}")
    def delete_alert_source(index: int, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            sources = data.setdefault("alert_rules", {}).setdefault("sources", [])
            if not 0 <= index < len(sources):
                raise HTTPException(status_code=404, detail="No such list")
            sources.pop(index)
            return sources

        result = config_store.mutate(_mutate)
        blocklist.refresh()
        return result

    @app.post("/api/alert-rules/sources/{index}/toggle")
    def toggle_alert_source(index: int, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            sources = data.setdefault("alert_rules", {}).setdefault("sources", [])
            if not 0 <= index < len(sources):
                raise HTTPException(status_code=404, detail="No such list")
            sources[index]["enabled"] = not sources[index].get("enabled", True)
            return sources

        result = config_store.mutate(_mutate)
        blocklist.refresh()
        return result

    @app.patch("/api/settings/notifications/email")
    def update_notification_email_settings(
        body: NotificationEmailSettingsIn, _: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        data_in = body.model_dump(exclude_unset=True)
        payload = {k: v for k, v in data_in.items() if (v if k == "smtp_password" else v is not None)}

        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            email_cfg = data.setdefault("notifications", {}).setdefault("email", {})
            email_cfg.update(payload)
            return _notification_email_settings(email_cfg)

        return config_store.mutate(_mutate)

    @app.post("/api/notifications/test-email")
    def send_test_email(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        if notifications is None:
            raise HTTPException(status_code=503, detail="Notifications are not available")
        try:
            notifications.send_test_email()
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"ok": True}

    @app.post("/api/settings/notifications/webhooks")
    def add_notification_webhook(
        body: NotificationWebhookIn, _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        if body.type not in ("discord", "slack", "telegram"):
            raise HTTPException(status_code=400, detail="type must be discord, slack, or telegram")
        entry = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
        entry.setdefault("enabled", True)
        entry.setdefault("min_severity", "medium")

        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            webhooks = data.setdefault("notifications", {}).setdefault("webhooks", [])
            webhooks.append(entry)
            return [_notification_webhook_public(w) for w in webhooks]

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/notifications/webhooks/{index}")
    def update_notification_webhook(
        index: int, body: NotificationWebhookIn, _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        data_in = body.model_dump(exclude_unset=True)
        payload = {
            k: v for k, v in data_in.items() if (v if k in ("url", "telegram_bot_token") else v is not None)
        }

        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            webhooks = data.setdefault("notifications", {}).setdefault("webhooks", [])
            if not 0 <= index < len(webhooks):
                raise HTTPException(status_code=404, detail="No such webhook")
            webhooks[index].update(payload)
            return [_notification_webhook_public(w) for w in webhooks]

        return config_store.mutate(_mutate)

    @app.delete("/api/settings/notifications/webhooks/{index}")
    def delete_notification_webhook(index: int, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            webhooks = data.setdefault("notifications", {}).setdefault("webhooks", [])
            if not 0 <= index < len(webhooks):
                raise HTTPException(status_code=404, detail="No such webhook")
            webhooks.pop(index)
            return [_notification_webhook_public(w) for w in webhooks]

        return config_store.mutate(_mutate)

    @app.post("/api/settings/notifications/webhooks/{index}/toggle")
    def toggle_notification_webhook(index: int, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            webhooks = data.setdefault("notifications", {}).setdefault("webhooks", [])
            if not 0 <= index < len(webhooks):
                raise HTTPException(status_code=404, detail="No such webhook")
            webhooks[index]["enabled"] = not webhooks[index].get("enabled", True)
            return [_notification_webhook_public(w) for w in webhooks]

        return config_store.mutate(_mutate)

    @app.post("/api/notifications/test-webhook/{index}")
    def send_test_webhook(index: int, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        if notifications is None:
            raise HTTPException(status_code=503, detail="Notifications are not available")
        try:
            notifications.send_test_webhook(index)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"ok": True}

    @app.get("/api/anomalies")
    def list_anomalies(
        include_acknowledged: bool = True,
        limit: int = 200,
        user: dict[str, Any] = Depends(require_permission("view_anomalies")),
    ) -> list[dict[str, Any]]:
        if anomaly is None:
            return []
        rows = anomaly.list(include_acknowledged=include_acknowledged, limit=max(1, min(limit, 1000)))
        allowed = _allowed_client_ips(user)
        if allowed is not None:
            rows = [r for r in rows if r.get("client") in allowed]
        return rows

    @app.get("/api/anomalies/count")
    def anomalies_count(_: dict[str, Any] = Depends(require_permission("view_anomalies"))) -> dict[str, int]:
        return {"unacknowledged": anomaly.unacknowledged_count() if anomaly is not None else 0}

    @app.post("/api/anomalies/check-now")
    def anomalies_check_now(_: dict[str, Any] = Depends(require_permission("view_anomalies"))) -> list[dict[str, Any]]:
        if anomaly is None:
            return []
        return anomaly.check_once()

    @app.post("/api/anomalies/reanalyze")
    def anomalies_reanalyze(body: ReanalyzeIn, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        if anomaly is None:
            return []
        hours = max(1.0, min(body.hours, 24 * 30))
        return anomaly.reanalyze(hours)

    @app.get("/api/anomalies/{anomaly_id}/domains")
    def anomaly_domains(
        anomaly_id: int, user: dict[str, Any] = Depends(require_permission("view_anomalies"))
    ) -> dict[str, Any]:
        if anomaly is None:
            raise HTTPException(status_code=404, detail="No such anomaly")
        row = anomaly.get(anomaly_id)
        if row is None:
            raise HTTPException(status_code=404, detail="No such anomaly")
        allowed = _allowed_client_ips(user)
        if allowed is not None and row.get("client") not in allowed:
            raise HTTPException(status_code=404, detail="No such anomaly")
        kind = row["kind"]
        details = row["details"] or {}
        if kind.startswith("watched_domain:"):
            domain = details.get("domain")
            return {"domains": [domain] if domain else [], "blocked_only": False}
        window_minutes = details.get("window_minutes")
        if window_minutes is None:
            return {"domains": [], "blocked_only": False}
        until_ts = row["ts"]
        since_ts = until_ts - float(window_minutes) * 60
        blocked_only = kind in ("high_blocked_ratio", "blocked_domain_burst")
        domains = stats.domains_for_client_window(row["client"], since_ts, until_ts, blocked_only=blocked_only)
        return {"domains": domains, "blocked_only": blocked_only}

    def _check_anomaly_in_scope(anomaly_id: int, user: dict[str, Any]) -> None:
        if anomaly is None:
            raise HTTPException(status_code=404, detail="No such anomaly")
        allowed = _allowed_client_ips(user)
        if allowed is None:
            return
        row = anomaly.get(anomaly_id)
        if row is None or row.get("client") not in allowed:
            raise HTTPException(status_code=404, detail="No such anomaly")

    @app.post("/api/anomalies/{anomaly_id}/acknowledge")
    def acknowledge_anomaly(
        anomaly_id: int, user: dict[str, Any] = Depends(require_permission("view_anomalies"))
    ) -> dict[str, Any]:
        _check_anomaly_in_scope(anomaly_id, user)
        if anomaly is None or not anomaly.acknowledge(anomaly_id):
            raise HTTPException(status_code=404, detail="No such anomaly")
        return {"ok": True}

    @app.post("/api/anomalies/{anomaly_id}/unacknowledge")
    def unacknowledge_anomaly(
        anomaly_id: int, user: dict[str, Any] = Depends(require_permission("view_anomalies"))
    ) -> dict[str, Any]:
        _check_anomaly_in_scope(anomaly_id, user)
        if anomaly is None or not anomaly.unacknowledge(anomaly_id):
            raise HTTPException(status_code=404, detail="No such anomaly")
        return {"ok": True}

    @app.delete("/api/anomalies/{anomaly_id}")
    def delete_anomaly(anomaly_id: int, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        if anomaly is None or not anomaly.delete(anomaly_id):
            raise HTTPException(status_code=404, detail="No such anomaly")
        return {"ok": True}

    @app.delete("/api/anomalies")
    def clear_anomalies(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        if anomaly is not None:
            anomaly.clear()
        return {"ok": True}

    @app.post("/api/enrich")
    def enrich_target(body: EnrichIn, _: dict[str, Any] = Depends(require_permission("view_threat_intel"))) -> dict[str, Any]:
        target = body.target.strip()
        target_type = body.type if body.type in ("domain", "ip") else "domain"
        if not target:
            raise HTTPException(status_code=400, detail="Empty target")

        result = run_enrichment(target, target_type, config_store)
        history: list[dict[str, Any]] = []
        if enrichment_store is not None:
            enrichment_store.record(
                result["target"], result["type"], result["overall_verdict"], result["overall_score"], result["sources"]
            )
            history = enrichment_store.history_for(result["target"], limit=20)
        result["history"] = history
        if target_type == "ip":
            blocked_clients = config_store.get("blocked_clients", default=[]) or []
            result["client_blocked"] = any(ip_matches(result["target"], p) for p in blocked_clients)
        return result

    @app.get("/api/enrich/history")
    def enrichment_history(limit: int = 100, target: str | None = None, _: dict[str, Any] = Depends(require_permission("view_threat_intel"))) -> list[dict[str, Any]]:
        if enrichment_store is None:
            return []
        limit = max(1, min(limit, 500))
        if target:
            return enrichment_store.history_for(target.strip(), limit=limit)
        return enrichment_store.recent(limit=limit)

    @app.get("/api/users")
    def list_users(_: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return [public_user(u) for u in users.list()]

    @app.post("/api/users")
    def create_user(body: UserCreateIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        try:
            user = users.create(
                body.username,
                body.password,
                body.role,
                body.permissions.model_dump() if body.permissions else None,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return public_user(user)

    @app.patch("/api/users/{username}")
    def update_user(username: str, body: UserUpdateIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        try:
            user = users.update(
                username,
                password=body.password or None,
                role=body.role,
                permissions=body.permissions.model_dump() if body.permissions is not None else None,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if body.password:
            sessions.destroy_all_for(username)
        return public_user(user)

    @app.delete("/api/users/{username}")
    def delete_user(username: str, admin: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        if username == admin.get("username"):
            raise HTTPException(status_code=400, detail="Can't delete the account you're signed in with")
        try:
            users.delete(username)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        sessions.destroy_all_for(username)
        return {"ok": True}

    @app.post("/api/account/password")
    def change_own_password(
        body: ChangePasswordIn, user: dict[str, Any] = Depends(require_auth)
    ) -> dict[str, Any]:
        if not verify_password(body.current_password, user.get("password_hash", "")):
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        if not body.new_password:
            raise HTTPException(status_code=400, detail="New password is required")
        users.update(user["username"], password=body.new_password)
        return {"ok": True}

    @app.post("/api/account/totp/setup")
    def start_totp_setup(user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
        secret, uri = users.begin_totp_setup(user["username"])
        return {"secret": secret, "otpauth_uri": uri, "qr_svg": qr_svg(uri)}

    @app.post("/api/account/totp/confirm")
    def confirm_totp_setup(body: TotpConfirmIn, user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
        try:
            backup_codes = users.confirm_totp_setup(user["username"], body.code)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"ok": True, "backup_codes": backup_codes}

    @app.post("/api/account/totp/disable")
    def disable_totp(body: TotpDisableIn, user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
        try:
            users.disable_totp(user["username"], body.password)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"ok": True}

    @app.post("/api/account/passkeys/register/options")
    def start_passkey_registration(request: Request, user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
        existing_ids = users.passkey_credential_ids(user["username"])
        options_json, challenge = passkeys_lib.registration_options_json(
            _webauthn_rp_id(request), "DNS-shield", user["username"], existing_ids
        )
        token = pending_challenges.new_token(user["username"], challenge)
        return {"token": token, "options": options_json}

    @app.post("/api/account/passkeys/register/verify")
    def confirm_passkey_registration(
        body: PasskeyRegisterVerifyIn, request: Request, user: dict[str, Any] = Depends(require_auth)
    ) -> dict[str, Any]:
        entry = pending_challenges.pop(body.token)
        if entry is None or entry[0] != user["username"]:
            raise HTTPException(status_code=400, detail="Registration session expired - try again")
        challenge = entry[1]
        try:
            result = passkeys_lib.verify_registration(
                credential=body.credential,
                expected_challenge=challenge,
                rp_id=_webauthn_rp_id(request),
                origin=_webauthn_origin(request),
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Could not verify passkey: {exc}") from exc
        credential_id = bytes_to_base64url(result.credential_id)
        return users.add_passkey(
            user["username"], body.name, credential_id, result.credential_public_key, result.sign_count
        )

    @app.get("/api/account/passkeys")
    def list_passkeys(user: dict[str, Any] = Depends(require_auth)) -> list[dict[str, Any]]:
        return users.list_passkeys(user["username"])

    @app.delete("/api/account/passkeys/{passkey_id}")
    def delete_passkey(passkey_id: str, user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
        try:
            users.remove_passkey(user["username"], passkey_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"ok": True}

    @app.get("/api/account/tokens")
    def list_api_tokens(user: dict[str, Any] = Depends(require_auth)) -> list[dict[str, Any]]:
        return users.list_tokens(user["username"])

    @app.post("/api/account/tokens")
    def create_api_token(body: ApiTokenIn, user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
        try:
            token, record = users.create_token(user["username"], body.name)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"token": token, **record}

    @app.delete("/api/account/tokens/{token_id}")
    def revoke_api_token(token_id: str, user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
        try:
            users.revoke_token(user["username"], token_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"ok": True}

    @app.get("/api/audit-log")
    def list_audit_log(
        before_id: int | None = None, limit: int = 200, _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        if audit_log is None:
            return []
        return audit_log.list(limit=min(limit, 500), before_id=before_id)

    return app
