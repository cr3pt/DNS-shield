# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import base64
import io
import logging
import os
import re
import secrets
import sqlite3
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

import yaml
from dnslib import DNSRecord
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field, field_validator

from app.anomaly import _base_domain
from app.auth import verify_password
from app.blocklist import check_regex_pattern_safety
from app.graph import GRAPH_VIEWS
from app.blocklist_catalog import BLOCKLIST_CATALOG
from app import dns_rewrites
from app import new_client_detection
from app.proxy import access as proxy_access
from app.proxy import certbot_manager as proxy_certbot
from app.proxy import domain as proxy_domain
from app.proxy import healthcheck as proxy_healthcheck
from app.proxy import nginx_manager
from app.proxy import validate as proxy_validate
from app.enrichment import enrich as run_enrichment
from app.enrichment import maybe_alert_on_verdict
from app.import_adguard import import_config
from app.import_pihole import import_config as import_pihole_config
from app.login_throttle import LoginThrottle
from app.metrics import render_metrics
from app.netmatch import ip_matches, normalize_client_pattern, normalize_client_patterns
from app.passkeys import PendingChallengeStore
from app import passkeys as passkeys_lib
from webauthn.helpers import bytes_to_base64url
from app.sessions import COOKIE_NAME, SessionStore
from app.sso import OIDCError, PendingSSOStore, build_authorization_url, exchange_code, verify_id_token
from app.tls import ensure_self_signed_cert
from app.url_safety import check_public_url
from app.two_factor import PendingTotpStore, qr_svg
from app.typosquat import DEFAULT_PROTECTED_DOMAINS
from app.upstream import address as upstream_address
from app.upstream import is_disabled as upstream_is_disabled
from app.users import LANGUAGE_NATIVE_NAMES, SUPPORTED_LANGUAGES, UserStore, public_user

logger = logging.getLogger("dnsshield.web")

STATIC_DIR = Path(__file__).resolve().parent / "static"
LOCALES_DIR = Path(__file__).resolve().parent.parent / "locales"

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'; object-src 'none'"
    ),
}

CSRF_COOKIE_NAME = "dnsshield_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"
_CSRF_EXEMPT_PATHS = {
    "/api/login",
    "/api/login/totp",
    "/api/login/passkey/options",
    "/api/login/passkey/verify",
}

_CLEARABLE_SECRET_PATHS = {
    "enrichment.virustotal_api_key",
    "enrichment.abuseipdb_api_key",
    "enrichment.otx_api_key",
    "enrichment.greynoise_api_key",
    "enrichment.shodan_api_key",
    "enrichment.urlhaus_api_key",
    "enrichment.ipinfo_api_key",
    "enrichment.ai_api_key",
    "enrichment.local_api_key",
    "sso.client_secret",
    "notifications.email.smtp_password",
}


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
    "blocked_ratio_threshold": 0.7,
    "domain_burst_threshold": 50,
    "domain_burst_min_entropy": 3.3,
    "domain_burst_min_label_length": 10,
    "domain_burst_entropy_fraction": 0.5,
    "blocked_domain_burst_threshold": 15,
    "dns_tunneling_threshold": 30,
    "dns_tunneling_min_label_length": 20,
    "dns_tunneling_min_entropy": 3.0,
    "subdomain_count_threshold": 50,
    "ptr_scan_threshold": 15,
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


def _url_ping_settings(cfg: dict[str, Any]) -> dict[str, Any]:
    return {
        "enabled": bool(cfg.get("enabled", False)),
        "url": cfg.get("url", "") or "",
        "interval_minutes": cfg.get("interval_minutes", 15) or 15,
    }


def _rogue_dhcp_settings(cfg: dict[str, Any]) -> dict[str, Any]:
    return {
        "enabled": bool(cfg.get("enabled", False)),
        "interfaces": list(cfg.get("interfaces", []) or []),
        "allowed_server_ips": list(cfg.get("allowed_server_ips", []) or []),
        "check_interval_minutes": cfg.get("check_interval_minutes", 15) or 15,
        "cooldown_minutes": cfg.get("cooldown_minutes", 60) or 60,
    }


def _new_client_detection_settings(cfg: dict[str, Any]) -> dict[str, Any]:
    return {
        "dns_enabled": bool(cfg.get("dns_enabled", False)),
        "dns_learning_days": cfg.get("dns_learning_days", 7) or 7,
        "dns_learning_started_at": cfg.get("dns_learning_started_at"),
        "dhcp_enabled": bool(cfg.get("dhcp_enabled", False)),
        "dhcp_learning_days": cfg.get("dhcp_learning_days", 7) or 7,
        "dhcp_learning_started_at": cfg.get("dhcp_learning_started_at"),
    }


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


def _sso_settings_public(cfg: dict[str, Any]) -> dict[str, Any]:
    return {
        "enabled": bool(cfg.get("enabled", False)),
        "issuer": cfg.get("issuer", "") or "",
        "client_id": cfg.get("client_id", "") or "",
        "client_secret_set": bool(cfg.get("client_secret")),
        "client_secret_preview": _masked_key_preview(cfg.get("client_secret")),
        "scopes": cfg.get("scopes", "") or "openid email profile",
        "button_label": cfg.get("button_label", "") or "Single Sign-On",
        "username_claim": cfg.get("username_claim", "") or "preferred_username",
        "auto_provision": bool(cfg.get("auto_provision", True)),
        "default_role": cfg.get("default_role", "") or "user",
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


class TyposquatFpIn(BaseModel):
    domain: str
    protected: str


class RebindingFpIn(BaseModel):
    domain: str
    ip: str


class ThreatIntelFpIn(BaseModel):
    target: str
    verdict: str


class ValueIn(BaseModel):
    value: str


class RegexPatternIn(BaseModel):
    pattern: str


_GROUP_NAME_MAX_LENGTH = 255


def _clean_group_name(value: str) -> str:
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value or ""):
        raise ValueError("Group name can't contain control characters")
    name = " ".join((value or "").split())
    if not name:
        raise ValueError("Group name can't be empty")
    if len(name) > _GROUP_NAME_MAX_LENGTH:
        raise ValueError(f"Group name can be at most {_GROUP_NAME_MAX_LENGTH} characters")
    return name


class ClientGroupIn(BaseModel):
    name: str
    match: list[str] = []

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        return _clean_group_name(value)

    @field_validator("match")
    @classmethod
    def _validate_match(cls, value: list[str]) -> list[str]:
        return normalize_client_patterns(value)

    enabled: bool = True
    allowlist: list[str] = []
    denylist: list[str] = []
    upstreams: list[str] = []
    blocklist_sources: list[dict[str, Any]] = []
    safe_search: bool | None = None
    schedule: dict[str, Any] | None = None


class GroupNameIn(BaseModel):
    name: str

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        return _clean_group_name(value)


class GroupEnabledIn(BaseModel):
    enabled: bool


class GroupMatchIn(BaseModel):
    patterns: list[str] = Field(min_length=1, max_length=200)


class GroupSafeSearchIn(BaseModel):
    safe_search: bool | None = None


class DhcpReservationIn(BaseModel):
    mac: str
    ip: str
    hostname: str | None = None
    dns_servers: list[str] = []
    custom_options: list[dict[str, Any]] = []


class DhcpScopeIn(BaseModel):
    name: str
    enabled: bool = True
    interface: str
    vlan_id: int | None = None
    server_ip: str
    network: str
    pool_start: str
    pool_end: str
    gateway: str = ""
    dns_servers: list[str] = []
    domain_name: str = ""
    lease_seconds: float = 86400
    ntp_servers: list[str] = []
    wins_servers: list[str] = []
    mtu: int | None = None
    tftp_server: str = ""
    bootfile_name: str = ""
    static_routes: list[dict[str, Any]] = []
    excluded_ips: list[str] = []
    custom_options: list[dict[str, Any]] = []
    reservations: list[dict[str, Any]] = []


class DhcpScopePatchIn(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    interface: str | None = None
    vlan_id: int | None = None
    server_ip: str | None = None
    network: str | None = None
    pool_start: str | None = None
    pool_end: str | None = None
    gateway: str | None = None
    dns_servers: list[str] | None = None
    domain_name: str | None = None
    lease_seconds: float | None = None
    ntp_servers: list[str] | None = None
    wins_servers: list[str] | None = None
    mtu: int | None = None
    tftp_server: str | None = None
    bootfile_name: str | None = None
    static_routes: list[dict[str, Any]] | None = None
    excluded_ips: list[str] | None = None
    custom_options: list[dict[str, Any]] | None = None


class DhcpSettingsIn(BaseModel):
    enabled: bool | None = None


class RogueDhcpSettingsIn(BaseModel):
    enabled: bool | None = None
    interfaces: list[str] | None = None
    allowed_server_ips: list[str] | None = None
    check_interval_minutes: float | None = None
    cooldown_minutes: float | None = None


class NewClientDetectionSettingsIn(BaseModel):
    dns_enabled: bool | None = None
    dns_learning_days: float | None = None
    dhcp_enabled: bool | None = None
    dhcp_learning_days: float | None = None


class ProxyRuleIn(BaseModel):
    id: str | None = None
    type: str = "proxy"
    path: str = "/"
    upstream: str | None = None
    websocket: bool = False
    target: str | None = None
    code: int | None = None


class ProxySslIn(BaseModel):
    enabled: bool = False
    cert_path: str | None = None
    key_path: str | None = None


class ProxyDomainIn(BaseModel):
    hostnames: list[str] | str
    rules: list[dict[str, Any]] = []
    enabled: bool | None = None
    force_https: bool = False
    ssl: dict[str, Any] | None = None
    custom_config: str | None = None


class ProxySettingsIn(BaseModel):
    enabled: bool | None = None


class GraphSettingsIn(BaseModel):
    suspicious_zscore: float | None = None
    suspicious_min_degree: int | None = None


class ProxyCertbotIn(BaseModel):
    email: str


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
    query_case_randomization_enabled: bool | None = None
    block_mode: str | None = None
    blocked_ipv4: str | None = None
    blocked_ipv6: str | None = None
    block_ipv6: bool | None = None
    block_non_latin: bool | None = None
    cache_enabled: bool | None = None
    cache_max_entries: int | None = None
    cache_min_ttl_seconds: int | None = None
    cache_max_ttl_seconds: int | None = None
    cache_serve_stale_enabled: bool | None = None
    cache_stale_grace_seconds: int | None = None
    cache_prefetch_enabled: bool | None = None
    cache_prefetch_before_expiry_seconds: int | None = None
    cache_prefetch_min_hits: int | None = None
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
    rebinding_protection_enabled: bool | None = None
    rebinding_action: str | None = None
    rebinding_exempt_domains: list[str] | None = None
    local_tld_alert_enabled: bool | None = None
    local_tld_list: list[str] | None = None
    local_tld_cooldown_minutes: float | None = None
    query_acl_enabled: bool | None = None
    query_acl_extra_networks: list[str] | None = None


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
    ttl: int | None = None


class WebSettingsIn(BaseModel):
    listen_address: str | None = None
    listen_port: int | None = None
    theme: str | None = None
    https_enabled: bool | None = None
    https_cert_path: str | None = None
    https_key_path: str | None = None
    login_max_attempts: int | None = None
    login_lockout_minutes: float | None = None


class ClearSecretIn(BaseModel):
    path: str


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


class LanguageIn(BaseModel):
    language: str


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
    greynoise_api_key: str | None = None
    shodan_api_key: str | None = None
    urlhaus_api_key: str | None = None
    rdap_enabled: bool | None = None
    crtsh_enabled: bool | None = None
    ipinfo_enabled: bool | None = None
    ipinfo_api_key: str | None = None
    ai_enabled: bool | None = None
    ai_api_key: str | None = None
    public_enabled: bool | None = None
    local_enabled: bool | None = None
    local_url: str | None = None
    local_api_key: str | None = None
    alert_enabled: bool | None = None
    alert_min_severity: str | None = None
    auto_enrich_enabled: bool | None = None
    auto_enrich_interval_seconds: float | None = None
    auto_enrich_max_per_check: int | None = None


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
    subdomain_count_threshold: int | None = None
    ptr_scan_threshold: int | None = None
    cooldown_minutes: float | None = None


class ReanalyzeIn(BaseModel):
    hours: float


class AlertRulesSettingsIn(BaseModel):
    check_interval_seconds: float | None = None
    cooldown_minutes: float | None = None


class UrlPingSettingsIn(BaseModel):
    enabled: bool | None = None
    url: str | None = None
    interval_minutes: float | None = None


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


class SSOSettingsIn(BaseModel):
    enabled: bool | None = None
    issuer: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    scopes: str | None = None
    button_label: str | None = None
    username_claim: str | None = None
    auto_provision: bool | None = None
    default_role: str | None = None


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

    def _webauthn_rp_id(request: Request) -> str:
        return request.url.hostname or "localhost"

    def _webauthn_origin(request: Request) -> str:
        return request.headers.get("origin") or f"{request.url.scheme}://{request.url.netloc}"

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
        _set_auth_cookies(response, token)
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
        _set_auth_cookies(response, token)
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
        _set_auth_cookies(response, token)
        if audit_log is not None:
            audit_log.record(username, "login (passkey)", client_ip=client_ip)
        return {"ok": True, "user": public_user(user)}

    def _sso_config() -> dict[str, Any]:
        return config_store.get("sso", default={}) or {}

    def _sso_redirect_uri(request: Request) -> str:
        return f"{request.url.scheme}://{request.url.netloc}/api/sso/callback"

    @app.get("/api/sso/login")
    def sso_login(request: Request, next: str = "/") -> RedirectResponse:
        cfg = _sso_config()
        if not cfg.get("enabled"):
            raise HTTPException(status_code=404, detail="Single sign-on is not enabled")
        nonce = secrets.token_urlsafe(24)
        safe_next = next if next.startswith("/") and not next.startswith("//") else "/"
        state = pending_sso.create(nonce, safe_next)
        try:
            auth_url = build_authorization_url(cfg, _sso_redirect_uri(request), state, nonce)
        except OIDCError:
            return RedirectResponse("/login?error=sso_unavailable")
        return RedirectResponse(auth_url)

    @app.get("/api/sso/callback")
    def sso_callback(
        request: Request,
        response: Response,
        code: str | None = None,
        state: str | None = None,
        error: str | None = None,
    ) -> RedirectResponse:
        client_ip = request.client.host if request.client else "unknown"
        cfg = _sso_config()
        if not cfg.get("enabled"):
            raise HTTPException(status_code=404, detail="Single sign-on is not enabled")

        max_attempts = int(config_store.get("web", "login_max_attempts", default=5) or 5)
        lockout_seconds = max(1.0, float(config_store.get("web", "login_lockout_minutes", default=15) or 15) * 60)
        login_throttle.configure(max_attempts, lockout_seconds)
        if login_throttle.retry_after(client_ip) is not None:
            return RedirectResponse("/login?error=sso_failed")

        entry = pending_sso.consume(state)
        if error or entry is None:
            return RedirectResponse("/login?error=sso_failed")

        if code is None:
            return RedirectResponse("/login?error=sso_failed")

        try:
            token, metadata = exchange_code(cfg, _sso_redirect_uri(request), code)
            id_token = token.get("id_token")
            if not id_token:
                raise OIDCError("Identity provider did not return an ID token")
            claims = verify_id_token(id_token, metadata, cfg, entry["nonce"])
        except OIDCError:
            login_throttle.record_failure(client_ip)
            return RedirectResponse("/login?error=sso_failed")

        username_claim = cfg.get("username_claim") or "preferred_username"
        identity = claims.get(username_claim) or claims.get("email") or claims.get("sub")
        if not identity:
            return RedirectResponse("/login?error=sso_no_identity")
        identity = str(identity).strip()

        existing = users.get(identity)
        if existing is not None and not existing.get("sso"):
            login_throttle.record_failure(client_ip)
            return RedirectResponse("/login?error=sso_account_conflict")
        if existing is None:
            if not cfg.get("auto_provision", True):
                return RedirectResponse("/login?error=sso_no_account")
            user = users.find_or_create_sso(identity, cfg.get("default_role") or "user")
        else:
            user = existing

        login_throttle.record_success(client_ip)
        session_token = sessions.create(user["username"])
        redirect = RedirectResponse(entry.get("next") or "/")
        _set_auth_cookies(redirect, session_token)
        if audit_log is not None:
            audit_log.record(user["username"], "login (SSO)", client_ip=client_ip)
        return redirect

    @app.post("/api/logout")
    def logout(request: Request, response: Response) -> dict[str, Any]:
        user = _current_user(request)
        sessions.destroy(request.cookies.get(COOKIE_NAME))
        _clear_auth_cookies(response)
        if audit_log is not None and user is not None:
            client_ip = request.client.host if request.client else "unknown"
            audit_log.record(user["username"], "logout", client_ip=client_ip)
        return {"ok": True}

    @app.get("/api/whoami")
    def whoami(request: Request) -> dict[str, Any]:
        user = _current_user(request)
        enr = config_store.get("enrichment", default={}) or {}
        public_ready = bool(enr.get("public_enabled")) and (
            any(
                enr.get(k)
                for k in (
                    "virustotal_api_key",
                    "abuseipdb_api_key",
                    "otx_api_key",
                    "greynoise_api_key",
                    "shodan_api_key",
                    "urlhaus_api_key",
                )
            )
            or enr.get("rdap_enabled", True)
            or enr.get("crtsh_enabled")
        )
        local_ready = bool(enr.get("local_enabled")) and bool(enr.get("local_url"))
        sso_cfg = config_store.get("sso", default={}) or {}
        return {
            "user": public_user(user) if user is not None else None,
            "enrichment_available": public_ready or local_ready,
            "sso_enabled": bool(sso_cfg.get("enabled")),
            "sso_button_label": sso_cfg.get("button_label") or "Single Sign-On",
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

    @app.get("/api/graph")
    def get_graph(
        min_count: int = 1,
        limit_nodes: int = 150,
        view: str = "bipartite",
        group: str | None = None,
        no_group: bool = False,
        user: dict[str, Any] = Depends(require_permission("view_graph")),
    ) -> dict[str, Any]:
        if client_domain_graph is None:
            raise HTTPException(status_code=503, detail="Graph is not available")
        if view not in GRAPH_VIEWS:
            raise HTTPException(status_code=400, detail="Unknown graph view")
        allowed = _allowed_client_ips(user)
        result = client_domain_graph.get_graph(
            restrict_client_ips=_clients_in_group_scope(user, group, no_group, client_domain_graph.distinct_clients),
            min_count=max(1, min_count),
            limit_nodes=limit_nodes,
            view=view,
        )
        if allowed is None:
            result["groups"] = [str(g.get("name", "")) for g in config_store.get("client_groups", default=[]) or []]
        else:
            result["groups"] = sorted({name for name in (blocklist.group_name_for(ip) for ip in allowed) if name})
        return result

    @app.get("/api/graph/client/{client}")
    def get_graph_client(
        client: str, user: dict[str, Any] = Depends(require_permission("view_graph"))
    ) -> dict[str, Any]:
        if client_domain_graph is None:
            raise HTTPException(status_code=503, detail="Graph is not available")
        detail = client_domain_graph.client_detail(client, restrict_client_ips=_allowed_client_ips(user))
        if detail is None:
            raise HTTPException(status_code=404, detail="Client not found")
        detail["hostname"] = client_names.get(client) if client_names is not None else None
        return detail

    @app.get("/api/graph/domain/{domain}")
    def get_graph_domain(
        domain: str,
        group: str | None = None,
        no_group: bool = False,
        user: dict[str, Any] = Depends(require_permission("view_graph")),
    ) -> dict[str, Any]:
        if client_domain_graph is None:
            raise HTTPException(status_code=503, detail="Graph is not available")
        return client_domain_graph.domain_detail(
            domain.lower(),
            restrict_client_ips=_clients_in_group_scope(user, group, no_group, client_domain_graph.distinct_clients),
        )

    @app.post("/api/graph/clear")
    def clear_graph(_: dict[str, Any] = Depends(require_admin)) -> dict[str, bool]:
        if client_domain_graph is None:
            raise HTTPException(status_code=503, detail="Graph is not available")
        client_domain_graph.clear()
        return {"ok": True}

    @app.patch("/api/settings/graph")
    def update_graph_settings(body: GraphSettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            cfg = data.setdefault("graph", {})
            cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return cfg

        return config_store.mutate(_mutate)

    def _clients_in_group_scope(
        user: dict[str, Any], group: str | None, no_group: bool, known_clients=None
    ) -> list[str] | None:
        if group and no_group:
            raise HTTPException(status_code=400, detail="Use either group or no_group, not both")
        restrict = _allowed_client_ips(user)
        if not (group or no_group):
            return restrict
        if group and group not in {str(g.get("name", "")) for g in config_store.get("client_groups", default=[]) or []}:
            raise HTTPException(status_code=404, detail="No such client group")
        candidates = (known_clients or stats.distinct_clients)() if restrict is None else restrict
        return [
            ip
            for ip in candidates
            if (blocklist.group_name_for(ip) == group if group else blocklist.group_name_for(ip) is None)
        ]

    @app.get("/api/query-log/clients")
    def get_query_log_clients(
        group: str | None = None,
        no_group: bool = False,
        user: dict[str, Any] = Depends(require_auth),
    ) -> dict[str, Any]:
        allowed = _allowed_client_ips(user)
        everyone = stats.distinct_clients() if allowed is None else allowed
        scoped = _clients_in_group_scope(user, group, no_group)
        clients = everyone if scoped is None else scoped
        if allowed is None:
            group_names = [str(g.get("name", "")) for g in config_store.get("client_groups", default=[]) or []]
        else:
            group_names = sorted({name for name in (blocklist.group_name_for(ip) for ip in everyone) if name})
        return {
            "clients": sorted(clients),
            "groups": group_names,
            "client_names": client_names.snapshot() if client_names is not None else {},
        }

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
        group: str | None = None,
        no_group: bool = False,
        user: dict[str, Any] = Depends(require_auth),
    ) -> dict[str, Any]:
        restrict = _clients_in_group_scope(user, group, no_group)
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
            restrict_client_ips=restrict,
        )
        client_groups = {}
        for ip in {row["client"] for row in rows}:
            name = blocklist.group_name_for(ip)
            if name is not None:
                client_groups[ip] = name
        return {
            "rows": rows,
            "total": total,
            "client_groups": client_groups,
            "client_names": client_names.snapshot() if client_names is not None else {},
        }

    @app.delete("/api/query-log")
    def clear_query_log(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        stats.clear()
        if anomaly is not None:
            anomaly.reset_new_dns_clients()
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
        try:
            check_public_url(source.url)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

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
        try:
            check_regex_pattern_safety(pattern)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

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
        try:
            check_public_url(source.url)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

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
            if any(str(g.get("name", "")).casefold() == group.name.casefold() for g in groups):
                raise HTTPException(status_code=409, detail=f'A client group named "{group.name}" already exists')
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

    @app.put("/api/client-groups/{index}/name")
    def rename_client_group(
        index: int, body: GroupNameIn, _: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> tuple[dict[str, Any], str]:
            groups = data.setdefault("client_groups", [])
            if not 0 <= index < len(groups):
                raise HTTPException(status_code=404, detail="No such client group")
            old_name = str(groups[index].get("name", ""))
            for position, other in enumerate(groups):
                if position != index and str(other.get("name", "")).casefold() == body.name.casefold():
                    raise HTTPException(status_code=409, detail=f'A client group named "{body.name}" already exists')
            if old_name == body.name:
                return groups[index], old_name
            groups[index]["name"] = body.name
            for user in data.get("users", []) or []:
                permissions = user.get("permissions")
                allowed = permissions.get("allowed_groups") if isinstance(permissions, dict) else None
                if allowed and old_name in allowed:
                    renamed: list[str] = []
                    for entry in allowed:
                        entry = body.name if entry == old_name else entry
                        if entry not in renamed:
                            renamed.append(entry)
                    permissions["allowed_groups"] = renamed
            return groups[index], old_name

        group, old_name = config_store.mutate(_mutate)
        if old_name != body.name:
            blocklist.rename_group(old_name, body.name)
        return group

    @app.put("/api/client-groups/{index}/enabled")
    def set_client_group_enabled(
        index: int, body: GroupEnabledIn, _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            groups = data.setdefault("client_groups", [])
            if not 0 <= index < len(groups):
                raise HTTPException(status_code=404, detail="No such client group")
            groups[index]["enabled"] = body.enabled
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

    @app.post("/api/client-groups/{index}/match")
    def add_group_match(index: int, body: GroupMatchIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        try:
            patterns = normalize_client_patterns(body.patterns)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        def _fn(group: dict[str, Any]) -> dict[str, Any]:
            items = group.setdefault("match", [])
            for pattern in patterns:
                if pattern not in items:
                    items.append(pattern)
            return group

        return _group_mutate(index, _fn)

    @app.delete("/api/client-groups/{index}/match")
    def remove_group_match(index: int, pattern: str, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _fn(group: dict[str, Any]) -> dict[str, Any]:
            items = group.setdefault("match", [])
            target = pattern if pattern in items else None
            if target is None:
                try:
                    normalized = normalize_client_pattern(pattern)
                except ValueError:
                    normalized = None
                target = normalized if normalized in items else None
            if target is None:
                raise HTTPException(status_code=404, detail="No such pattern in this group")
            if len(items) <= 1:
                raise HTTPException(
                    status_code=400, detail="A group needs at least one pattern - delete the group instead"
                )
            items.remove(target)
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
        try:
            check_public_url(source.url)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

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

    @app.get("/api/dhcp/scopes")
    def list_dhcp_scopes(_: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return config_store.get("dhcp", "scopes", default=[]) or []

    @app.post("/api/dhcp/scopes")
    def add_dhcp_scope(scope: DhcpScopeIn, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            dhcp_cfg = data.setdefault("dhcp", {})
            scopes = dhcp_cfg.setdefault("scopes", [])
            if any(s.get("name") == scope.name for s in scopes):
                raise HTTPException(status_code=400, detail="A scope with this name already exists")
            scopes.append(scope.model_dump())
            return scopes

        return config_store.mutate(_mutate)

    def _dhcp_scope_mutate(index: int, fn) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            scopes = data.setdefault("dhcp", {}).setdefault("scopes", [])
            if not 0 <= index < len(scopes):
                raise HTTPException(status_code=404, detail="No such DHCP scope")
            fn(scopes[index])
            return scopes

        return config_store.mutate(_mutate)

    @app.patch("/api/dhcp/scopes/{index}")
    def update_dhcp_scope(
        index: int, body: DhcpScopePatchIn, _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        payload = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}

        def _fn(scope: dict[str, Any]) -> None:
            scope.update(payload)

        return _dhcp_scope_mutate(index, _fn)

    @app.delete("/api/dhcp/scopes/{index}")
    def delete_dhcp_scope(index: int, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            scopes = data.setdefault("dhcp", {}).setdefault("scopes", [])
            if not 0 <= index < len(scopes):
                raise HTTPException(status_code=404, detail="No such DHCP scope")
            scopes.pop(index)
            return scopes

        return config_store.mutate(_mutate)

    @app.post("/api/dhcp/scopes/{index}/toggle")
    def toggle_dhcp_scope(index: int, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _fn(scope: dict[str, Any]) -> None:
            scope["enabled"] = not scope.get("enabled", True)

        return _dhcp_scope_mutate(index, _fn)

    @app.post("/api/dhcp/scopes/{index}/reservations")
    def add_dhcp_reservation(
        index: int, body: DhcpReservationIn, _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        mac = body.mac.upper()

        def _fn(scope: dict[str, Any]) -> None:
            reservations = scope.setdefault("reservations", [])
            if any(r.get("mac", "").upper() == mac for r in reservations):
                raise HTTPException(status_code=400, detail="A reservation for this MAC already exists")
            entry = body.model_dump()
            entry["mac"] = mac
            reservations.append(entry)

        _dhcp_scope_mutate(index, _fn)
        return config_store.get("dhcp", "scopes", default=[])[index].get("reservations", [])

    @app.delete("/api/dhcp/scopes/{index}/reservations/{mac}")
    def delete_dhcp_reservation(
        index: int, mac: str, _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        mac = mac.upper()

        def _fn(scope: dict[str, Any]) -> None:
            reservations = scope.setdefault("reservations", [])
            scope["reservations"] = [r for r in reservations if r.get("mac", "").upper() != mac]

        _dhcp_scope_mutate(index, _fn)
        return config_store.get("dhcp", "scopes", default=[])[index].get("reservations", [])

    @app.get("/api/dhcp/leases")
    def list_dhcp_leases(_: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        if dhcp_server is None:
            return []
        return dhcp_server.lease_store.all_active()

    @app.delete("/api/dhcp/leases/{mac}")
    def delete_dhcp_lease(mac: str, _: dict[str, Any] = Depends(require_admin)) -> dict[str, str]:
        if dhcp_server is None:
            raise HTTPException(status_code=400, detail="DHCP server is not running")
        dhcp_server.lease_store.release(mac.upper())
        return {"status": "released"}

    @app.post("/api/dhcp/leases/{mac}/reserve")
    def reserve_dhcp_lease(mac: str, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        if dhcp_server is None:
            raise HTTPException(status_code=400, detail="DHCP server is not running")
        mac = mac.upper()
        lease = dhcp_server.lease_store.get_by_mac(mac)
        if lease is None:
            raise HTTPException(status_code=404, detail="No active lease for this MAC")

        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            scopes = data.setdefault("dhcp", {}).setdefault("scopes", [])
            for scope in scopes:
                if scope.get("name") != lease["scope"]:
                    continue
                reservations = scope.setdefault("reservations", [])
                if any(r.get("mac", "").upper() == mac for r in reservations):
                    raise HTTPException(status_code=400, detail="A reservation for this MAC already exists")
                reservations.append({
                    "mac": mac, "ip": lease["ip"], "hostname": lease.get("hostname"),
                    "dns_servers": [], "custom_options": [],
                })
                return scope
            raise HTTPException(status_code=404, detail="Scope for this lease no longer exists")

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/dhcp")
    def update_dhcp_settings(body: DhcpSettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            dhcp_cfg = data.setdefault("dhcp", {})
            dhcp_cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return {"enabled": bool(dhcp_cfg.get("enabled", False))}

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/rogue-dhcp-detection")
    def update_rogue_dhcp_settings(
        body: RogueDhcpSettingsIn, _: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            cfg = data.setdefault("rogue_dhcp_detection", {})
            cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return _rogue_dhcp_settings(cfg)

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/new-client-detection")
    def update_new_client_detection_settings(
        body: NewClientDetectionSettingsIn, _: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        payload = body.model_dump(exclude_unset=True)
        was_dns_enabled = bool(config_store.get("new_client_detection", "dns_enabled", default=False))
        was_dhcp_enabled = bool(config_store.get("new_client_detection", "dhcp_enabled", default=False))

        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            cfg = data.setdefault("new_client_detection", {})
            cfg.update({k: v for k, v in payload.items() if v is not None})
            if payload.get("dns_enabled") and not was_dns_enabled:
                cfg["dns_learning_started_at"] = time.time()
            if payload.get("dhcp_enabled") and not was_dhcp_enabled:
                cfg["dhcp_learning_started_at"] = time.time()
            return _new_client_detection_settings(cfg)

        return config_store.mutate(_mutate)

    @app.post("/api/new-client-detection/reset-dns")
    def reset_new_dns_clients(_: dict[str, Any] = Depends(require_admin)) -> dict[str, str]:
        if anomaly is not None:
            anomaly.reset_new_dns_clients()
        return {"status": "reset"}

    @app.post("/api/new-client-detection/reset-dhcp")
    def reset_new_dhcp_clients(_: dict[str, Any] = Depends(require_admin)) -> dict[str, str]:
        if dhcp_server is not None:
            dhcp_server.lease_store.reset_known_macs()
        new_client_detection.reset_learning(config_store, "new_client_detection", "dhcp_learning_started_at")
        return {"status": "reset"}

    def _find_proxy_domain_index(domains: list[dict[str, Any]], domain_id: str) -> int:
        for i, d in enumerate(domains):
            if d.get("id") == domain_id:
                return i
        return -1

    def _normalize_proxy_domain(body: ProxyDomainIn, user: dict[str, Any], existing: dict[str, Any] | None = None):
        payload = body.model_dump()
        if payload.get("custom_config") and user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Custom config is only available to administrators")
        try:
            normalized = proxy_domain.normalize_domain(payload, existing)
        except proxy_validate.ValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not proxy_access.is_domain_allowed(user, normalized["hostnames"]):
            raise HTTPException(status_code=403, detail="You don't have access to one of these domains")
        return normalized

    @app.get("/api/proxy/domains")
    def list_proxy_domains(
        user: dict[str, Any] = Depends(require_permission("can_manage_proxy")),
    ) -> list[dict[str, Any]]:
        domains = config_store.get("proxy", "domains", default=[]) or []
        return [d for d in domains if proxy_access.is_domain_allowed(user, d.get("hostnames"))]

    @app.post("/api/proxy/domains/preview")
    def preview_proxy_domain(
        body: ProxyDomainIn, user: dict[str, Any] = Depends(require_permission("can_manage_proxy"))
    ) -> dict[str, str]:
        normalized = _normalize_proxy_domain(body, user)
        return {"config": nginx_manager.preview_domain(normalized)}

    @app.post("/api/proxy/domains")
    def add_proxy_domain(
        body: ProxyDomainIn, user: dict[str, Any] = Depends(require_permission("can_manage_proxy"))
    ) -> dict[str, Any]:
        normalized = _normalize_proxy_domain(body, user)

        existing_domains = config_store.get("proxy", "domains", default=[]) or []
        used = {h for d in existing_domains for h in d.get("hostnames", [])}
        if used & set(normalized["hostnames"]):
            raise HTTPException(status_code=409, detail="One of these domains is already used by another entry")

        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            domains = data.setdefault("proxy", {}).setdefault("domains", [])
            domains.append(normalized)
            return domains

        config_store.mutate(_mutate)
        apply_result = nginx_manager.apply_domain(normalized)
        return {"domain": normalized, "apply": apply_result}

    @app.put("/api/proxy/domains/{domain_id}")
    def update_proxy_domain(
        domain_id: str, body: ProxyDomainIn, user: dict[str, Any] = Depends(require_permission("can_manage_proxy"))
    ) -> dict[str, Any]:
        domains = config_store.get("proxy", "domains", default=[]) or []
        idx = _find_proxy_domain_index(domains, domain_id)
        if idx < 0 or not proxy_access.is_domain_allowed(user, domains[idx].get("hostnames")):
            raise HTTPException(status_code=404, detail="Domain not found")

        normalized = _normalize_proxy_domain(body, user, existing=domains[idx])
        used = {h for i, d in enumerate(domains) if i != idx for h in d.get("hostnames", [])}
        if used & set(normalized["hostnames"]):
            raise HTTPException(status_code=409, detail="One of these domains is already used by another entry")

        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            domains_ = data.setdefault("proxy", {}).setdefault("domains", [])
            domains_[idx] = normalized
            return domains_

        config_store.mutate(_mutate)
        apply_result = nginx_manager.apply_domain(normalized)
        return {"domain": normalized, "apply": apply_result}

    @app.delete("/api/proxy/domains/{domain_id}")
    def delete_proxy_domain(
        domain_id: str, user: dict[str, Any] = Depends(require_permission("can_manage_proxy"))
    ) -> dict[str, Any]:
        domains = config_store.get("proxy", "domains", default=[]) or []
        idx = _find_proxy_domain_index(domains, domain_id)
        if idx < 0 or not proxy_access.is_domain_allowed(user, domains[idx].get("hostnames")):
            raise HTTPException(status_code=404, detail="Domain not found")

        remove_result = nginx_manager.remove_domain_config(domain_id)
        if not remove_result["ok"]:
            raise HTTPException(status_code=500, detail=f"Could not remove nginx config: {remove_result['error']}")

        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            domains_ = data.setdefault("proxy", {}).setdefault("domains", [])
            domains_.pop(idx)
            return domains_

        return {"domains": config_store.mutate(_mutate)}

    @app.post("/api/proxy/domains/{domain_id}/toggle")
    def toggle_proxy_domain(
        domain_id: str, user: dict[str, Any] = Depends(require_permission("can_manage_proxy"))
    ) -> dict[str, Any]:
        domains = config_store.get("proxy", "domains", default=[]) or []
        idx = _find_proxy_domain_index(domains, domain_id)
        if idx < 0 or not proxy_access.is_domain_allowed(user, domains[idx].get("hostnames")):
            raise HTTPException(status_code=404, detail="Domain not found")

        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            domains_ = data.setdefault("proxy", {}).setdefault("domains", [])
            domains_[idx]["enabled"] = not domains_[idx].get("enabled", True)
            domains_[idx]["updated_at"] = time.time()
            return domains_[idx]

        updated = config_store.mutate(_mutate)
        apply_result = nginx_manager.apply_domain(updated)
        return {"domain": updated, "apply": apply_result}

    @app.get("/api/proxy/domains/{domain_id}/health")
    def proxy_domain_health(
        domain_id: str, user: dict[str, Any] = Depends(require_permission("can_manage_proxy"))
    ) -> dict[str, Any]:
        domains = config_store.get("proxy", "domains", default=[]) or []
        idx = _find_proxy_domain_index(domains, domain_id)
        if idx < 0 or not proxy_access.is_domain_allowed(user, domains[idx].get("hostnames")):
            raise HTTPException(status_code=404, detail="Domain not found")

        domain = domains[idx]
        use_https = bool(domain.get("ssl", {}).get("enabled"))
        resolver = f"127.0.0.1:{config_store.get('dns', 'listen_port', default=53)}"
        return proxy_healthcheck.check_domain_health(domain["hostnames"], domain.get("rules"), use_https, resolver)

    @app.post("/api/proxy/domains/{domain_id}/certbot")
    def issue_proxy_certificate(
        domain_id: str, body: ProxyCertbotIn, _: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        domains = config_store.get("proxy", "domains", default=[]) or []
        idx = _find_proxy_domain_index(domains, domain_id)
        if idx < 0:
            raise HTTPException(status_code=404, detail="Domain not found")
        if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", body.email):
            raise HTTPException(status_code=400, detail="Provide a valid email address (required by Let's Encrypt)")

        result = proxy_certbot.issue_certificate(domains[idx]["hostnames"], body.email)
        if not result["ok"]:
            raise HTTPException(status_code=500, detail=result["error"])

        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            domains_ = data.setdefault("proxy", {}).setdefault("domains", [])
            domains_[idx]["ssl"] = {"enabled": True, "cert_path": result["cert_path"], "key_path": result["key_path"]}
            domains_[idx]["updated_at"] = time.time()
            return domains_[idx]

        updated = config_store.mutate(_mutate)
        apply_result = nginx_manager.apply_domain(updated)
        return {"domain": updated, "apply": apply_result, "certbot": result}

    @app.get("/api/proxy/status")
    def proxy_status(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        return {"nginx": nginx_manager.test_config()}

    @app.post("/api/proxy/reload")
    def proxy_reload(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        test = nginx_manager.test_config()
        if not test["ok"]:
            raise HTTPException(status_code=400, detail=f"nginx config has errors, reload aborted: {test['stderr'] or test['stdout']}")
        reload_result = nginx_manager.reload_nginx()
        return {"ok": reload_result["ok"], "details": reload_result["stderr"] or reload_result["stdout"]}

    @app.patch("/api/settings/proxy")
    def update_proxy_settings(body: ProxySettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            cfg = data.setdefault("proxy", {})
            cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return {"enabled": bool(cfg.get("enabled", False))}

        return config_store.mutate(_mutate)

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
        if rtype not in dns_rewrites.RECORD_TYPES:
            raise HTTPException(status_code=400, detail=f"Type must be one of: {', '.join(dns_rewrites.RECORD_TYPES)}")
        ttl = rewrite.ttl or dns_rewrites.DEFAULT_TTL
        if not 1 <= ttl <= 604800:
            raise HTTPException(status_code=400, detail="TTL must be between 1 and 604800 seconds")

        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            rewrites = data.setdefault("dns_rewrites", [])
            rewrites.append({"name": name, "type": rtype, "value": value, "ttl": ttl})
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

    @app.post("/api/settings/clear-secret")
    def clear_secret(body: ClearSecretIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        if body.path not in _CLEARABLE_SECRET_PATHS:
            raise HTTPException(status_code=400, detail="Unknown or non-clearable field")

        def _mutate(data: dict[str, Any]) -> None:
            parts = body.path.split(".")
            node = data
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = ""

        config_store.mutate(_mutate)
        return {"cleared": body.path}

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
                "greynoise_api_key_set": bool(snap.get("enrichment", {}).get("greynoise_api_key")),
                "greynoise_api_key_preview": _masked_key_preview(snap.get("enrichment", {}).get("greynoise_api_key")),
                "shodan_api_key_set": bool(snap.get("enrichment", {}).get("shodan_api_key")),
                "shodan_api_key_preview": _masked_key_preview(snap.get("enrichment", {}).get("shodan_api_key")),
                "urlhaus_api_key_set": bool(snap.get("enrichment", {}).get("urlhaus_api_key")),
                "urlhaus_api_key_preview": _masked_key_preview(snap.get("enrichment", {}).get("urlhaus_api_key")),
                "rdap_enabled": bool(snap.get("enrichment", {}).get("rdap_enabled", True)),
                "crtsh_enabled": bool(snap.get("enrichment", {}).get("crtsh_enabled", False)),
                "ipinfo_enabled": bool(snap.get("enrichment", {}).get("ipinfo_enabled", False)),
                "ipinfo_api_key_set": bool(snap.get("enrichment", {}).get("ipinfo_api_key")),
                "ipinfo_api_key_preview": _masked_key_preview(snap.get("enrichment", {}).get("ipinfo_api_key")),
                "ai_enabled": bool(snap.get("enrichment", {}).get("ai_enabled", False)),
                "ai_api_key_set": bool(snap.get("enrichment", {}).get("ai_api_key")),
                "ai_api_key_preview": _masked_key_preview(snap.get("enrichment", {}).get("ai_api_key")),
                "public_enabled": bool(snap.get("enrichment", {}).get("public_enabled", False)),
                "local_enabled": bool(snap.get("enrichment", {}).get("local_enabled", False)),
                "local_url": snap.get("enrichment", {}).get("local_url", "") or "",
                "local_api_key_set": bool(snap.get("enrichment", {}).get("local_api_key")),
                "local_api_key_preview": _masked_key_preview(snap.get("enrichment", {}).get("local_api_key")),
                "alert_enabled": bool(snap.get("enrichment", {}).get("alert_enabled", True)),
                "alert_min_severity": snap.get("enrichment", {}).get("alert_min_severity", "medium") or "medium",
                "auto_enrich_enabled": bool(snap.get("enrichment", {}).get("auto_enrich_enabled", False)),
                "auto_enrich_interval_seconds": snap.get("enrichment", {}).get("auto_enrich_interval_seconds", 30) or 30,
                "auto_enrich_max_per_check": snap.get("enrichment", {}).get("auto_enrich_max_per_check", 5) or 5,
            },
            "sso": _sso_settings_public(snap.get("sso", {})),
            "anomaly": _anomaly_settings(snap.get("anomaly", {})),
            "alert_rules": _alert_rules_settings(snap.get("alert_rules", {})),
            "url_ping": _url_ping_settings(snap.get("url_ping", {})),
            "dhcp": {"enabled": bool(snap.get("dhcp", {}).get("enabled", False)), "scope_count": len(snap.get("dhcp", {}).get("scopes", []) or [])},
            "proxy": {"enabled": bool(snap.get("proxy", {}).get("enabled", False)), "domain_count": len(snap.get("proxy", {}).get("domains", []) or [])},
            "graph": {
                "suspicious_zscore": snap.get("graph", {}).get("suspicious_zscore", 2.5) or 2.5,
                "suspicious_min_degree": snap.get("graph", {}).get("suspicious_min_degree", 15) or 15,
            },
            "rogue_dhcp_detection": _rogue_dhcp_settings(snap.get("rogue_dhcp_detection", {})),
            "new_client_detection": _new_client_detection_settings(snap.get("new_client_detection", {})),
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
            old_max_distance = dns_cfg.get("typosquat_max_distance")
            dns_cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            if dns_cfg.get("typosquat_max_distance") != old_max_distance:
                blocklist.clear_typosquat_cache()
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

    @app.post("/api/settings/web/migrate-https")
    def migrate_to_https(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        web_cfg = config_store.snapshot().get("web", {})
        cert_path_cfg = web_cfg.get("https_cert_path", "") or ""
        key_path_cfg = web_cfg.get("https_key_path", "") or ""
        if not cert_path_cfg or not key_path_cfg:
            try:
                ensure_self_signed_cert(data_dir / "tls" / "cert.pem", data_dir / "tls" / "key.pem")
            except OSError as exc:
                raise HTTPException(status_code=500, detail=f"Could not generate a self-signed certificate: {exc}")

        def _mutate(data: dict[str, Any]) -> None:
            data.setdefault("web", {})["https_enabled"] = True

        config_store.mutate(_mutate)
        return {"https_enabled": True, "restart_required": True, "restart_note": RESTART_NOTE}

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
        keep_if_blank = {
            "virustotal_api_key",
            "abuseipdb_api_key",
            "otx_api_key",
            "greynoise_api_key",
            "shodan_api_key",
            "urlhaus_api_key",
            "ipinfo_api_key",
            "ai_api_key",
            "local_api_key",
        }
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
                "greynoise_api_key_set": bool(enr.get("greynoise_api_key")),
                "greynoise_api_key_preview": _masked_key_preview(enr.get("greynoise_api_key")),
                "shodan_api_key_set": bool(enr.get("shodan_api_key")),
                "shodan_api_key_preview": _masked_key_preview(enr.get("shodan_api_key")),
                "urlhaus_api_key_set": bool(enr.get("urlhaus_api_key")),
                "urlhaus_api_key_preview": _masked_key_preview(enr.get("urlhaus_api_key")),
                "rdap_enabled": bool(enr.get("rdap_enabled", True)),
                "crtsh_enabled": bool(enr.get("crtsh_enabled", False)),
                "ipinfo_enabled": bool(enr.get("ipinfo_enabled", False)),
                "ipinfo_api_key_set": bool(enr.get("ipinfo_api_key")),
                "ipinfo_api_key_preview": _masked_key_preview(enr.get("ipinfo_api_key")),
                "ai_enabled": bool(enr.get("ai_enabled", False)),
                "ai_api_key_set": bool(enr.get("ai_api_key")),
                "ai_api_key_preview": _masked_key_preview(enr.get("ai_api_key")),
                "public_enabled": bool(enr.get("public_enabled", False)),
                "local_enabled": bool(enr.get("local_enabled", False)),
                "local_url": enr.get("local_url", "") or "",
                "local_api_key_set": bool(enr.get("local_api_key")),
                "local_api_key_preview": _masked_key_preview(enr.get("local_api_key")),
                "alert_enabled": bool(enr.get("alert_enabled", True)),
                "alert_min_severity": enr.get("alert_min_severity", "medium") or "medium",
                "auto_enrich_enabled": bool(enr.get("auto_enrich_enabled", False)),
                "auto_enrich_interval_seconds": enr.get("auto_enrich_interval_seconds", 30) or 30,
                "auto_enrich_max_per_check": enr.get("auto_enrich_max_per_check", 5) or 5,
            }

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/sso")
    def update_sso_settings(body: SSOSettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        keep_if_blank = {"client_secret"}
        data_in = body.model_dump(exclude_unset=True)
        if "default_role" in data_in and data_in["default_role"] not in ("admin", "user"):
            raise HTTPException(status_code=400, detail='Default role must be "admin" or "user"')
        payload = {k: v for k, v in data_in.items() if (v if k in keep_if_blank else v is not None)}

        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            data.setdefault("sso", {}).update(payload)
            return _sso_settings_public(data["sso"])

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

    @app.patch("/api/settings/url-ping")
    def update_url_ping_settings(body: UrlPingSettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            cfg = data.setdefault("url_ping", {})
            cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return _url_ping_settings(cfg)

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
        try:
            check_public_url(source.url)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

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

    @app.get("/api/anomalies/subdomain-analysis")
    def subdomain_analysis(
        hours: float = 24, limit: int = 20, _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        if anomaly is None:
            return []
        hours = max(1.0, min(hours, 24 * 30))
        limit = max(1, min(limit, 100))
        return anomaly.analyze_subdomain_counts(hours=hours, limit=limit)

    @app.get("/api/anomalies/subdomain-analysis/domains")
    def subdomain_analysis_domains(
        base_domain: str, hours: float = 24, _: dict[str, Any] = Depends(require_admin)
    ) -> list[str]:
        if anomaly is None:
            return []
        hours = max(1.0, min(hours, 24 * 30))
        return anomaly.list_subdomains(base_domain.strip().lower().rstrip("."), hours=hours)

    @app.get("/api/anomaly-subdomain-exclusions")
    def list_anomaly_subdomain_exclusions(
        _: dict[str, Any] = Depends(require_permission("view_anomalies")),
    ) -> list[str]:
        return config_store.get("anomaly", "subdomain_count_excluded_domains", default=[]) or []

    @app.post("/api/anomaly-subdomain-exclusions")
    def add_anomaly_subdomain_exclusion(body: DomainIn, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        domain = body.domain.strip().lower().rstrip(".")
        if not domain:
            raise HTTPException(status_code=400, detail="Empty domain")

        def _mutate(data: dict[str, Any]) -> list[str]:
            domains = data.setdefault("anomaly", {}).setdefault("subdomain_count_excluded_domains", [])
            if domain not in domains:
                domains.append(domain)
            return domains

        return config_store.mutate(_mutate)

    @app.delete("/api/anomaly-subdomain-exclusions/{domain}")
    def remove_anomaly_subdomain_exclusion(domain: str, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        domain = domain.strip().lower().rstrip(".")

        def _mutate(data: dict[str, Any]) -> list[str]:
            domains = data.setdefault("anomaly", {}).setdefault("subdomain_count_excluded_domains", [])
            if domain in domains:
                domains.remove(domain)
            return domains

        return config_store.mutate(_mutate)

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
        if kind in ("dns_tunneling", "subdomain_count_burst"):
            base = details.get("base_domain")
            if base:
                domains = [d for d in domains if _base_domain(d) == base]
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

    @app.get("/api/anomaly-exclusions")
    def list_anomaly_exclusions(_: dict[str, Any] = Depends(require_permission("view_anomalies"))) -> list[str]:
        return config_store.get("anomaly", "excluded_domains", default=[]) or []

    @app.post("/api/anomaly-exclusions")
    def add_anomaly_exclusion(body: DomainIn, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        domain = body.domain.strip().lower().rstrip(".")
        if not domain:
            raise HTTPException(status_code=400, detail="Empty domain")

        def _mutate(data: dict[str, Any]) -> list[str]:
            domains = data.setdefault("anomaly", {}).setdefault("excluded_domains", [])
            if domain not in domains:
                domains.append(domain)
            return domains

        return config_store.mutate(_mutate)

    @app.delete("/api/anomaly-exclusions/{domain}")
    def remove_anomaly_exclusion(domain: str, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        domain = domain.strip().lower().rstrip(".")

        def _mutate(data: dict[str, Any]) -> list[str]:
            domains = data.setdefault("anomaly", {}).setdefault("excluded_domains", [])
            if domain in domains:
                domains.remove(domain)
            return domains

        return config_store.mutate(_mutate)

    @app.get("/api/typosquat-fp")
    def list_typosquat_fp(_: dict[str, Any] = Depends(require_permission("view_anomalies"))) -> list[dict[str, str]]:
        return config_store.get("anomaly", "typosquat_fp_pairs", default=[]) or []

    @app.post("/api/typosquat-fp")
    def add_typosquat_fp(body: TyposquatFpIn, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, str]]:
        domain = body.domain.strip().lower().rstrip(".")
        protected = body.protected.strip().lower().rstrip(".")
        if not domain or not protected:
            raise HTTPException(status_code=400, detail="Empty domain or protected domain")

        def _mutate(data: dict[str, Any]) -> list[dict[str, str]]:
            pairs = data.setdefault("anomaly", {}).setdefault("typosquat_fp_pairs", [])
            if not any(p.get("domain") == domain and p.get("protected") == protected for p in pairs):
                pairs.append({"domain": domain, "protected": protected})
            return pairs

        return config_store.mutate(_mutate)

    @app.delete("/api/typosquat-fp/{domain}/{protected}")
    def remove_typosquat_fp(domain: str, protected: str, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, str]]:
        domain = domain.strip().lower().rstrip(".")
        protected = protected.strip().lower().rstrip(".")

        def _mutate(data: dict[str, Any]) -> list[dict[str, str]]:
            pairs = data.setdefault("anomaly", {}).setdefault("typosquat_fp_pairs", [])
            pairs[:] = [p for p in pairs if not (p.get("domain") == domain and p.get("protected") == protected)]
            return pairs

        return config_store.mutate(_mutate)

    @app.get("/api/rebinding-fp")
    def list_rebinding_fp(_: dict[str, Any] = Depends(require_permission("view_anomalies"))) -> list[dict[str, str]]:
        return config_store.get("anomaly", "rebinding_fp_pairs", default=[]) or []

    @app.post("/api/rebinding-fp")
    def add_rebinding_fp(body: RebindingFpIn, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, str]]:
        domain = body.domain.strip().lower().rstrip(".")
        ip = body.ip.strip()
        if not domain or not ip:
            raise HTTPException(status_code=400, detail="Empty domain or IP")

        def _mutate(data: dict[str, Any]) -> list[dict[str, str]]:
            pairs = data.setdefault("anomaly", {}).setdefault("rebinding_fp_pairs", [])
            if not any(p.get("domain") == domain and p.get("ip") == ip for p in pairs):
                pairs.append({"domain": domain, "ip": ip})
            return pairs

        return config_store.mutate(_mutate)

    @app.delete("/api/rebinding-fp/{domain}/{ip}")
    def remove_rebinding_fp(domain: str, ip: str, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, str]]:
        domain = domain.strip().lower().rstrip(".")
        ip = ip.strip()

        def _mutate(data: dict[str, Any]) -> list[dict[str, str]]:
            pairs = data.setdefault("anomaly", {}).setdefault("rebinding_fp_pairs", [])
            pairs[:] = [p for p in pairs if not (p.get("domain") == domain and p.get("ip") == ip)]
            return pairs

        return config_store.mutate(_mutate)

    @app.get("/api/threat-intel-fp")
    def list_threat_intel_fp(_: dict[str, Any] = Depends(require_permission("view_anomalies"))) -> list[dict[str, str]]:
        return config_store.get("anomaly", "threat_intel_fp_targets", default=[]) or []

    @app.post("/api/threat-intel-fp")
    def add_threat_intel_fp(body: ThreatIntelFpIn, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, str]]:
        target = body.target.strip().lower()
        verdict = body.verdict.strip().lower()
        if not target or not verdict:
            raise HTTPException(status_code=400, detail="Empty target or verdict")

        def _mutate(data: dict[str, Any]) -> list[dict[str, str]]:
            targets = data.setdefault("anomaly", {}).setdefault("threat_intel_fp_targets", [])
            for entry in targets:
                if entry.get("target") == target:
                    entry["verdict"] = verdict
                    return targets
            targets.append({"target": target, "verdict": verdict})
            return targets

        return config_store.mutate(_mutate)

    @app.delete("/api/threat-intel-fp/{target}")
    def remove_threat_intel_fp(target: str, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, str]]:
        target = target.strip().lower()

        def _mutate(data: dict[str, Any]) -> list[dict[str, str]]:
            targets = data.setdefault("anomaly", {}).setdefault("threat_intel_fp_targets", [])
            targets[:] = [e for e in targets if e.get("target") != target]
            return targets

        return config_store.mutate(_mutate)

    @app.get("/api/domain-lookup")
    def domain_lookup(domain: str, _: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
        domain = domain.strip().lower().rstrip(".")
        if not domain:
            raise HTTPException(status_code=400, detail="Empty domain")
        return blocklist.lookup_domain(domain)

    @app.post("/api/enrich")
    def enrich_target(body: EnrichIn, user: dict[str, Any] = Depends(require_permission("view_threat_intel"))) -> dict[str, Any]:
        target = body.target.strip()
        target_type = body.type if body.type in ("domain", "ip") else "domain"
        if not target:
            raise HTTPException(status_code=400, detail="Empty target")

        try:
            result = run_enrichment(target, target_type, config_store)
        except Exception as exc:
            logger.exception("enrichment lookup failed for %s", target)
            raise HTTPException(status_code=502, detail=f"Enrichment failed: {exc}") from exc
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
            ip_source = blocklist.answer_ip_blocked(result["target"])
            result["local_blocklist"] = {
                "blocked": ip_source is not None,
                "block_reason": f"Malicious IP list: {ip_source}" if ip_source else None,
            }
            result["mac_address"] = blocklist.mac_for(result["target"])
        else:
            result["local_blocklist"] = blocklist.lookup_domain(result["target"])
            result["recent_clients"] = stats.recent_clients_for_domain(
                result["target"], limit=20, restrict_client_ips=_allowed_client_ips(user)
            )
        maybe_alert_on_verdict(result, config_store, anomaly)
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

    @app.get("/api/languages")
    def list_languages() -> list[dict[str, str]]:
        return [{"code": code, "name": LANGUAGE_NATIVE_NAMES.get(code, code)} for code in SUPPORTED_LANGUAGES]

    @app.get("/api/locales/{lang}")
    def get_locale(lang: str) -> Response:
        if lang not in SUPPORTED_LANGUAGES:
            raise HTTPException(status_code=404, detail="Unknown language")
        locale_path = LOCALES_DIR / f"{lang}.json"
        if locale_path.exists():
            return FileResponse(locale_path, media_type="application/json")
        return Response(content="{}", media_type="application/json")

    @app.post("/api/account/language")
    def set_own_language(body: LanguageIn, user: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
        try:
            updated = users.set_language(user["username"], body.language)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return public_user(updated)

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
