# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Constants and helpers shared by the web app and its route modules."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import HTTPException

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
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
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

# The only endpoints an account flagged must_change_password may call
# (everything else answers 403 until the password is changed).
_PASSWORD_CHANGE_ALLOWED_PATHS = {
    "/api/account/password",
    "/api/account/language",
    "/api/languages",
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


def _ref_index(items: list[Any], ref: str, detail: str) -> int:
    """Position of the entry a route names: its stable `id` or, for older
    clients and plain-string lists, its numeric index. 404 if neither fits."""
    for position, item in enumerate(items):
        if isinstance(item, dict) and item.get("id") == ref:
            return position
    if ref.isdigit() and len(ref) < 7 and int(ref) < len(items):
        return int(ref)
    raise HTTPException(status_code=404, detail=detail)


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
        "id": cfg.get("id"),
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
