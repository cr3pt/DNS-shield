from __future__ import annotations

import time
import uuid
from typing import Any

from app.proxy.validate import (
    ValidationError,
    assert_file_path,
    assert_hostname,
    assert_path,
    assert_redirect_code,
    assert_redirect_target,
    assert_upstream,
)


def normalize_rule(input_rule: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(input_rule, dict):
        raise ValidationError("Invalid rule.")
    rule_id = input_rule.get("id") or str(uuid.uuid4())
    path = assert_path(input_rule.get("path") or "/")
    if input_rule.get("type") == "redirect":
        return {
            "id": rule_id,
            "type": "redirect",
            "path": path,
            "target": assert_redirect_target(input_rule.get("target")),
            "code": assert_redirect_code(input_rule.get("code") or 301),
        }
    return {
        "id": rule_id,
        "type": "proxy",
        "path": path,
        "upstream": assert_upstream(input_rule.get("upstream")),
        "websocket": bool(input_rule.get("websocket")),
    }


def normalize_domain(input_domain: dict[str, Any], existing: dict[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(input_domain, dict):
        raise ValidationError("Missing domain data.")

    raw_hostnames = input_domain.get("hostnames")
    if isinstance(raw_hostnames, str):
        raw_hostnames = [h for h in raw_hostnames.replace(",", " ").split() if h]
    raw_hostnames = raw_hostnames or []
    if not raw_hostnames:
        raise ValidationError("Provide at least one hostname.")
    hostnames = [assert_hostname(h.strip()) for h in raw_hostnames]

    rules = [normalize_rule(r) for r in input_domain.get("rules") or []]
    if not rules:
        raise ValidationError("Add at least one rule (proxy or redirect).")

    ssl_in = input_domain.get("ssl") or {}
    ssl = {"enabled": bool(ssl_in.get("enabled")), "cert_path": "", "key_path": ""}
    if ssl["enabled"]:
        ssl["cert_path"] = assert_file_path(ssl_in.get("cert_path"), "SSL certificate")
        ssl["key_path"] = assert_file_path(ssl_in.get("key_path"), "SSL key")

    custom_config = input_domain.get("custom_config")
    if custom_config is None:
        custom_config = (existing or {}).get("custom_config", "")

    now = time.time()
    return {
        "id": (existing or {}).get("id") or str(uuid.uuid4()),
        "hostnames": hostnames,
        "enabled": True if input_domain.get("enabled") is None else bool(input_domain.get("enabled")),
        "force_https": bool(input_domain.get("force_https")),
        "ssl": ssl,
        "rules": rules,
        "custom_config": str(custom_config or ""),
        "created_at": (existing or {}).get("created_at") or now,
        "updated_at": now,
    }
