# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Cache, blocklist and allow sources, allow/deny rules, TLDs, answer-IP rules, log-ignore and typosquat lists."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from fastapi import Depends, FastAPI, HTTPException

from app.blocklist import check_regex_pattern_safety, normalize_tld
from app.blocklist_catalog import BLOCKLIST_CATALOG
from app.netmatch import normalize_client_pattern
from app.services import catalog as services_catalog
from app.typosquat import DEFAULT_PROTECTED_DOMAINS
from app.url_safety import check_public_url
from app.web.common import _ref_index
from app.web.context import AppContext
from app.web.models import BlockedServicesIn, BlocklistSourceIn, DomainIn, RegexPatternIn, ValueIn


def register(app: FastAPI, ctx: AppContext) -> None:
    blocklist = ctx.blocklist
    cache = ctx.cache
    config_store = ctx.config_store
    require_admin = ctx.require_admin
    require_auth = ctx.require_auth
    require_permission = ctx.require_permission

    @app.post("/api/cache/clear")
    def clear_cache(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        if cache is None:
            raise HTTPException(status_code=404, detail="Cache is disabled")
        cache.clear()
        # Extra DNS worker processes (DNSSHIELD_DNS_WORKERS > 1) keep their own
        # cache; bumping the generation tells them to drop it too.
        config_store.mutate(
            lambda d: d.setdefault("dns", {}).update(
                {"cache_generation": int((d.get("dns") or {}).get("cache_generation") or 0) + 1}
            )
        )
        cache.sync_generation()
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
        blocklist.request_refresh()
        return result

    def _delete_source(field: str, index: str) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            sources = data.setdefault("blocklists", {}).setdefault(field, [])
            pos = _ref_index(sources, index, "No such list")
            sources.pop(pos)
            return sources

        result = config_store.mutate(_mutate)
        blocklist.request_refresh()
        return result

    def _toggle_source(field: str, index: str) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            sources = data.setdefault("blocklists", {}).setdefault(field, [])
            pos = _ref_index(sources, index, "No such list")
            sources[pos]["enabled"] = not sources[pos].get("enabled", True)
            return sources

        result = config_store.mutate(_mutate)
        blocklist.request_refresh()
        return result

    @app.get("/api/blocklists")
    def list_blocklists(_: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return _list_sources("sources")

    @app.post("/api/blocklists")
    def add_blocklist(source: BlocklistSourceIn, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return _add_source("sources", source)

    @app.delete("/api/blocklists/{index}")
    def delete_blocklist(index: str, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return _delete_source("sources", index)

    @app.post("/api/blocklists/{index}/toggle")
    def toggle_blocklist(index: str, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return _toggle_source("sources", index)

    @app.get("/api/allow-sources")
    def list_allow_sources(_: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return _list_sources("allow_sources")

    @app.post("/api/allow-sources")
    def add_allow_source(source: BlocklistSourceIn, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return _add_source("allow_sources", source)

    @app.delete("/api/allow-sources/{index}")
    def delete_allow_source(index: str, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return _delete_source("allow_sources", index)

    @app.post("/api/allow-sources/{index}/toggle")
    def toggle_allow_source(index: str, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return _toggle_source("allow_sources", index)

    @app.get("/api/blocklists/catalog")
    def get_blocklist_catalog(_: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        existing_urls = {s.get("url") for s in _list_sources("sources")}
        return [entry for entry in BLOCKLIST_CATALOG if entry["url"] not in existing_urls]

    @app.post("/api/blocklists/refresh")
    def refresh_blocklists(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        blocklist.refresh()  # explicit "refresh now": the caller waits for the new counts
        return {"ok": True, "domains": blocklist.total_count(), "allowed": blocklist.allowed_count()}

    @app.get("/api/services")
    def get_services(_: dict[str, Any] = Depends(require_auth)) -> dict[str, Any]:
        return {
            "services": services_catalog(),
            "blocked": config_store.get("blocked_services", default=[]) or [],
        }

    @app.put("/api/blocked-services")
    def set_blocked_services(body: BlockedServicesIn, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        def _mutate(data: dict[str, Any]) -> list[str]:
            data["blocked_services"] = body.services
            return body.services

        return config_store.mutate(_mutate)

    @app.get("/api/rules")
    def get_rules(_: dict[str, Any] = Depends(require_auth)) -> dict[str, list[str]]:
        return {
            "allowlist": config_store.get("allowlist", default=[]) or [],
            "denylist": config_store.get("denylist", default=[]) or [],
            "denylist_regex": config_store.get("denylist_regex", default=[]) or [],
            "blocked_clients": config_store.get("blocked_clients", default=[]) or [],
            "blocked_answer_ips": config_store.get("blocked_answer_ips", default=[]) or [],
        }

    def _ip_or_cidr(value: str) -> str:
        text = (value or "").strip()
        try:
            if "/" in text:
                return str(ipaddress.ip_network(text, strict=False))
            return str(ipaddress.ip_address(text))
        except ValueError:
            raise HTTPException(
                status_code=400, detail=f'"{value}" is not an IP address or CIDR range (e.g. 192.168.1.10 or 10.0.0.0/8)'
            ) from None

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
            for item in [i for i in items if str(i).strip().lower().rstrip(".") == value]:
                items.remove(item)
            return items

        return config_store.mutate(_mutate)

    @app.post("/api/rules/allow")
    def add_allow(body: DomainIn, _: dict[str, Any] = Depends(require_permission("can_whitelist"))) -> list[str]:
        return _add_rule("allowlist", body.domain)

    @app.delete("/api/rules/allow/{domain:path}")
    def remove_allow(domain: str, _: dict[str, Any] = Depends(require_permission("can_whitelist"))) -> list[str]:
        return _remove_rule("allowlist", domain)

    @app.post("/api/rules/deny")
    def add_deny(body: DomainIn, _: dict[str, Any] = Depends(require_permission("can_block"))) -> list[str]:
        return _add_rule("denylist", body.domain)

    @app.delete("/api/rules/deny/{domain:path}")
    def remove_deny(domain: str, _: dict[str, Any] = Depends(require_permission("can_block"))) -> list[str]:
        return _remove_rule("denylist", domain)

    @app.get("/api/blocked-tlds")
    def get_blocked_tlds(_: dict[str, Any] = Depends(require_auth)) -> list[str]:
        return config_store.get("blocked_tlds", default=[]) or []

    @app.post("/api/blocked-tlds")
    def add_blocked_tld(body: ValueIn, _: dict[str, Any] = Depends(require_permission("can_block"))) -> list[str]:
        try:
            tld = normalize_tld(body.value)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        def _mutate(data: dict[str, Any]) -> list[str]:
            items = data.setdefault("blocked_tlds", [])
            if tld not in items:
                items.append(tld)
            return items

        return config_store.mutate(_mutate)

    @app.delete("/api/blocked-tlds/{tld}")
    def remove_blocked_tld(tld: str, _: dict[str, Any] = Depends(require_permission("can_block"))) -> list[str]:
        try:
            value = normalize_tld(tld)
        except ValueError:
            value = tld.strip().strip(".").lower()

        def _mutate(data: dict[str, Any]) -> list[str]:
            items = data.setdefault("blocked_tlds", [])
            if value in items:
                items.remove(value)
            return items

        return config_store.mutate(_mutate)

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

    @app.delete("/api/rules/deny-regex/{pattern:path}")
    def remove_deny_regex(pattern: str, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        def _mutate(data: dict[str, Any]) -> list[str]:
            items = data.setdefault("denylist_regex", [])
            if pattern in items:
                items.remove(pattern)
            return items

        return config_store.mutate(_mutate)

    @app.post("/api/rules/deny-client")
    def add_deny_client(body: ValueIn, _: dict[str, Any] = Depends(require_permission("can_block"))) -> list[str]:
        try:
            pattern = normalize_client_pattern(body.value)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _add_rule("blocked_clients", pattern, label="client")

    @app.delete("/api/rules/deny-client/{client:path}")
    def remove_deny_client(client: str, _: dict[str, Any] = Depends(require_permission("can_block"))) -> list[str]:
        return _remove_rule("blocked_clients", client)

    @app.post("/api/rules/deny-answer-ip")
    def add_deny_answer_ip(body: ValueIn, _: dict[str, Any] = Depends(require_permission("can_block"))) -> list[str]:
        result = _add_rule("blocked_answer_ips", _ip_or_cidr(body.value), label="IP")
        blocklist.request_refresh()
        return result

    @app.delete("/api/rules/deny-answer-ip/{value:path}")
    def remove_deny_answer_ip(value: str, _: dict[str, Any] = Depends(require_permission("can_block"))) -> list[str]:
        result = _remove_rule("blocked_answer_ips", value)
        blocklist.request_refresh()
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
        blocklist.request_refresh()
        return result

    @app.delete("/api/answer-ip-sources/{index}")
    def delete_answer_ip_source(
        index: str, _: dict[str, Any] = Depends(require_permission("can_block"))
    ) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            sources = data.setdefault("blocked_answer_ip_sources", [])
            pos = _ref_index(sources, index, "No such list")
            sources.pop(pos)
            return sources

        result = config_store.mutate(_mutate)
        blocklist.request_refresh()
        return result

    @app.post("/api/answer-ip-sources/{index}/toggle")
    def toggle_answer_ip_source(
        index: str, _: dict[str, Any] = Depends(require_permission("can_block"))
    ) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            sources = data.setdefault("blocked_answer_ip_sources", [])
            pos = _ref_index(sources, index, "No such list")
            sources[pos]["enabled"] = not sources[pos].get("enabled", True)
            return sources

        result = config_store.mutate(_mutate)
        blocklist.request_refresh()
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

    @app.delete("/api/log-ignore/domains/{value:path}")
    def remove_ignored_domain(value: str, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        return _remove_nested_rule("logging", "ignored_domains", value.strip().lower().rstrip("."))

    @app.post("/api/log-ignore/clients")
    def add_ignored_client(body: ValueIn, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        return _add_nested_rule("logging", "ignored_clients", _ip_or_cidr(body.value))

    @app.delete("/api/log-ignore/clients/{value:path}")
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

    @app.delete("/api/typosquat-domains/{value:path}")
    def remove_typosquat_domain(value: str, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        result = _remove_nested_rule("dns", "typosquat_extra_domains", value.strip().lower().rstrip("."))
        blocklist.clear_typosquat_cache()
        return result
