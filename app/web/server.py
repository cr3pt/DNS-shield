"""Web UI + REST API.

Everything here only ever reads/writes the local config store and the
local stats snapshot - the one exception is POST /api/enrich, which
looks up a domain/IP's reputation via VirusTotal/AbuseIPDB/AlienVault OTX
(app/enrichment.py) - and that only ever runs when a user clicks
"Enrich" in the dashboard, never automatically.
"""

from __future__ import annotations

import io
import re
import secrets
import sqlite3
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

import yaml
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

from app.blocklist_catalog import BLOCKLIST_CATALOG
from app.enrichment import enrich as run_enrichment
from app.import_adguard import import_config
from app.import_pihole import import_config as import_pihole_config
from app.netmatch import ip_matches
from app.upstream import address as upstream_address
from app.upstream import is_disabled as upstream_is_disabled

STATIC_DIR = Path(__file__).resolve().parent / "static"

security = HTTPBasic()


def _masked_key_preview(key: str | None) -> str:
    """First and last character of a saved API key, e.g. "a***********f" -
    enough for a user to recognize *which* key is saved (in case they keep
    more than one VirusTotal/AbuseIPDB/OTX account, say) without the full
    value ever being sent back to the browser. Empty string if no key is
    saved, or the key itself if it's a single character (nothing to mask).
    """
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
    "cooldown_minutes": 60,
}


def _anomaly_settings(cfg: dict[str, Any]) -> dict[str, Any]:
    return {key: cfg.get(key, default) for key, default in _ANOMALY_DEFAULTS.items()}


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


class UpstreamsIn(BaseModel):
    upstreams: list[str]


class DomainUpstreamIn(BaseModel):
    name: str
    domains: list[str] = []
    upstreams: list[str] = []


class RewriteIn(BaseModel):
    name: str
    type: str  # "A" or "AAAA"
    value: str


class WebSettingsIn(BaseModel):
    listen_address: str | None = None
    listen_port: int | None = None
    username: str | None = None
    password: str | None = None  # blank/omitted = keep current password
    theme: str | None = None


class LoggingSettingsIn(BaseModel):
    retention_days: float | None = None


class BlocklistSettingsIn(BaseModel):
    refresh_interval_hours: float | None = None


class PauseIn(BaseModel):
    seconds: float | None = None  # None/omitted = pause until manually resumed


class EnrichmentSettingsIn(BaseModel):
    virustotal_api_key: str | None = None  # blank/omitted = keep current key
    abuseipdb_api_key: str | None = None
    otx_api_key: str | None = None
    public_enabled: bool | None = None  # master on/off for the three cloud services above
    local_enabled: bool | None = None
    local_url: str | None = None  # not a secret - blank clears it, unlike the API key fields
    local_api_key: str | None = None  # blank/omitted = keep current key


class EnrichIn(BaseModel):
    target: str
    type: str  # "domain" or "ip"


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
    cooldown_minutes: float | None = None


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
) -> FastAPI:
    app = FastAPI(title="DNS-shield", docs_url=None, redoc_url=None)

    def require_auth(credentials: HTTPBasicCredentials = Depends(security)) -> None:
        username = str(config_store.get("web", "username", default="admin"))
        password = str(config_store.get("web", "password", default="changeme"))
        ok_user = secrets.compare_digest(credentials.username, username)
        ok_pass = secrets.compare_digest(credentials.password, password)
        if not (ok_user and ok_pass):
            raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Basic"})

    @app.get("/")
    def index(_: None = Depends(require_auth)) -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/api/status")
    def status(_: None = Depends(require_auth)) -> dict[str, Any]:
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
            "cache": cache.stats() if cache is not None else None,
            "upstream_stats": upstream_stats.snapshot() if upstream_stats is not None else {},
            "pause": {
                "active": blocklist.is_paused(),
                "until": config_store.get("pause", "until", default=None),
            },
        }

    @app.post("/api/pause")
    def pause_blocking(body: PauseIn, _: None = Depends(require_auth)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            pause_cfg = data.setdefault("pause", {})
            pause_cfg["active"] = True
            pause_cfg["until"] = (time.time() + body.seconds) if body.seconds else None
            return pause_cfg

        return config_store.mutate(_mutate)

    @app.post("/api/resume")
    def resume_blocking(_: None = Depends(require_auth)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            pause_cfg = data.setdefault("pause", {})
            pause_cfg["active"] = False
            pause_cfg["until"] = None
            return pause_cfg

        return config_store.mutate(_mutate)

    @app.get("/api/stats")
    def get_stats(top_n: int = 25, log_n: int = 200, _: None = Depends(require_auth)) -> dict[str, Any]:
        snapshot = stats.snapshot(top_n=top_n, log_n=log_n)
        snapshot["client_names"] = client_names.snapshot() if client_names is not None else {}
        return snapshot

    @app.get("/api/stats/timeseries")
    def get_stats_timeseries(range: str = "24h", _: None = Depends(require_auth)) -> list[dict[str, Any]]:
        if range not in ("24h", "7d", "30d"):
            range = "24h"
        return stats.timeseries(range)

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
        _: None = Depends(require_auth),
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
        )
        return {
            "rows": rows,
            "total": total,
            "client_names": client_names.snapshot() if client_names is not None else {},
        }

    @app.delete("/api/query-log")
    def clear_query_log(_: None = Depends(require_auth)) -> dict[str, Any]:
        stats.clear()
        return {"ok": True}

    @app.post("/api/cache/clear")
    def clear_cache(_: None = Depends(require_auth)) -> dict[str, Any]:
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
    def list_blocklists(_: None = Depends(require_auth)) -> list[dict[str, Any]]:
        return _list_sources("sources")

    @app.post("/api/blocklists")
    def add_blocklist(source: BlocklistSourceIn, _: None = Depends(require_auth)) -> list[dict[str, Any]]:
        return _add_source("sources", source)

    @app.delete("/api/blocklists/{index}")
    def delete_blocklist(index: int, _: None = Depends(require_auth)) -> list[dict[str, Any]]:
        return _delete_source("sources", index)

    @app.post("/api/blocklists/{index}/toggle")
    def toggle_blocklist(index: int, _: None = Depends(require_auth)) -> list[dict[str, Any]]:
        return _toggle_source("sources", index)

    @app.get("/api/allow-sources")
    def list_allow_sources(_: None = Depends(require_auth)) -> list[dict[str, Any]]:
        return _list_sources("allow_sources")

    @app.post("/api/allow-sources")
    def add_allow_source(source: BlocklistSourceIn, _: None = Depends(require_auth)) -> list[dict[str, Any]]:
        return _add_source("allow_sources", source)

    @app.delete("/api/allow-sources/{index}")
    def delete_allow_source(index: int, _: None = Depends(require_auth)) -> list[dict[str, Any]]:
        return _delete_source("allow_sources", index)

    @app.post("/api/allow-sources/{index}/toggle")
    def toggle_allow_source(index: int, _: None = Depends(require_auth)) -> list[dict[str, Any]]:
        return _toggle_source("allow_sources", index)

    @app.get("/api/blocklists/catalog")
    def get_blocklist_catalog(_: None = Depends(require_auth)) -> list[dict[str, Any]]:
        # An entry already present as a configured source has nothing left
        # to suggest, so it's dropped from the list entirely rather than
        # shown disabled - "added" is a one-way trip out of Suggested lists.
        existing_urls = {s.get("url") for s in _list_sources("sources")}
        return [entry for entry in BLOCKLIST_CATALOG if entry["url"] not in existing_urls]

    @app.post("/api/blocklists/refresh")
    def refresh_blocklists(_: None = Depends(require_auth)) -> dict[str, Any]:
        blocklist.refresh()
        return {"ok": True, "domains": blocklist.total_count(), "allowed": blocklist.allowed_count()}

    @app.get("/api/rules")
    def get_rules(_: None = Depends(require_auth)) -> dict[str, list[str]]:
        return {
            "allowlist": config_store.get("allowlist", default=[]) or [],
            "denylist": config_store.get("denylist", default=[]) or [],
            "denylist_regex": config_store.get("denylist_regex", default=[]) or [],
            "blocked_clients": config_store.get("blocked_clients", default=[]) or [],
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
    def add_allow(body: DomainIn, _: None = Depends(require_auth)) -> list[str]:
        return _add_rule("allowlist", body.domain)

    @app.delete("/api/rules/allow/{domain}")
    def remove_allow(domain: str, _: None = Depends(require_auth)) -> list[str]:
        return _remove_rule("allowlist", domain)

    @app.post("/api/rules/deny")
    def add_deny(body: DomainIn, _: None = Depends(require_auth)) -> list[str]:
        return _add_rule("denylist", body.domain)

    @app.delete("/api/rules/deny/{domain}")
    def remove_deny(domain: str, _: None = Depends(require_auth)) -> list[str]:
        return _remove_rule("denylist", domain)

    # -- denylist_regex: experimental, off by default (dns.regex_denylist_enabled) -
    # matched against the full query name with re.Pattern.search(), so an
    # unanchored pattern like "tracker" matches anywhere in the name, same
    # as a typical AdBlock-style regex rule. Compiled once and cached in
    # BlocklistManager, not per query - see blocklist.py.
    @app.post("/api/rules/deny-regex")
    def add_deny_regex(body: RegexPatternIn, _: None = Depends(require_auth)) -> list[str]:
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
    def remove_deny_regex(pattern: str, _: None = Depends(require_auth)) -> list[str]:
        def _mutate(data: dict[str, Any]) -> list[str]:
            items = data.setdefault("denylist_regex", [])
            if pattern in items:
                items.remove(pattern)
            return items

        return config_store.mutate(_mutate)

    # -- blocked_clients: EVERY query from this IP/CIDR is blocked, for every
    # domain - not a domain-scoped rule. Dashboard: "Block host" button next
    # to a client IP (query log, Stats, Enrich popup), or added by hand here.
    @app.post("/api/rules/deny-client")
    def add_deny_client(body: ValueIn, _: None = Depends(require_auth)) -> list[str]:
        return _add_rule("blocked_clients", body.value, label="client")

    @app.delete("/api/rules/deny-client/{client}")
    def remove_deny_client(client: str, _: None = Depends(require_auth)) -> list[str]:
        return _remove_rule("blocked_clients", client)

    # -- log-ignore: excluded from the query log only, resolution/blocking is unaffected --
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
    def get_log_ignore(_: None = Depends(require_auth)) -> dict[str, list[str]]:
        return {
            "domains": config_store.get("logging", "ignored_domains", default=[]) or [],
            "clients": config_store.get("logging", "ignored_clients", default=[]) or [],
        }

    @app.post("/api/log-ignore/domains")
    def add_ignored_domain(body: DomainIn, _: None = Depends(require_auth)) -> list[str]:
        return _add_nested_rule("logging", "ignored_domains", body.domain.strip().lower().rstrip("."))

    @app.delete("/api/log-ignore/domains/{value}")
    def remove_ignored_domain(value: str, _: None = Depends(require_auth)) -> list[str]:
        return _remove_nested_rule("logging", "ignored_domains", value.strip().lower().rstrip("."))

    @app.post("/api/log-ignore/clients")
    def add_ignored_client(body: ValueIn, _: None = Depends(require_auth)) -> list[str]:
        return _add_nested_rule("logging", "ignored_clients", body.value.strip())

    @app.delete("/api/log-ignore/clients/{value}")
    def remove_ignored_client(value: str, _: None = Depends(require_auth)) -> list[str]:
        return _remove_nested_rule("logging", "ignored_clients", value.strip())

    @app.get("/api/client-groups")
    def list_client_groups(_: None = Depends(require_auth)) -> list[dict[str, Any]]:
        return config_store.get("client_groups", default=[]) or []

    @app.post("/api/client-groups")
    def add_client_group(group: ClientGroupIn, _: None = Depends(require_auth)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            groups = data.setdefault("client_groups", [])
            groups.append(group.model_dump())
            return groups

        return config_store.mutate(_mutate)

    @app.delete("/api/client-groups/{index}")
    def delete_client_group(index: int, _: None = Depends(require_auth)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            groups = data.setdefault("client_groups", [])
            if not 0 <= index < len(groups):
                raise HTTPException(status_code=404, detail="No such client group")
            groups.pop(index)
            return groups

        return config_store.mutate(_mutate)

    @app.post("/api/client-groups/{index}/toggle")
    def toggle_client_group(index: int, _: None = Depends(require_auth)) -> list[dict[str, Any]]:
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
    def add_group_allow(index: int, body: DomainIn, _: None = Depends(require_auth)) -> dict[str, Any]:
        return _add_group_rule(index, "allowlist", body.domain)

    @app.delete("/api/client-groups/{index}/allow/{domain}")
    def remove_group_allow(index: int, domain: str, _: None = Depends(require_auth)) -> dict[str, Any]:
        return _remove_group_rule(index, "allowlist", domain)

    @app.post("/api/client-groups/{index}/deny")
    def add_group_deny(index: int, body: DomainIn, _: None = Depends(require_auth)) -> dict[str, Any]:
        return _add_group_rule(index, "denylist", body.domain)

    @app.delete("/api/client-groups/{index}/deny/{domain}")
    def remove_group_deny(index: int, domain: str, _: None = Depends(require_auth)) -> dict[str, Any]:
        return _remove_group_rule(index, "denylist", domain)

    @app.put("/api/client-groups/{index}/upstreams")
    def set_group_upstreams(index: int, body: UpstreamsIn, _: None = Depends(require_auth)) -> dict[str, Any]:
        def _fn(group: dict[str, Any]) -> dict[str, Any]:
            group["upstreams"] = body.upstreams
            return group

        return _group_mutate(index, _fn)

    # -- per-group extra blocklist sources: additive to the global blocklist,
    # e.g. a stricter extra list for a kids' devices group. Mirrors the
    # global /api/blocklists CRUD above, scoped to one group's own list. --
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
    def list_group_blocklist_sources(index: int, _: None = Depends(require_auth)) -> list[dict[str, Any]]:
        groups = config_store.get("client_groups", default=[]) or []
        if not 0 <= index < len(groups):
            raise HTTPException(status_code=404, detail="No such client group")
        return groups[index].get("blocklist_sources", []) or []

    @app.post("/api/client-groups/{index}/blocklist-sources")
    def add_group_blocklist_source(
        index: int, source: BlocklistSourceIn, _: None = Depends(require_auth)
    ) -> list[dict[str, Any]]:
        def _fn(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
            sources.append(source.model_dump())
            return sources

        return _group_source_mutate(index, _fn)

    @app.delete("/api/client-groups/{index}/blocklist-sources/{source_index}")
    def delete_group_blocklist_source(
        index: int, source_index: int, _: None = Depends(require_auth)
    ) -> list[dict[str, Any]]:
        def _fn(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
            if not 0 <= source_index < len(sources):
                raise HTTPException(status_code=404, detail="No such list")
            sources.pop(source_index)
            return sources

        return _group_source_mutate(index, _fn)

    @app.post("/api/client-groups/{index}/blocklist-sources/{source_index}/toggle")
    def toggle_group_blocklist_source(
        index: int, source_index: int, _: None = Depends(require_auth)
    ) -> list[dict[str, Any]]:
        def _fn(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
            if not 0 <= source_index < len(sources):
                raise HTTPException(status_code=404, detail="No such list")
            sources[source_index]["enabled"] = not sources[source_index].get("enabled", True)
            return sources

        return _group_source_mutate(index, _fn)

    # -- per-domain upstream routing: [/domain/] -> specific resolvers, AdGuard-style --
    @app.get("/api/domain-upstreams")
    def list_domain_upstreams(_: None = Depends(require_auth)) -> list[dict[str, Any]]:
        return config_store.get("domain_upstreams", default=[]) or []

    @app.post("/api/domain-upstreams")
    def add_domain_upstream(rule: DomainUpstreamIn, _: None = Depends(require_auth)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            rules = data.setdefault("domain_upstreams", [])
            rules.append(rule.model_dump())
            return rules

        return config_store.mutate(_mutate)

    @app.delete("/api/domain-upstreams/{index}")
    def delete_domain_upstream(index: int, _: None = Depends(require_auth)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            rules = data.setdefault("domain_upstreams", [])
            if not 0 <= index < len(rules):
                raise HTTPException(status_code=404, detail="No such rule")
            rules.pop(index)
            return rules

        return config_store.mutate(_mutate)

    # -- custom DNS records ("rewrites"): answer a hostname with an IP you --
    # choose, entirely locally - see app/dns_rewrites.py for the matching
    # rule and where this sits in the resolution order.
    @app.get("/api/rewrites")
    def list_rewrites(_: None = Depends(require_auth)) -> list[dict[str, Any]]:
        return config_store.get("dns_rewrites", default=[]) or []

    @app.post("/api/rewrites")
    def add_rewrite(rewrite: RewriteIn, _: None = Depends(require_auth)) -> list[dict[str, Any]]:
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
    def delete_rewrite(index: int, _: None = Depends(require_auth)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            rewrites = data.setdefault("dns_rewrites", [])
            if not 0 <= index < len(rewrites):
                raise HTTPException(status_code=404, detail="No such rewrite")
            rewrites.pop(index)
            return rewrites

        return config_store.mutate(_mutate)

    # -- import an existing AdGuard Home config, from the browser -------
    # Deliberately a plain (non-async) def: blocklist.refresh() below makes
    # blocking HTTP calls for every configured source, and a real AdGuard
    # config can list several. FastAPI runs sync routes in a worker thread,
    # same as every other endpoint here that calls refresh() - an async def
    # would instead run that blocking work directly on the event loop and
    # freeze the entire web UI for every user until every source timed out
    # or responded.
    @app.post("/api/import/adguard")
    def import_adguard(file: UploadFile = File(...), _: None = Depends(require_auth)) -> dict[str, Any]:
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

    # -- import an existing Pi-hole gravity.db, from the browser --------
    # Same sync-def reasoning as import_adguard above: blocklist.refresh()
    # makes blocking HTTP calls for every configured source.
    @app.post("/api/import/pihole")
    def import_pihole(file: UploadFile = File(...), _: None = Depends(require_auth)) -> dict[str, Any]:
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

    # -- config backup: a full snapshot the browser downloads as a .zip ----
    # This is your own config leaving the container for your own local
    # machine, at your own request (a button click) - nothing is sent
    # anywhere else. It's a full, unmasked snapshot (same as
    # config.backup.yaml already on disk), including any threat-intel API
    # keys and your web login password in plain text, so the README.txt
    # bundled alongside it says the same: treat the download like you would
    # a password.
    _EXPORT_README = """DNS-shield configuration backup
================================

config.yaml is a full snapshot of this instance's config.db at the time of
export: blocklists, allow/deny rules, client groups, DNS/web settings,
custom DNS records - and yes, any threat-intel API keys and your web login
password, all in plain text (same as data/config.backup.yaml already on
disk). Treat this file like a password: back it up somewhere you'd store
a password, not somewhere public.

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
    def export_config(_: None = Depends(require_auth)) -> Response:
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

    # -- config restore: the other end of /api/export above. Unlike the
    # AdGuard/Pi-hole importers, this is DNS-shield's own native format, so
    # there's no lossy conversion and nothing to merge onto the current
    # config - a restore replaces it outright, exactly reproducing whatever
    # was true at export time. blocklist.refresh() below makes blocking
    # HTTP calls, same sync-def reasoning as the other importers above.
    @app.post("/api/import/backup")
    def import_backup(file: UploadFile = File(...), _: None = Depends(require_auth)) -> dict[str, Any]:
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

        return {"ok": True}

    # -- full settings: everything not covered by the CRUD endpoints above -
    RESTART_NOTE = "Changing this requires restarting the container (docker compose restart)."

    @app.get("/api/settings")
    def get_settings(_: None = Depends(require_auth)) -> dict[str, Any]:
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
                "username": web_cfg.get("username"),
                "theme": web_cfg.get("theme", "navy"),
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
            "restart_required": [
                "dns.listen_address",
                "dns.listen_port",
                "web.listen_address",
                "web.listen_port",
                "dns.block_page_enabled",
                "dns.block_page_port",
            ],
            "restart_note": RESTART_NOTE,
        }

    @app.patch("/api/settings/dns")
    def update_dns_settings(body: DnsSettingsIn, _: None = Depends(require_auth)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            dns_cfg = data.setdefault("dns", {})
            # None means "the client left this field blank" (e.g. a numeric
            # input with no value serializes to null), never "clear this
            # setting" - every field here has a real default, so a blank
            # submission should leave the existing value alone.
            dns_cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return {k: v for k, v in dns_cfg.items() if k != "upstreams"}

        return config_store.mutate(_mutate)

    @app.put("/api/settings/upstreams")
    def update_upstreams(body: UpstreamsIn, _: None = Depends(require_auth)) -> list[str]:
        # A leading "#" marks an upstream as disabled - kept in the list
        # (so re-enabling doesn't mean re-typing it) but skipped by
        # FilteringResolver - see app.upstream.is_disabled. Only truly
        # blank lines are dropped; a "# ..." line is a real disabled entry
        # now, not a comment to discard.
        upstreams = [u.strip() for u in body.upstreams if u.strip()]

        def _mutate(data: dict[str, Any]) -> list[str]:
            data.setdefault("dns", {})["upstreams"] = upstreams
            return data["dns"]["upstreams"]

        return config_store.mutate(_mutate)

    @app.post("/api/settings/upstreams/{index}/toggle")
    def toggle_upstream(index: int, _: None = Depends(require_auth)) -> list[str]:
        def _mutate(data: dict[str, Any]) -> list[str]:
            upstreams = data.setdefault("dns", {}).setdefault("upstreams", [])
            if not 0 <= index < len(upstreams):
                raise HTTPException(status_code=404, detail="No such upstream")
            entry = upstreams[index]
            upstreams[index] = upstream_address(entry) if upstream_is_disabled(entry) else "#" + entry.strip()
            return upstreams

        return config_store.mutate(_mutate)

    @app.delete("/api/settings/upstreams/{index}")
    def delete_upstream(index: int, _: None = Depends(require_auth)) -> list[str]:
        def _mutate(data: dict[str, Any]) -> list[str]:
            upstreams = data.setdefault("dns", {}).setdefault("upstreams", [])
            if not 0 <= index < len(upstreams):
                raise HTTPException(status_code=404, detail="No such upstream")
            upstreams.pop(index)
            return upstreams

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/web")
    def update_web_settings(body: WebSettingsIn, _: None = Depends(require_auth)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            web_cfg = data.setdefault("web", {})
            payload = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
            password = payload.pop("password", None)
            web_cfg.update(payload)
            if password:
                web_cfg["password"] = password
            return {k: v for k, v in web_cfg.items() if k != "password"}

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/logging")
    def update_logging_settings(body: LoggingSettingsIn, _: None = Depends(require_auth)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            logging_cfg = data.setdefault("logging", {})
            logging_cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return logging_cfg

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/blocklists")
    def update_blocklist_settings(body: BlocklistSettingsIn, _: None = Depends(require_auth)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            bl_cfg = data.setdefault("blocklists", {})
            bl_cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return {k: v for k, v in bl_cfg.items() if k not in ("sources", "allow_sources")}

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/enrichment")
    def update_enrichment_settings(body: EnrichmentSettingsIn, _: None = Depends(require_auth)) -> dict[str, Any]:
        # API-key-shaped fields: blank/omitted means "keep the current
        # value" (these are masked password inputs - the form never shows
        # the real key back, so an empty field must not overwrite it).
        # Everything else (the two on/off switches, and local_url which is
        # a plain, unmasked field) is applied exactly as sent, including
        # false/blank, so a switch can actually be turned off and a saved
        # local_url can actually be cleared.
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
    def update_anomaly_settings(body: AnomalySettingsIn, _: None = Depends(require_auth)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            anomaly_cfg = data.setdefault("anomaly", {})
            anomaly_cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return _anomaly_settings(anomaly_cfg)

        return config_store.mutate(_mutate)

    # -- local anomaly detection: a background thread that periodically ---
    # scans the query log for per-client statistical red flags (a spike in
    # blocked queries, an unusual number of distinct domains). Entirely
    # local - see app/anomaly.py.
    @app.get("/api/anomalies")
    def list_anomalies(
        include_acknowledged: bool = True, limit: int = 200, _: None = Depends(require_auth)
    ) -> list[dict[str, Any]]:
        if anomaly is None:
            return []
        return anomaly.list(include_acknowledged=include_acknowledged, limit=max(1, min(limit, 1000)))

    @app.get("/api/anomalies/count")
    def anomalies_count(_: None = Depends(require_auth)) -> dict[str, int]:
        return {"unacknowledged": anomaly.unacknowledged_count() if anomaly is not None else 0}

    @app.post("/api/anomalies/check-now")
    def anomalies_check_now(_: None = Depends(require_auth)) -> list[dict[str, Any]]:
        if anomaly is None:
            return []
        return anomaly.check_once()

    @app.post("/api/anomalies/{anomaly_id}/acknowledge")
    def acknowledge_anomaly(anomaly_id: int, _: None = Depends(require_auth)) -> dict[str, Any]:
        if anomaly is None or not anomaly.acknowledge(anomaly_id):
            raise HTTPException(status_code=404, detail="No such anomaly")
        return {"ok": True}

    @app.delete("/api/anomalies/{anomaly_id}")
    def delete_anomaly(anomaly_id: int, _: None = Depends(require_auth)) -> dict[str, Any]:
        if anomaly is None or not anomaly.delete(anomaly_id):
            raise HTTPException(status_code=404, detail="No such anomaly")
        return {"ok": True}

    @app.delete("/api/anomalies")
    def clear_anomalies(_: None = Depends(require_auth)) -> dict[str, Any]:
        if anomaly is not None:
            anomaly.clear()
        return {"ok": True}

    # -- threat-intel enrichment: manual only, triggered by the "Enrich" ---
    # button in the dashboard. Never called automatically, never on a
    # schedule, never as a side effect of a DNS query.
    @app.post("/api/enrich")
    def enrich_target(body: EnrichIn, _: None = Depends(require_auth)) -> dict[str, Any]:
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
            # Past lookups for this exact target (this one included, as the
            # newest row) - lets the popup show how its verdict/score have
            # moved over time, not just the result of this one click.
            history = enrichment_store.history_for(result["target"], limit=20)
        result["history"] = history
        if target_type == "ip":
            blocked_clients = config_store.get("blocked_clients", default=[]) or []
            result["client_blocked"] = any(ip_matches(result["target"], p) for p in blocked_clients)
        return result

    @app.get("/api/enrich/history")
    def enrichment_history(limit: int = 100, target: str | None = None, _: None = Depends(require_auth)) -> list[dict[str, Any]]:
        if enrichment_store is None:
            return []
        limit = max(1, min(limit, 500))
        if target:
            return enrichment_store.history_for(target.strip(), limit=limit)
        return enrichment_store.recent(limit=limit)

    return app
