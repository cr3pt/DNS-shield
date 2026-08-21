"""Web UI + REST API.

Everything here only ever reads/writes the local config store and the
local stats snapshot - the one exception is POST /api/enrich, which
looks up a domain/IP's reputation via VirusTotal/AbuseIPDB/AlienVault OTX
(app/enrichment.py) - and that only ever runs when a user clicks
"Enrich" in the dashboard, never automatically.
"""

from __future__ import annotations

import secrets
import time
from pathlib import Path
from typing import Any

import yaml
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

from app.enrichment import enrich as run_enrichment
from app.import_adguard import import_config

STATIC_DIR = Path(__file__).resolve().parent / "static"

security = HTTPBasic()


class BlocklistSourceIn(BaseModel):
    name: str
    url: str
    enabled: bool = True


class DomainIn(BaseModel):
    domain: str


class ValueIn(BaseModel):
    value: str


class ClientGroupIn(BaseModel):
    name: str
    match: list[str] = []
    enabled: bool = True
    allowlist: list[str] = []
    denylist: list[str] = []
    upstreams: list[str] = []


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


class UpstreamsIn(BaseModel):
    upstreams: list[str]


class DomainUpstreamIn(BaseModel):
    name: str
    domains: list[str] = []
    upstreams: list[str] = []


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


def create_app(
    config_store,
    blocklist,
    stats,
    started_at: float,
    cache=None,
    client_names=None,
    upstream_stats=None,
    enrichment_store=None,
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
        return {
            "uptime_seconds": time.time() - started_at,
            "dns_listen": f"{config_store.get('dns', 'listen_address', default='0.0.0.0')}:"
            f"{config_store.get('dns', 'listen_port', default=53)}",
            "blocklist_domains": blocklist.total_count(),
            "blocklist_sources": blocklist.source_counts(),
            "blocklist_last_refresh": blocklist.last_refresh(),
            "allowlist_domains": blocklist.allowed_count(),
            "allowlist_sources": blocklist.allow_source_counts(),
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

    @app.post("/api/blocklists/refresh")
    def refresh_blocklists(_: None = Depends(require_auth)) -> dict[str, Any]:
        blocklist.refresh()
        return {"ok": True, "domains": blocklist.total_count(), "allowed": blocklist.allowed_count()}

    @app.get("/api/rules")
    def get_rules(_: None = Depends(require_auth)) -> dict[str, list[str]]:
        return {
            "allowlist": config_store.get("allowlist", default=[]) or [],
            "denylist": config_store.get("denylist", default=[]) or [],
        }

    def _add_rule(list_name: str, domain: str) -> list[str]:
        domain = domain.strip().lower().rstrip(".")
        if not domain:
            raise HTTPException(status_code=400, detail="Empty domain")

        def _mutate(data: dict[str, Any]) -> list[str]:
            items = data.setdefault(list_name, [])
            if domain not in items:
                items.append(domain)
            return items

        return config_store.mutate(_mutate)

    def _remove_rule(list_name: str, domain: str) -> list[str]:
        domain = domain.strip().lower().rstrip(".")

        def _mutate(data: dict[str, Any]) -> list[str]:
            items = data.setdefault(list_name, [])
            if domain in items:
                items.remove(domain)
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
                "abuseipdb_api_key_set": bool(snap.get("enrichment", {}).get("abuseipdb_api_key")),
                "otx_api_key_set": bool(snap.get("enrichment", {}).get("otx_api_key")),
                "public_enabled": bool(snap.get("enrichment", {}).get("public_enabled", False)),
                "local_enabled": bool(snap.get("enrichment", {}).get("local_enabled", False)),
                "local_url": snap.get("enrichment", {}).get("local_url", "") or "",
                "local_api_key_set": bool(snap.get("enrichment", {}).get("local_api_key")),
            },
            "restart_required": ["dns.listen_address", "dns.listen_port", "web.listen_address", "web.listen_port"],
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
        upstreams = [u.strip() for u in body.upstreams if u.strip() and not u.strip().startswith("#")]

        def _mutate(data: dict[str, Any]) -> list[str]:
            data.setdefault("dns", {})["upstreams"] = upstreams
            return data["dns"]["upstreams"]

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
                "abuseipdb_api_key_set": bool(enr.get("abuseipdb_api_key")),
                "otx_api_key_set": bool(enr.get("otx_api_key")),
                "public_enabled": bool(enr.get("public_enabled", False)),
                "local_enabled": bool(enr.get("local_enabled", False)),
                "local_url": enr.get("local_url", "") or "",
                "local_api_key_set": bool(enr.get("local_api_key")),
            }

        return config_store.mutate(_mutate)

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
