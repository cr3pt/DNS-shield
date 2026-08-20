"""Web UI + REST API.

Everything here only ever reads/writes the local config store and the
local stats snapshot - there is no outbound call of any kind from this
module.
"""

from __future__ import annotations

import secrets
import time
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

STATIC_DIR = Path(__file__).resolve().parent / "static"

security = HTTPBasic()


class BlocklistSourceIn(BaseModel):
    name: str
    url: str
    enabled: bool = True


class DomainIn(BaseModel):
    domain: str


class ClientGroupIn(BaseModel):
    name: str
    match: list[str] = []
    enabled: bool = True
    allowlist: list[str] = []
    denylist: list[str] = []


def create_app(config_store, blocklist, stats, started_at: float, cache=None, client_names=None) -> FastAPI:
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
            "cache": cache.stats() if cache is not None else None,
        }

    @app.get("/api/stats")
    def get_stats(top_n: int = 25, log_n: int = 200, _: None = Depends(require_auth)) -> dict[str, Any]:
        snapshot = stats.snapshot(top_n=top_n, log_n=log_n)
        snapshot["client_names"] = client_names.snapshot() if client_names is not None else {}
        return snapshot

    @app.post("/api/cache/clear")
    def clear_cache(_: None = Depends(require_auth)) -> dict[str, Any]:
        if cache is None:
            raise HTTPException(status_code=404, detail="Cache is disabled")
        cache.clear()
        return {"ok": True}

    @app.get("/api/blocklists")
    def list_blocklists(_: None = Depends(require_auth)) -> list[dict[str, Any]]:
        return config_store.get("blocklists", "sources", default=[]) or []

    @app.post("/api/blocklists")
    def add_blocklist(source: BlocklistSourceIn, _: None = Depends(require_auth)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            sources = data.setdefault("blocklists", {}).setdefault("sources", [])
            sources.append(source.model_dump())
            return sources

        result = config_store.mutate(_mutate)
        blocklist.refresh()
        return result

    @app.delete("/api/blocklists/{index}")
    def delete_blocklist(index: int, _: None = Depends(require_auth)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            sources = data.setdefault("blocklists", {}).setdefault("sources", [])
            if not 0 <= index < len(sources):
                raise HTTPException(status_code=404, detail="No such blocklist")
            sources.pop(index)
            return sources

        result = config_store.mutate(_mutate)
        blocklist.refresh()
        return result

    @app.post("/api/blocklists/{index}/toggle")
    def toggle_blocklist(index: int, _: None = Depends(require_auth)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            sources = data.setdefault("blocklists", {}).setdefault("sources", [])
            if not 0 <= index < len(sources):
                raise HTTPException(status_code=404, detail="No such blocklist")
            sources[index]["enabled"] = not sources[index].get("enabled", True)
            return sources

        result = config_store.mutate(_mutate)
        blocklist.refresh()
        return result

    @app.post("/api/blocklists/refresh")
    def refresh_blocklists(_: None = Depends(require_auth)) -> dict[str, Any]:
        blocklist.refresh()
        return {"ok": True, "domains": blocklist.total_count()}

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

    return app
