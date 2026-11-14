# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Public summary, health, metrics, the dashboard page, status and pause."""

from __future__ import annotations

import base64
import time
from typing import Any

from dnslib import DNSRecord
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, Response

from app.metrics import render_metrics
from app.web.common import STATIC_DIR
from app.web.context import AppContext
from app.web.models import PauseIn


def register(app: FastAPI, ctx: AppContext) -> None:
    NO_CACHE = ctx.NO_CACHE
    anomaly = ctx.anomaly
    blocklist = ctx.blocklist
    cache = ctx.cache
    config_store = ctx.config_store
    dnssec_cache = ctx.dnssec_cache
    require_admin = ctx.require_admin
    require_auth = ctx.require_auth
    resolver = ctx.resolver
    started_at = ctx.started_at
    stats = ctx.stats
    upstream_stats = ctx.upstream_stats

    @app.get("/api/public/summary")
    def public_summary() -> dict[str, Any]:
        if not config_store.get("web", "public_view_enabled", default=False):
            raise HTTPException(status_code=404, detail="The public view is turned off")
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
                raise HTTPException(status_code=400, detail="Malformed DNS message") from None
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
                raise HTTPException(status_code=400, detail="Invalid base64url encoding") from None
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
            "blocklist_refreshing": blocklist.refresh_pending(),
            "source_updates": blocklist.source_update_info(),
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
