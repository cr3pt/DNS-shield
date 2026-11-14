# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Domain lookup and threat-intel enrichment."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query

from app.enrichment import enrich as run_enrichment
from app.enrichment import maybe_alert_on_verdict
from app.netmatch import ip_matches
from app.web.common import logger
from app.web.context import AppContext
from app.web.models import EnrichIn


def register(app: FastAPI, ctx: AppContext) -> None:
    _allowed_client_ips = ctx._allowed_client_ips
    anomaly = ctx.anomaly
    blocklist = ctx.blocklist
    config_store = ctx.config_store
    enrichment_store = ctx.enrichment_store
    require_auth = ctx.require_auth
    require_permission = ctx.require_permission
    stats = ctx.stats

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
    def enrichment_history(limit: int = Query(100, ge=1, le=1000), target: str | None = None, _: dict[str, Any] = Depends(require_permission("view_threat_intel"))) -> list[dict[str, Any]]:
        if enrichment_store is None:
            return []
        limit = max(1, min(limit, 500))
        if target:
            return enrichment_store.history_for(target.strip(), limit=limit)
        return enrichment_store.recent(limit=limit)
