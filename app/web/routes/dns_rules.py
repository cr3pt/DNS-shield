# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Per-domain upstreams and DNS rewrites."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException

from app import dns_rewrites
from app.web.common import _ref_index
from app.web.context import AppContext
from app.web.models import DomainUpstreamIn, RewriteIn


def register(app: FastAPI, ctx: AppContext) -> None:
    config_store = ctx.config_store
    require_admin = ctx.require_admin
    cache = ctx.cache

    def _drop_cached_answers(data: dict[str, Any]) -> None:
        """A changed per-domain rule must take effect now, not when the
        answers cached from the previous upstream expire. Clearing here
        covers this process; bumping the generation (saved with the same
        change) tells extra DNS workers to drop their caches too."""
        if cache is None:
            return
        cache.clear()
        dns = data.setdefault("dns", {})
        dns["cache_generation"] = int(dns.get("cache_generation") or 0) + 1

    @app.get("/api/domain-upstreams")
    def list_domain_upstreams(_: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return config_store.get("domain_upstreams", default=[]) or []

    @app.post("/api/domain-upstreams")
    def add_domain_upstream(rule: DomainUpstreamIn, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            rules = data.setdefault("domain_upstreams", [])
            rules.append(rule.model_dump())
            _drop_cached_answers(data)
            return rules

        return config_store.mutate(_mutate)

    @app.delete("/api/domain-upstreams/{index}")
    def delete_domain_upstream(index: str, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            rules = data.setdefault("domain_upstreams", [])
            pos = _ref_index(rules, index, "No such rule")
            rules.pop(pos)
            _drop_cached_answers(data)
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
    def delete_rewrite(index: str, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            rewrites = data.setdefault("dns_rewrites", [])
            pos = _ref_index(rewrites, index, "No such rewrite")
            rewrites.pop(pos)
            return rewrites

        return config_store.mutate(_mutate)
