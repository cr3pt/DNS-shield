# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Statistics, the client/domain graph and the query log."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query

from app.graph import GRAPH_VIEWS
from app.web.context import AppContext
from app.web.models import GraphSettingsIn


def register(app: FastAPI, ctx: AppContext) -> None:
    _allowed_client_ips = ctx._allowed_client_ips
    anomaly = ctx.anomaly
    blocklist = ctx.blocklist
    client_domain_graph = ctx.client_domain_graph
    client_names = ctx.client_names
    config_store = ctx.config_store
    require_admin = ctx.require_admin
    require_auth = ctx.require_auth
    require_permission = ctx.require_permission
    stats = ctx.stats

    @app.get("/api/stats")
    def get_stats(
        top_n: int = Query(25, ge=1, le=500), log_n: int = Query(200, ge=0, le=5000), user: dict[str, Any] = Depends(require_auth)
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
        min_count: int = Query(1, ge=1, le=1_000_000),
        limit_nodes: int = Query(150, ge=1, le=2000),
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
        limit: int = Query(100, ge=1, le=5000),
        offset: int = Query(0, ge=0),
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
