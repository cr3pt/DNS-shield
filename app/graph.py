# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from app.domain_suffix import registrable_domain

logger = logging.getLogger("dnsshield.graph")

_POLL_INTERVAL_SECONDS = 10
_REVERSE_DNS_SUFFIXES = (".in-addr.arpa", ".ip6.arpa")
_PROJECTION_NEIGHBOURS = 3
_CLUSTER_MIN_WEIGHT = 0.4
_CLUSTER_MAX_ROUNDS = 30
_PROJECTION_MAX_NODES = 300
GRAPH_VIEWS = ("bipartite", "domains", "clients")

SCHEMA = """
CREATE TABLE IF NOT EXISTS edges (
    client TEXT NOT NULL,
    domain TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    blocked_count INTEGER NOT NULL DEFAULT 0,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    PRIMARY KEY (client, domain)
);
CREATE INDEX IF NOT EXISTS idx_edges_client ON edges(client);
CREATE INDEX IF NOT EXISTS idx_edges_domain ON edges(domain);
"""


def _degree_scores(degrees: list[int], zscore_threshold: float, min_degree: int) -> tuple[float, float]:
    n = len(degrees)
    if n == 0:
        return 0.0, 0.0
    mean = sum(degrees) / n
    variance = sum((d - mean) ** 2 for d in degrees) / n
    return mean, variance**0.5


def _communities(candidates: list[tuple[float, int, str, str]]) -> dict[str, int]:
    neighbours: dict[str, list[tuple[str, float]]] = {}
    for weight, _shared, left_id, right_id in candidates:
        if weight < _CLUSTER_MIN_WEIGHT:
            continue
        neighbours.setdefault(left_id, []).append((right_id, weight))
        neighbours.setdefault(right_id, []).append((left_id, weight))
    order = sorted(neighbours)
    label = {node: index for index, node in enumerate(order)}
    for _ in range(_CLUSTER_MAX_ROUNDS):
        changed = False
        for node in order:
            totals: dict[int, float] = {}
            for other, weight in neighbours[node]:
                totals[label[other]] = totals.get(label[other], 0.0) + weight
            best = max(totals, key=lambda lab: (round(totals[lab], 9), -lab))
            if best != label[node] and round(totals[best], 9) > round(totals.get(label[node], 0.0), 9):
                label[node] = best
                changed = True
        if not changed:
            break
    members: dict[int, list[str]] = {}
    for node, lab in label.items():
        members.setdefault(lab, []).append(node)
    groups = sorted((nodes for nodes in members.values() if len(nodes) > 1), key=lambda nodes: (-len(nodes), min(nodes)))
    return {node: index for index, nodes in enumerate(groups) for node in nodes}


class ClientDomainGraph:
    def __init__(self, config_store, stats, db_path: Path):
        self._config = config_store
        self._stats = stats
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._cursor: int | None = None
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="client-domain-graph", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _loop(self) -> None:
        while not self._stop_event.wait(_POLL_INTERVAL_SECONDS):
            try:
                self._process_new_queries()
            except Exception:
                logger.exception("client-domain graph aggregation failed")

    def _process_new_queries(self) -> None:
        if self._cursor is None:
            self._cursor = self._stats.max_query_id()
            return
        rows = self._stats.queries_since(self._cursor, limit=5000)
        if not rows:
            return
        self._cursor = max(row["id"] for row in rows)

        with self._lock:
            conn = self._connect()
            try:
                for row in rows:
                    qname = (row["domain"] or "").rstrip(".").lower()
                    if not qname or qname.endswith(_REVERSE_DNS_SUFFIXES):
                        continue
                    domain = registrable_domain(qname)
                    if not domain:
                        continue
                    blocked_inc = 1 if row["blocked"] else 0
                    conn.execute(
                        "INSERT INTO edges (client, domain, count, blocked_count, first_seen, last_seen) "
                        "VALUES (?, ?, 1, ?, ?, ?) "
                        "ON CONFLICT(client, domain) DO UPDATE SET "
                        "count = count + 1, blocked_count = blocked_count + excluded.blocked_count, "
                        "last_seen = excluded.last_seen",
                        (row["client"], domain, blocked_inc, row["ts"], row["ts"]),
                    )
                conn.commit()
            finally:
                conn.close()

    def clear(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM edges")
                conn.commit()
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                conn.close()

    def distinct_clients(self) -> list[str]:
        conn = self._connect()
        try:
            return [row[0] for row in conn.execute("SELECT DISTINCT client FROM edges")]
        finally:
            conn.close()

    def get_graph(
        self,
        restrict_client_ips: list[str] | None = None,
        min_count: int = 1,
        limit_nodes: int = 150,
        view: str = "bipartite",
    ) -> dict[str, Any]:
        if view not in GRAPH_VIEWS:
            raise ValueError(f"Unknown graph view: {view}")
        zscore_threshold = float(self._config.get("graph", "suspicious_zscore", default=2.5))
        min_degree = int(self._config.get("graph", "suspicious_min_degree", default=15))

        where = ["count >= ?"]
        params: list[Any] = [min_count]
        if restrict_client_ips is not None:
            if not restrict_client_ips:
                where.append("0")
            else:
                where.append("client IN (%s)" % ",".join("?" for _ in restrict_client_ips))
                params.extend(restrict_client_ips)
        where_sql = " AND ".join(where)

        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            client_rows = conn.execute(
                f"SELECT client, COUNT(*) AS degree, SUM(count) AS total, SUM(blocked_count) AS blocked, "
                f"MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen "
                f"FROM edges WHERE {where_sql} GROUP BY client",
                params,
            ).fetchall()
            domain_rows = conn.execute(
                f"SELECT domain, COUNT(*) AS degree, SUM(count) AS total, SUM(blocked_count) AS blocked, "
                f"MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen "
                f"FROM edges WHERE {where_sql} GROUP BY domain",
                params,
            ).fetchall()

            client_mean, client_std = _degree_scores([r["degree"] for r in client_rows], zscore_threshold, min_degree)
            domain_mean, domain_std = _degree_scores([r["degree"] for r in domain_rows], zscore_threshold, min_degree)

            def _score(degree: int, mean: float, std: float) -> float:
                return (degree - mean) / std if std > 0 else 0.0

            clients = [
                {
                    "id": r["client"],
                    "degree": r["degree"],
                    "total": r["total"],
                    "blocked": r["blocked"] or 0,
                    "first_seen": r["first_seen"],
                    "last_seen": r["last_seen"],
                    "score": round(_score(r["degree"], client_mean, client_std), 2),
                    "suspicious": r["degree"] >= min_degree and _score(r["degree"], client_mean, client_std) >= zscore_threshold,
                }
                for r in client_rows
            ]
            domains = [
                {
                    "id": r["domain"],
                    "degree": r["degree"],
                    "total": r["total"],
                    "blocked": r["blocked"] or 0,
                    "first_seen": r["first_seen"],
                    "last_seen": r["last_seen"],
                    "score": round(_score(r["degree"], domain_mean, domain_std), 2),
                    "suspicious": r["degree"] >= min_degree and _score(r["degree"], domain_mean, domain_std) >= zscore_threshold,
                }
                for r in domain_rows
            ]

            clients.sort(key=lambda c: c["total"], reverse=True)
            domains.sort(key=lambda d: d["total"], reverse=True)
            if view != "bipartite":
                limit_nodes = min(limit_nodes, _PROJECTION_MAX_NODES) if limit_nodes > 0 else _PROJECTION_MAX_NODES
            truncated = limit_nodes > 0 and (len(clients) > limit_nodes or len(domains) > limit_nodes)
            if limit_nodes > 0:
                clients = clients[:limit_nodes]
                domains = domains[:limit_nodes]

            client_ids = {c["id"] for c in clients}
            domain_ids = {d["id"] for d in domains}
            links: list[dict[str, Any]] = []
            if view != "bipartite":
                edges: list[dict[str, Any]] = []
                node_column = "domain" if view == "domains" else "client"
                links, clusters = self._projection(
                    conn, node_column, domain_ids if view == "domains" else client_ids, min_count, restrict_client_ips
                )
                shown = domains if view == "domains" else clients
                for node in shown:
                    node["cluster"] = clusters.get(node["id"])
                if view == "domains":
                    clients = []
                else:
                    domains = []
            elif not client_ids or not domain_ids:
                edges = []
            else:
                edge_where = where_sql
                edge_params = list(params)
                edge_where += " AND client IN (%s) AND domain IN (%s)" % (
                    ",".join("?" for _ in client_ids),
                    ",".join("?" for _ in domain_ids),
                )
                edge_params.extend(client_ids)
                edge_params.extend(domain_ids)
                edge_rows = conn.execute(
                    f"SELECT client, domain, count, blocked_count, first_seen, last_seen FROM edges "
                    f"WHERE {edge_where}",
                    edge_params,
                ).fetchall()
                edges = [
                    {
                        "client": r["client"],
                        "domain": r["domain"],
                        "count": r["count"],
                        "blocked": r["blocked_count"],
                        "first_seen": r["first_seen"],
                        "last_seen": r["last_seen"],
                    }
                    for r in edge_rows
                ]
        finally:
            conn.close()

        return {
            "clients": clients,
            "domains": domains,
            "edges": edges,
            "links": links,
            "truncated": truncated,
            "view": view,
        }

    @staticmethod
    def _projection(
        conn: sqlite3.Connection,
        node_column: str,
        node_ids: set[str],
        min_count: int,
        restrict_client_ips: list[str] | None,
    ) -> tuple[list[dict[str, Any]], dict[str, int]]:
        if node_column not in ("client", "domain") or len(node_ids) < 2:
            return [], {}
        other_column = "client" if node_column == "domain" else "domain"
        ids = sorted(node_ids)
        marks = ",".join("?" for _ in ids)

        def _filters(alias: str) -> tuple[str, list[Any]]:
            sql = f"{alias}.count >= ? AND {alias}.{node_column} IN ({marks})"
            params: list[Any] = [min_count, *ids]
            if restrict_client_ips is not None:
                if not restrict_client_ips:
                    return sql + " AND 0", params
                sql += f" AND {alias}.client IN ({','.join('?' for _ in restrict_client_ips)})"
                params.extend(restrict_client_ips)
            return sql, params

        a_sql, a_params = _filters("a")
        b_sql, b_params = _filters("b")
        pair_rows = conn.execute(
            f"SELECT a.{node_column} AS left_id, b.{node_column} AS right_id, "
            f"COUNT(*) AS shared, SUM(a.count * b.count) AS dot "
            f"FROM edges a JOIN edges b ON a.{other_column} = b.{other_column} "
            f"AND a.{node_column} < b.{node_column} "
            f"WHERE {a_sql} AND {b_sql} GROUP BY a.{node_column}, b.{node_column}",
            [*a_params, *b_params],
        ).fetchall()
        if not pair_rows:
            return [], {}
        n_sql, n_params = _filters("e")
        norms = {
            row[0]: row[1] ** 0.5
            for row in conn.execute(
                f"SELECT e.{node_column}, SUM(e.count * e.count) FROM edges e WHERE {n_sql} GROUP BY e.{node_column}",
                n_params,
            )
        }

        candidates: list[tuple[float, int, str, str]] = []
        for left_id, right_id, shared, dot in pair_rows:
            denominator = norms.get(left_id, 0.0) * norms.get(right_id, 0.0)
            if denominator <= 0:
                continue
            candidates.append((dot / denominator, shared, left_id, right_id))
        candidates.sort(key=lambda c: (-c[0], -c[1], c[2], c[3]))

        clusters = _communities(candidates)

        taken: dict[str, int] = {}
        links: list[dict[str, Any]] = []
        for weight, shared, left_id, right_id in candidates:
            if taken.get(left_id, 0) >= _PROJECTION_NEIGHBOURS and taken.get(right_id, 0) >= _PROJECTION_NEIGHBOURS:
                continue
            taken[left_id] = taken.get(left_id, 0) + 1
            taken[right_id] = taken.get(right_id, 0) + 1
            links.append({"a": left_id, "b": right_id, "shared": shared, "weight": round(weight, 3)})
        return links, clusters

    def client_detail(self, client: str, restrict_client_ips: list[str] | None = None) -> dict[str, Any] | None:
        if restrict_client_ips is not None and client not in restrict_client_ips:
            return None
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT domain, count, blocked_count, first_seen, last_seen FROM edges "
                "WHERE client = ? ORDER BY count DESC",
                (client,),
            ).fetchall()
        finally:
            conn.close()
        if not rows:
            return {"client": client, "domains": [], "distinct_domains": 0, "total_count": 0}
        return {
            "client": client,
            "domains": [
                {
                    "domain": r["domain"],
                    "count": r["count"],
                    "blocked": r["blocked_count"],
                    "first_seen": r["first_seen"],
                    "last_seen": r["last_seen"],
                }
                for r in rows
            ],
            "distinct_domains": len(rows),
            "total_count": sum(r["count"] for r in rows),
        }

    def domain_detail(self, domain: str, restrict_client_ips: list[str] | None = None) -> dict[str, Any]:
        where = ["domain = ?"]
        params: list[Any] = [domain]
        if restrict_client_ips is not None:
            if not restrict_client_ips:
                where.append("0")
            else:
                where.append("client IN (%s)" % ",".join("?" for _ in restrict_client_ips))
                params.extend(restrict_client_ips)
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                f"SELECT client, count, blocked_count, first_seen, last_seen FROM edges "
                f"WHERE {' AND '.join(where)} ORDER BY count DESC",
                params,
            ).fetchall()
        finally:
            conn.close()
        return {
            "domain": domain,
            "clients": [
                {
                    "client": r["client"],
                    "count": r["count"],
                    "blocked": r["blocked_count"],
                    "first_seen": r["first_seen"],
                    "last_seen": r["last_seen"],
                }
                for r in rows
            ],
            "distinct_clients": len(rows),
            "total_count": sum(r["count"] for r in rows),
        }
