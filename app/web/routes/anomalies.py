# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Anomalies, their exclusions and false-positive lists."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query

from app.anomaly import _base_domain
from app.web.context import AppContext
from app.web.models import (
    DomainIn,
    ReanalyzeIn,
    RebindingFpIn,
    ThreatIntelFpIn,
    TyposquatFpIn,
)


def register(app: FastAPI, ctx: AppContext) -> None:
    _allowed_client_ips = ctx._allowed_client_ips
    anomaly = ctx.anomaly
    config_store = ctx.config_store
    require_admin = ctx.require_admin
    require_permission = ctx.require_permission
    stats = ctx.stats

    @app.get("/api/anomalies")
    def list_anomalies(
        include_acknowledged: bool = True,
        limit: int = Query(200, ge=1, le=5000),
        user: dict[str, Any] = Depends(require_permission("view_anomalies")),
    ) -> list[dict[str, Any]]:
        if anomaly is None:
            return []
        rows = anomaly.list(include_acknowledged=include_acknowledged, limit=max(1, min(limit, 1000)))
        allowed = _allowed_client_ips(user)
        if allowed is not None:
            rows = [r for r in rows if r.get("client") in allowed]
        return rows

    @app.get("/api/anomalies/count")
    def anomalies_count(_: dict[str, Any] = Depends(require_permission("view_anomalies"))) -> dict[str, int]:
        return {"unacknowledged": anomaly.unacknowledged_count() if anomaly is not None else 0}

    @app.post("/api/anomalies/check-now")
    def anomalies_check_now(_: dict[str, Any] = Depends(require_permission("view_anomalies"))) -> list[dict[str, Any]]:
        if anomaly is None:
            return []
        return anomaly.check_once()

    @app.post("/api/anomalies/reanalyze")
    def anomalies_reanalyze(body: ReanalyzeIn, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        if anomaly is None:
            return []
        hours = max(1.0, min(body.hours, 24 * 30))
        return anomaly.reanalyze(hours)

    @app.get("/api/anomalies/subdomain-analysis")
    def subdomain_analysis(
        hours: float = Query(24, gt=0, le=24 * 90), limit: int = Query(20, ge=1, le=1000), _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        if anomaly is None:
            return []
        hours = max(1.0, min(hours, 24 * 30))
        limit = max(1, min(limit, 100))
        return anomaly.analyze_subdomain_counts(hours=hours, limit=limit)

    @app.get("/api/anomalies/subdomain-analysis/domains")
    def subdomain_analysis_domains(
        base_domain: str, hours: float = 24, _: dict[str, Any] = Depends(require_admin)
    ) -> list[str]:
        if anomaly is None:
            return []
        hours = max(1.0, min(hours, 24 * 30))
        return anomaly.list_subdomains(base_domain.strip().lower().rstrip("."), hours=hours)

    @app.get("/api/anomaly-subdomain-exclusions")
    def list_anomaly_subdomain_exclusions(
        _: dict[str, Any] = Depends(require_permission("view_anomalies")),
    ) -> list[str]:
        return config_store.get("anomaly", "subdomain_count_excluded_domains", default=[]) or []

    @app.post("/api/anomaly-subdomain-exclusions")
    def add_anomaly_subdomain_exclusion(body: DomainIn, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        domain = body.domain.strip().lower().rstrip(".")
        if not domain:
            raise HTTPException(status_code=400, detail="Empty domain")

        def _mutate(data: dict[str, Any]) -> list[str]:
            domains = data.setdefault("anomaly", {}).setdefault("subdomain_count_excluded_domains", [])
            if domain not in domains:
                domains.append(domain)
            return domains

        return config_store.mutate(_mutate)

    @app.delete("/api/anomaly-subdomain-exclusions/{domain:path}")
    def remove_anomaly_subdomain_exclusion(domain: str, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        domain = domain.strip().lower().rstrip(".")

        def _mutate(data: dict[str, Any]) -> list[str]:
            domains = data.setdefault("anomaly", {}).setdefault("subdomain_count_excluded_domains", [])
            if domain in domains:
                domains.remove(domain)
            return domains

        return config_store.mutate(_mutate)

    @app.get("/api/anomalies/{anomaly_id}/domains")
    def anomaly_domains(
        anomaly_id: int, user: dict[str, Any] = Depends(require_permission("view_anomalies"))
    ) -> dict[str, Any]:
        if anomaly is None:
            raise HTTPException(status_code=404, detail="No such anomaly")
        row = anomaly.get(anomaly_id)
        if row is None:
            raise HTTPException(status_code=404, detail="No such anomaly")
        allowed = _allowed_client_ips(user)
        if allowed is not None and row.get("client") not in allowed:
            raise HTTPException(status_code=404, detail="No such anomaly")
        kind = row["kind"]
        details = row["details"] or {}
        if kind.startswith("watched_domain:"):
            domain = details.get("domain")
            return {"domains": [domain] if domain else [], "blocked_only": False}
        window_minutes = details.get("window_minutes")
        if window_minutes is None:
            return {"domains": [], "blocked_only": False}
        until_ts = row["ts"]
        since_ts = until_ts - float(window_minutes) * 60
        blocked_only = kind in ("high_blocked_ratio", "blocked_domain_burst")
        domains = stats.domains_for_client_window(row["client"], since_ts, until_ts, blocked_only=blocked_only)
        if kind in ("dns_tunneling", "subdomain_count_burst"):
            base = details.get("base_domain")
            if base:
                domains = [d for d in domains if _base_domain(d) == base]
        return {"domains": domains, "blocked_only": blocked_only}

    def _check_anomaly_in_scope(anomaly_id: int, user: dict[str, Any]) -> None:
        if anomaly is None:
            raise HTTPException(status_code=404, detail="No such anomaly")
        allowed = _allowed_client_ips(user)
        if allowed is None:
            return
        row = anomaly.get(anomaly_id)
        if row is None or row.get("client") not in allowed:
            raise HTTPException(status_code=404, detail="No such anomaly")

    @app.post("/api/anomalies/{anomaly_id}/acknowledge")
    def acknowledge_anomaly(
        anomaly_id: int, user: dict[str, Any] = Depends(require_permission("view_anomalies"))
    ) -> dict[str, Any]:
        _check_anomaly_in_scope(anomaly_id, user)
        if anomaly is None or not anomaly.acknowledge(anomaly_id):
            raise HTTPException(status_code=404, detail="No such anomaly")
        return {"ok": True}

    @app.post("/api/anomalies/{anomaly_id}/unacknowledge")
    def unacknowledge_anomaly(
        anomaly_id: int, user: dict[str, Any] = Depends(require_permission("view_anomalies"))
    ) -> dict[str, Any]:
        _check_anomaly_in_scope(anomaly_id, user)
        if anomaly is None or not anomaly.unacknowledge(anomaly_id):
            raise HTTPException(status_code=404, detail="No such anomaly")
        return {"ok": True}

    @app.delete("/api/anomalies/{anomaly_id}")
    def delete_anomaly(anomaly_id: int, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        if anomaly is None or not anomaly.delete(anomaly_id):
            raise HTTPException(status_code=404, detail="No such anomaly")
        return {"ok": True}

    @app.delete("/api/anomalies")
    def clear_anomalies(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        if anomaly is not None:
            anomaly.clear()
        return {"ok": True}

    @app.get("/api/anomaly-exclusions")
    def list_anomaly_exclusions(_: dict[str, Any] = Depends(require_permission("view_anomalies"))) -> list[str]:
        return config_store.get("anomaly", "excluded_domains", default=[]) or []

    @app.post("/api/anomaly-exclusions")
    def add_anomaly_exclusion(body: DomainIn, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        domain = body.domain.strip().lower().rstrip(".")
        if not domain:
            raise HTTPException(status_code=400, detail="Empty domain")

        def _mutate(data: dict[str, Any]) -> list[str]:
            domains = data.setdefault("anomaly", {}).setdefault("excluded_domains", [])
            if domain not in domains:
                domains.append(domain)
            return domains

        return config_store.mutate(_mutate)

    @app.delete("/api/anomaly-exclusions/{domain:path}")
    def remove_anomaly_exclusion(domain: str, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        domain = domain.strip().lower().rstrip(".")

        def _mutate(data: dict[str, Any]) -> list[str]:
            domains = data.setdefault("anomaly", {}).setdefault("excluded_domains", [])
            if domain in domains:
                domains.remove(domain)
            return domains

        return config_store.mutate(_mutate)

    @app.get("/api/typosquat-fp")
    def list_typosquat_fp(_: dict[str, Any] = Depends(require_permission("view_anomalies"))) -> list[dict[str, str]]:
        return config_store.get("anomaly", "typosquat_fp_pairs", default=[]) or []

    @app.post("/api/typosquat-fp")
    def add_typosquat_fp(body: TyposquatFpIn, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, str]]:
        domain = body.domain.strip().lower().rstrip(".")
        protected = body.protected.strip().lower().rstrip(".")
        if not domain or not protected:
            raise HTTPException(status_code=400, detail="Empty domain or protected domain")

        def _mutate(data: dict[str, Any]) -> list[dict[str, str]]:
            pairs = data.setdefault("anomaly", {}).setdefault("typosquat_fp_pairs", [])
            if not any(p.get("domain") == domain and p.get("protected") == protected for p in pairs):
                pairs.append({"domain": domain, "protected": protected})
            return pairs

        return config_store.mutate(_mutate)

    @app.delete("/api/typosquat-fp/{domain}/{protected}")
    def remove_typosquat_fp(domain: str, protected: str, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, str]]:
        domain = domain.strip().lower().rstrip(".")
        protected = protected.strip().lower().rstrip(".")

        def _mutate(data: dict[str, Any]) -> list[dict[str, str]]:
            pairs = data.setdefault("anomaly", {}).setdefault("typosquat_fp_pairs", [])
            pairs[:] = [p for p in pairs if not (p.get("domain") == domain and p.get("protected") == protected)]
            return pairs

        return config_store.mutate(_mutate)

    @app.get("/api/rebinding-fp")
    def list_rebinding_fp(_: dict[str, Any] = Depends(require_permission("view_anomalies"))) -> list[dict[str, str]]:
        return config_store.get("anomaly", "rebinding_fp_pairs", default=[]) or []

    @app.post("/api/rebinding-fp")
    def add_rebinding_fp(body: RebindingFpIn, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, str]]:
        domain = body.domain.strip().lower().rstrip(".")
        ip = body.ip.strip()
        if not domain or not ip:
            raise HTTPException(status_code=400, detail="Empty domain or IP")

        def _mutate(data: dict[str, Any]) -> list[dict[str, str]]:
            pairs = data.setdefault("anomaly", {}).setdefault("rebinding_fp_pairs", [])
            if not any(p.get("domain") == domain and p.get("ip") == ip for p in pairs):
                pairs.append({"domain": domain, "ip": ip})
            return pairs

        return config_store.mutate(_mutate)

    @app.delete("/api/rebinding-fp/{domain}/{ip:path}")
    def remove_rebinding_fp(domain: str, ip: str, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, str]]:
        domain = domain.strip().lower().rstrip(".")
        ip = ip.strip()

        def _mutate(data: dict[str, Any]) -> list[dict[str, str]]:
            pairs = data.setdefault("anomaly", {}).setdefault("rebinding_fp_pairs", [])
            pairs[:] = [p for p in pairs if not (p.get("domain") == domain and p.get("ip") == ip)]
            return pairs

        return config_store.mutate(_mutate)

    @app.get("/api/threat-intel-fp")
    def list_threat_intel_fp(_: dict[str, Any] = Depends(require_permission("view_anomalies"))) -> list[dict[str, str]]:
        return config_store.get("anomaly", "threat_intel_fp_targets", default=[]) or []

    @app.post("/api/threat-intel-fp")
    def add_threat_intel_fp(body: ThreatIntelFpIn, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, str]]:
        target = body.target.strip().lower()
        verdict = body.verdict.strip().lower()
        if not target or not verdict:
            raise HTTPException(status_code=400, detail="Empty target or verdict")

        def _mutate(data: dict[str, Any]) -> list[dict[str, str]]:
            targets = data.setdefault("anomaly", {}).setdefault("threat_intel_fp_targets", [])
            for entry in targets:
                if entry.get("target") == target:
                    entry["verdict"] = verdict
                    return targets
            targets.append({"target": target, "verdict": verdict})
            return targets

        return config_store.mutate(_mutate)

    @app.delete("/api/threat-intel-fp/{target:path}")
    def remove_threat_intel_fp(target: str, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, str]]:
        target = target.strip().lower()

        def _mutate(data: dict[str, Any]) -> list[dict[str, str]]:
            targets = data.setdefault("anomaly", {}).setdefault("threat_intel_fp_targets", [])
            targets[:] = [e for e in targets if e.get("target") != target]
            return targets

        return config_store.mutate(_mutate)
