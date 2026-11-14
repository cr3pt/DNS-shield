# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Settings pages: DNS, upstreams, web, logging, enrichment, SSO, anomaly, alert rules, URL ping."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException

from app.tls import ensure_self_signed_cert
from app.upstream import address as upstream_address
from app.upstream import is_disabled as upstream_is_disabled
from app.url_safety import check_public_url
from app.web.common import (
    _CLEARABLE_SECRET_PATHS,
    _alert_rules_settings,
    _anomaly_settings,
    _masked_key_preview,
    _new_client_detection_settings,
    _notification_email_settings,
    _notification_webhook_public,
    _ref_index,
    _rogue_dhcp_settings,
    _sso_settings_public,
    _url_ping_settings,
)
from app.web.context import AppContext
from app.web.models import (
    AlertRulesSettingsIn,
    AnomalySettingsIn,
    BlocklistSettingsIn,
    BlocklistSourceIn,
    ClearSecretIn,
    DnsSettingsIn,
    DomainIn,
    EnrichmentSettingsIn,
    LoggingSettingsIn,
    SSOSettingsIn,
    UpstreamsIn,
    UrlPingSettingsIn,
    WebSettingsIn,
)


def register(app: FastAPI, ctx: AppContext) -> None:
    blocklist = ctx.blocklist
    config_store = ctx.config_store
    data_dir = ctx.data_dir
    require_admin = ctx.require_admin

    RESTART_NOTE = "Changing this requires restarting the container (docker compose restart)."

    @app.post("/api/settings/clear-secret")
    def clear_secret(body: ClearSecretIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        if body.path not in _CLEARABLE_SECRET_PATHS:
            raise HTTPException(status_code=400, detail="Unknown or non-clearable field")

        def _mutate(data: dict[str, Any]) -> None:
            parts = body.path.split(".")
            node = data
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = ""

        config_store.mutate(_mutate)
        return {"cleared": body.path}

    @app.get("/api/settings")
    def get_settings(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
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
                "theme": web_cfg.get("theme", "navy"),
                "https_enabled": bool(web_cfg.get("https_enabled", False)),
                "https_cert_path": web_cfg.get("https_cert_path", "") or "",
                "https_key_path": web_cfg.get("https_key_path", "") or "",
                "login_max_attempts": web_cfg.get("login_max_attempts", 5),
                "login_lockout_minutes": web_cfg.get("login_lockout_minutes", 15),
                "public_view_enabled": bool(web_cfg.get("public_view_enabled", False)),
                "public_url": web_cfg.get("public_url", "") or "",
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
                "greynoise_api_key_set": bool(snap.get("enrichment", {}).get("greynoise_api_key")),
                "greynoise_api_key_preview": _masked_key_preview(snap.get("enrichment", {}).get("greynoise_api_key")),
                "shodan_api_key_set": bool(snap.get("enrichment", {}).get("shodan_api_key")),
                "shodan_api_key_preview": _masked_key_preview(snap.get("enrichment", {}).get("shodan_api_key")),
                "urlhaus_api_key_set": bool(snap.get("enrichment", {}).get("urlhaus_api_key")),
                "urlhaus_api_key_preview": _masked_key_preview(snap.get("enrichment", {}).get("urlhaus_api_key")),
                "rdap_enabled": bool(snap.get("enrichment", {}).get("rdap_enabled", True)),
                "crtsh_enabled": bool(snap.get("enrichment", {}).get("crtsh_enabled", False)),
                "ipinfo_enabled": bool(snap.get("enrichment", {}).get("ipinfo_enabled", False)),
                "ipinfo_api_key_set": bool(snap.get("enrichment", {}).get("ipinfo_api_key")),
                "ipinfo_api_key_preview": _masked_key_preview(snap.get("enrichment", {}).get("ipinfo_api_key")),
                "ai_enabled": bool(snap.get("enrichment", {}).get("ai_enabled", False)),
                "ai_api_key_set": bool(snap.get("enrichment", {}).get("ai_api_key")),
                "ai_api_key_preview": _masked_key_preview(snap.get("enrichment", {}).get("ai_api_key")),
                "public_enabled": bool(snap.get("enrichment", {}).get("public_enabled", False)),
                "local_enabled": bool(snap.get("enrichment", {}).get("local_enabled", False)),
                "local_url": snap.get("enrichment", {}).get("local_url", "") or "",
                "local_api_key_set": bool(snap.get("enrichment", {}).get("local_api_key")),
                "local_api_key_preview": _masked_key_preview(snap.get("enrichment", {}).get("local_api_key")),
                "alert_enabled": bool(snap.get("enrichment", {}).get("alert_enabled", True)),
                "alert_min_severity": snap.get("enrichment", {}).get("alert_min_severity", "medium") or "medium",
                "auto_enrich_enabled": bool(snap.get("enrichment", {}).get("auto_enrich_enabled", False)),
                "auto_enrich_interval_seconds": snap.get("enrichment", {}).get("auto_enrich_interval_seconds", 30) or 30,
                "auto_enrich_max_per_check": snap.get("enrichment", {}).get("auto_enrich_max_per_check", 5) or 5,
            },
            "sso": _sso_settings_public(snap.get("sso", {})),
            "anomaly": _anomaly_settings(snap.get("anomaly", {})),
            "alert_rules": _alert_rules_settings(snap.get("alert_rules", {})),
            "url_ping": _url_ping_settings(snap.get("url_ping", {})),
            "dhcp": {"enabled": bool(snap.get("dhcp", {}).get("enabled", False)), "scope_count": len(snap.get("dhcp", {}).get("scopes", []) or [])},
            "proxy": {"enabled": bool(snap.get("proxy", {}).get("enabled", False)), "domain_count": len(snap.get("proxy", {}).get("domains", []) or [])},
            "graph": {
                "suspicious_zscore": snap.get("graph", {}).get("suspicious_zscore", 2.5) or 2.5,
                "suspicious_min_degree": snap.get("graph", {}).get("suspicious_min_degree", 15) or 15,
            },
            "rogue_dhcp_detection": _rogue_dhcp_settings(snap.get("rogue_dhcp_detection", {})),
            "new_client_detection": _new_client_detection_settings(snap.get("new_client_detection", {})),
            "notifications": {
                "email": _notification_email_settings(snap.get("notifications", {}).get("email", {})),
                "webhooks": [
                    _notification_webhook_public(w) for w in (snap.get("notifications", {}).get("webhooks", []) or [])
                ],
            },
            "restart_required": [
                "dns.listen_address",
                "dns.listen_port",
                "web.listen_address",
                "web.listen_port",
                "dns.block_page_enabled",
                "dns.block_page_port",
                "web.https_enabled",
                "web.https_cert_path",
                "web.https_key_path",
                "dns.dot_enabled",
                "dns.dot_port",
            ],
            "restart_note": RESTART_NOTE,
        }

    @app.patch("/api/settings/dns")
    def update_dns_settings(body: DnsSettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            dns_cfg = data.setdefault("dns", {})
            old_max_distance = dns_cfg.get("typosquat_max_distance")
            dns_cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            if dns_cfg.get("typosquat_max_distance") != old_max_distance:
                blocklist.clear_typosquat_cache()
            return {k: v for k, v in dns_cfg.items() if k != "upstreams"}

        return config_store.mutate(_mutate)

    @app.put("/api/settings/upstreams")
    def update_upstreams(body: UpstreamsIn, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        upstreams = [u.strip() for u in body.upstreams if u.strip()]

        def _mutate(data: dict[str, Any]) -> list[str]:
            data.setdefault("dns", {})["upstreams"] = upstreams
            return data["dns"]["upstreams"]

        return config_store.mutate(_mutate)

    @app.post("/api/settings/upstreams/{index}/toggle")
    def toggle_upstream(index: str, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        def _mutate(data: dict[str, Any]) -> list[str]:
            upstreams = data.setdefault("dns", {}).setdefault("upstreams", [])
            pos = _ref_index(upstreams, index, "No such upstream")
            entry = upstreams[pos]
            upstreams[pos] = upstream_address(entry) if upstream_is_disabled(entry) else "#" + entry.strip()
            return upstreams

        return config_store.mutate(_mutate)

    @app.delete("/api/settings/upstreams/{index}")
    def delete_upstream(index: str, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        def _mutate(data: dict[str, Any]) -> list[str]:
            upstreams = data.setdefault("dns", {}).setdefault("upstreams", [])
            pos = _ref_index(upstreams, index, "No such upstream")
            upstreams.pop(pos)
            return upstreams

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/web")
    def update_web_settings(body: WebSettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            web_cfg = data.setdefault("web", {})
            payload = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
            web_cfg.update(payload)
            return web_cfg

        return config_store.mutate(_mutate)

    @app.post("/api/settings/web/migrate-https")
    def migrate_to_https(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        web_cfg = config_store.snapshot().get("web", {})
        cert_path_cfg = web_cfg.get("https_cert_path", "") or ""
        key_path_cfg = web_cfg.get("https_key_path", "") or ""
        if not cert_path_cfg or not key_path_cfg:
            try:
                ensure_self_signed_cert(data_dir / "tls" / "cert.pem", data_dir / "tls" / "key.pem")
            except OSError as exc:
                raise HTTPException(status_code=500, detail=f"Could not generate a self-signed certificate: {exc}") from exc

        def _mutate(data: dict[str, Any]) -> None:
            data.setdefault("web", {})["https_enabled"] = True

        config_store.mutate(_mutate)
        return {"https_enabled": True, "restart_required": True, "restart_note": RESTART_NOTE}

    @app.patch("/api/settings/logging")
    def update_logging_settings(body: LoggingSettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            logging_cfg = data.setdefault("logging", {})
            logging_cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return logging_cfg

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/blocklists")
    def update_blocklist_settings(body: BlocklistSettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            bl_cfg = data.setdefault("blocklists", {})
            bl_cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return {k: v for k, v in bl_cfg.items() if k not in ("sources", "allow_sources")}

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/enrichment")
    def update_enrichment_settings(body: EnrichmentSettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        keep_if_blank = {
            "virustotal_api_key",
            "abuseipdb_api_key",
            "otx_api_key",
            "greynoise_api_key",
            "shodan_api_key",
            "urlhaus_api_key",
            "ipinfo_api_key",
            "ai_api_key",
            "local_api_key",
        }
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
                "greynoise_api_key_set": bool(enr.get("greynoise_api_key")),
                "greynoise_api_key_preview": _masked_key_preview(enr.get("greynoise_api_key")),
                "shodan_api_key_set": bool(enr.get("shodan_api_key")),
                "shodan_api_key_preview": _masked_key_preview(enr.get("shodan_api_key")),
                "urlhaus_api_key_set": bool(enr.get("urlhaus_api_key")),
                "urlhaus_api_key_preview": _masked_key_preview(enr.get("urlhaus_api_key")),
                "rdap_enabled": bool(enr.get("rdap_enabled", True)),
                "crtsh_enabled": bool(enr.get("crtsh_enabled", False)),
                "ipinfo_enabled": bool(enr.get("ipinfo_enabled", False)),
                "ipinfo_api_key_set": bool(enr.get("ipinfo_api_key")),
                "ipinfo_api_key_preview": _masked_key_preview(enr.get("ipinfo_api_key")),
                "ai_enabled": bool(enr.get("ai_enabled", False)),
                "ai_api_key_set": bool(enr.get("ai_api_key")),
                "ai_api_key_preview": _masked_key_preview(enr.get("ai_api_key")),
                "public_enabled": bool(enr.get("public_enabled", False)),
                "local_enabled": bool(enr.get("local_enabled", False)),
                "local_url": enr.get("local_url", "") or "",
                "local_api_key_set": bool(enr.get("local_api_key")),
                "local_api_key_preview": _masked_key_preview(enr.get("local_api_key")),
                "alert_enabled": bool(enr.get("alert_enabled", True)),
                "alert_min_severity": enr.get("alert_min_severity", "medium") or "medium",
                "auto_enrich_enabled": bool(enr.get("auto_enrich_enabled", False)),
                "auto_enrich_interval_seconds": enr.get("auto_enrich_interval_seconds", 30) or 30,
                "auto_enrich_max_per_check": enr.get("auto_enrich_max_per_check", 5) or 5,
            }

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/sso")
    def update_sso_settings(body: SSOSettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        keep_if_blank = {"client_secret"}
        data_in = body.model_dump(exclude_unset=True)
        if "default_role" in data_in and data_in["default_role"] not in ("admin", "user"):
            raise HTTPException(status_code=400, detail='Default role must be "admin" or "user"')
        payload = {k: v for k, v in data_in.items() if (v if k in keep_if_blank else v is not None)}

        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            data.setdefault("sso", {}).update(payload)
            return _sso_settings_public(data["sso"])

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/anomaly")
    def update_anomaly_settings(body: AnomalySettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            anomaly_cfg = data.setdefault("anomaly", {})
            anomaly_cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return _anomaly_settings(anomaly_cfg)

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/alert-rules")
    def update_alert_rules_settings(body: AlertRulesSettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            cfg = data.setdefault("alert_rules", {})
            cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return _alert_rules_settings(cfg)

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/url-ping")
    def update_url_ping_settings(body: UrlPingSettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            cfg = data.setdefault("url_ping", {})
            cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return _url_ping_settings(cfg)

        return config_store.mutate(_mutate)

    def _add_alert_domain(domain: str) -> list[str]:
        domain = domain.strip().lower().rstrip(".")
        if not domain:
            raise HTTPException(status_code=400, detail="Empty domain")

        def _mutate(data: dict[str, Any]) -> list[str]:
            domains = data.setdefault("alert_rules", {}).setdefault("domains", [])
            if domain not in domains:
                domains.append(domain)
            return domains

        result = config_store.mutate(_mutate)
        blocklist.refresh()
        return result

    def _remove_alert_domain(domain: str) -> list[str]:
        domain = domain.strip().lower().rstrip(".")

        def _mutate(data: dict[str, Any]) -> list[str]:
            domains = data.setdefault("alert_rules", {}).setdefault("domains", [])
            if domain in domains:
                domains.remove(domain)
            return domains

        result = config_store.mutate(_mutate)
        blocklist.refresh()
        return result

    @app.get("/api/alert-rules/domains")
    def list_alert_domains(_: dict[str, Any] = Depends(require_admin)) -> list[str]:
        return config_store.get("alert_rules", "domains", default=[]) or []

    @app.post("/api/alert-rules/domains")
    def add_alert_domain(body: DomainIn, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        return _add_alert_domain(body.domain)

    @app.delete("/api/alert-rules/domains/{domain:path}")
    def remove_alert_domain(domain: str, _: dict[str, Any] = Depends(require_admin)) -> list[str]:
        return _remove_alert_domain(domain)

    @app.get("/api/alert-rules/sources")
    def list_alert_sources(_: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return config_store.get("alert_rules", "sources", default=[]) or []

    @app.post("/api/alert-rules/sources")
    def add_alert_source(source: BlocklistSourceIn, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        try:
            check_public_url(source.url)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            sources = data.setdefault("alert_rules", {}).setdefault("sources", [])
            sources.append(source.model_dump())
            return sources

        result = config_store.mutate(_mutate)
        blocklist.refresh()
        return result

    @app.delete("/api/alert-rules/sources/{index}")
    def delete_alert_source(index: str, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            sources = data.setdefault("alert_rules", {}).setdefault("sources", [])
            pos = _ref_index(sources, index, "No such list")
            sources.pop(pos)
            return sources

        result = config_store.mutate(_mutate)
        blocklist.refresh()
        return result

    @app.post("/api/alert-rules/sources/{index}/toggle")
    def toggle_alert_source(index: str, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            sources = data.setdefault("alert_rules", {}).setdefault("sources", [])
            pos = _ref_index(sources, index, "No such list")
            sources[pos]["enabled"] = not sources[pos].get("enabled", True)
            return sources

        result = config_store.mutate(_mutate)
        blocklist.refresh()
        return result
