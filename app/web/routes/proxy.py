# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Reverse proxy domains, certificates and settings."""

from __future__ import annotations

import re
import time
from typing import Any

from fastapi import Depends, FastAPI, HTTPException

from app.proxy import (
    access as proxy_access,
)
from app.proxy import (
    certbot_manager as proxy_certbot,
)
from app.proxy import (
    domain as proxy_domain,
)
from app.proxy import (
    healthcheck as proxy_healthcheck,
)
from app.proxy import (
    nginx_manager,
)
from app.proxy import (
    validate as proxy_validate,
)
from app.web.context import AppContext
from app.web.models import ProxyCertbotIn, ProxyDomainIn, ProxySettingsIn


def register(app: FastAPI, ctx: AppContext) -> None:
    config_store = ctx.config_store
    require_admin = ctx.require_admin
    require_permission = ctx.require_permission

    def _find_proxy_domain_index(domains: list[dict[str, Any]], domain_id: str) -> int:
        for i, d in enumerate(domains):
            if d.get("id") == domain_id:
                return i
        return -1

    def _normalize_proxy_domain(body: ProxyDomainIn, user: dict[str, Any], existing: dict[str, Any] | None = None):
        payload = body.model_dump()
        if payload.get("custom_config") and user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Custom config is only available to administrators")
        try:
            normalized = proxy_domain.normalize_domain(payload, existing)
        except proxy_validate.ValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not proxy_access.is_domain_allowed(user, normalized["hostnames"]):
            raise HTTPException(status_code=403, detail="You don't have access to one of these domains")
        return normalized

    @app.get("/api/proxy/domains")
    def list_proxy_domains(
        user: dict[str, Any] = Depends(require_permission("can_manage_proxy")),
    ) -> list[dict[str, Any]]:
        domains = config_store.get("proxy", "domains", default=[]) or []
        return [d for d in domains if proxy_access.is_domain_allowed(user, d.get("hostnames"))]

    @app.post("/api/proxy/domains/preview")
    def preview_proxy_domain(
        body: ProxyDomainIn, user: dict[str, Any] = Depends(require_permission("can_manage_proxy"))
    ) -> dict[str, str]:
        normalized = _normalize_proxy_domain(body, user)
        return {"config": nginx_manager.preview_domain(normalized)}

    @app.post("/api/proxy/domains")
    def add_proxy_domain(
        body: ProxyDomainIn, user: dict[str, Any] = Depends(require_permission("can_manage_proxy"))
    ) -> dict[str, Any]:
        normalized = _normalize_proxy_domain(body, user)

        existing_domains = config_store.get("proxy", "domains", default=[]) or []
        used = {h for d in existing_domains for h in d.get("hostnames", [])}
        if used & set(normalized["hostnames"]):
            raise HTTPException(status_code=409, detail="One of these domains is already used by another entry")

        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            domains = data.setdefault("proxy", {}).setdefault("domains", [])
            domains.append(normalized)
            return domains

        config_store.mutate(_mutate)
        apply_result = nginx_manager.apply_domain(normalized)
        return {"domain": normalized, "apply": apply_result}

    @app.put("/api/proxy/domains/{domain_id}")
    def update_proxy_domain(
        domain_id: str, body: ProxyDomainIn, user: dict[str, Any] = Depends(require_permission("can_manage_proxy"))
    ) -> dict[str, Any]:
        domains = config_store.get("proxy", "domains", default=[]) or []
        idx = _find_proxy_domain_index(domains, domain_id)
        if idx < 0 or not proxy_access.is_domain_allowed(user, domains[idx].get("hostnames")):
            raise HTTPException(status_code=404, detail="Domain not found")

        normalized = _normalize_proxy_domain(body, user, existing=domains[idx])
        used = {h for i, d in enumerate(domains) if i != idx for h in d.get("hostnames", [])}
        if used & set(normalized["hostnames"]):
            raise HTTPException(status_code=409, detail="One of these domains is already used by another entry")

        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            domains_ = data.setdefault("proxy", {}).setdefault("domains", [])
            domains_[idx] = normalized
            return domains_

        config_store.mutate(_mutate)
        apply_result = nginx_manager.apply_domain(normalized)
        return {"domain": normalized, "apply": apply_result}

    @app.delete("/api/proxy/domains/{domain_id}")
    def delete_proxy_domain(
        domain_id: str, user: dict[str, Any] = Depends(require_permission("can_manage_proxy"))
    ) -> dict[str, Any]:
        domains = config_store.get("proxy", "domains", default=[]) or []
        idx = _find_proxy_domain_index(domains, domain_id)
        if idx < 0 or not proxy_access.is_domain_allowed(user, domains[idx].get("hostnames")):
            raise HTTPException(status_code=404, detail="Domain not found")

        remove_result = nginx_manager.remove_domain_config(domain_id)
        if not remove_result["ok"]:
            raise HTTPException(status_code=500, detail=f"Could not remove nginx config: {remove_result['error']}")

        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            domains_ = data.setdefault("proxy", {}).setdefault("domains", [])
            domains_.pop(idx)
            return domains_

        return {"domains": config_store.mutate(_mutate)}

    @app.post("/api/proxy/domains/{domain_id}/toggle")
    def toggle_proxy_domain(
        domain_id: str, user: dict[str, Any] = Depends(require_permission("can_manage_proxy"))
    ) -> dict[str, Any]:
        domains = config_store.get("proxy", "domains", default=[]) or []
        idx = _find_proxy_domain_index(domains, domain_id)
        if idx < 0 or not proxy_access.is_domain_allowed(user, domains[idx].get("hostnames")):
            raise HTTPException(status_code=404, detail="Domain not found")

        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            domains_ = data.setdefault("proxy", {}).setdefault("domains", [])
            domains_[idx]["enabled"] = not domains_[idx].get("enabled", True)
            domains_[idx]["updated_at"] = time.time()
            return domains_[idx]

        updated = config_store.mutate(_mutate)
        apply_result = nginx_manager.apply_domain(updated)
        return {"domain": updated, "apply": apply_result}

    @app.get("/api/proxy/domains/{domain_id}/health")
    def proxy_domain_health(
        domain_id: str, user: dict[str, Any] = Depends(require_permission("can_manage_proxy"))
    ) -> dict[str, Any]:
        domains = config_store.get("proxy", "domains", default=[]) or []
        idx = _find_proxy_domain_index(domains, domain_id)
        if idx < 0 or not proxy_access.is_domain_allowed(user, domains[idx].get("hostnames")):
            raise HTTPException(status_code=404, detail="Domain not found")

        domain = domains[idx]
        use_https = bool(domain.get("ssl", {}).get("enabled"))
        resolver = f"127.0.0.1:{config_store.get('dns', 'listen_port', default=53)}"
        return proxy_healthcheck.check_domain_health(domain["hostnames"], domain.get("rules"), use_https, resolver)

    @app.post("/api/proxy/domains/{domain_id}/certbot")
    def issue_proxy_certificate(
        domain_id: str, body: ProxyCertbotIn, _: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        domains = config_store.get("proxy", "domains", default=[]) or []
        idx = _find_proxy_domain_index(domains, domain_id)
        if idx < 0:
            raise HTTPException(status_code=404, detail="Domain not found")
        if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", body.email):
            raise HTTPException(status_code=400, detail="Provide a valid email address (required by Let's Encrypt)")

        result = proxy_certbot.issue_certificate(domains[idx]["hostnames"], body.email)
        if not result["ok"]:
            raise HTTPException(status_code=500, detail=result["error"])

        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            domains_ = data.setdefault("proxy", {}).setdefault("domains", [])
            domains_[idx]["ssl"] = {"enabled": True, "cert_path": result["cert_path"], "key_path": result["key_path"]}
            domains_[idx]["updated_at"] = time.time()
            return domains_[idx]

        updated = config_store.mutate(_mutate)
        apply_result = nginx_manager.apply_domain(updated)
        return {"domain": updated, "apply": apply_result, "certbot": result}

    @app.get("/api/proxy/status")
    def proxy_status(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        return {"nginx": nginx_manager.test_config()}

    @app.post("/api/proxy/reload")
    def proxy_reload(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        test = nginx_manager.test_config()
        if not test["ok"]:
            raise HTTPException(status_code=400, detail=f"nginx config has errors, reload aborted: {test['stderr'] or test['stdout']}")
        reload_result = nginx_manager.reload_nginx()
        return {"ok": reload_result["ok"], "details": reload_result["stderr"] or reload_result["stdout"]}

    @app.patch("/api/settings/proxy")
    def update_proxy_settings(body: ProxySettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            cfg = data.setdefault("proxy", {})
            cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return {"enabled": bool(cfg.get("enabled", False))}

        return config_store.mutate(_mutate)
