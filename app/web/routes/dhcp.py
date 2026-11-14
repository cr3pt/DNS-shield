# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""DHCP scopes, reservations, leases and client detection settings."""

from __future__ import annotations

import time
from typing import Any

from fastapi import Depends, FastAPI, HTTPException

from app import new_client_detection
from app.web.common import (
    _new_client_detection_settings,
    _ref_index,
    _rogue_dhcp_settings,
)
from app.web.context import AppContext
from app.web.models import (
    DhcpReservationIn,
    DhcpScopeIn,
    DhcpScopePatchIn,
    DhcpSettingsIn,
    NewClientDetectionSettingsIn,
    RogueDhcpSettingsIn,
)


def register(app: FastAPI, ctx: AppContext) -> None:
    anomaly = ctx.anomaly
    config_store = ctx.config_store
    dhcp_server = ctx.dhcp_server
    require_admin = ctx.require_admin

    @app.get("/api/dhcp/scopes")
    def list_dhcp_scopes(_: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return config_store.get("dhcp", "scopes", default=[]) or []

    @app.post("/api/dhcp/scopes")
    def add_dhcp_scope(scope: DhcpScopeIn, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            dhcp_cfg = data.setdefault("dhcp", {})
            scopes = dhcp_cfg.setdefault("scopes", [])
            if any(s.get("name") == scope.name for s in scopes):
                raise HTTPException(status_code=400, detail="A scope with this name already exists")
            scopes.append(scope.model_dump())
            return scopes

        return config_store.mutate(_mutate)

    def _dhcp_scope_mutate(index: str, fn) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            scopes = data.setdefault("dhcp", {}).setdefault("scopes", [])
            pos = _ref_index(scopes, index, "No such DHCP scope")
            fn(scopes[pos])
            return scopes

        return config_store.mutate(_mutate)

    @app.patch("/api/dhcp/scopes/{index}")
    def update_dhcp_scope(
        index: str, body: DhcpScopePatchIn, _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        payload = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}

        def _fn(scope: dict[str, Any]) -> None:
            scope.update(payload)

        return _dhcp_scope_mutate(index, _fn)

    @app.delete("/api/dhcp/scopes/{index}")
    def delete_dhcp_scope(index: str, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            scopes = data.setdefault("dhcp", {}).setdefault("scopes", [])
            pos = _ref_index(scopes, index, "No such DHCP scope")
            scopes.pop(pos)
            return scopes

        return config_store.mutate(_mutate)

    @app.post("/api/dhcp/scopes/{index}/toggle")
    def toggle_dhcp_scope(index: str, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _fn(scope: dict[str, Any]) -> None:
            scope["enabled"] = not scope.get("enabled", True)

        return _dhcp_scope_mutate(index, _fn)

    @app.post("/api/dhcp/scopes/{index}/reservations")
    def add_dhcp_reservation(
        index: str, body: DhcpReservationIn, _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        mac = body.mac.upper()

        def _fn(scope: dict[str, Any]) -> None:
            reservations = scope.setdefault("reservations", [])
            if any(r.get("mac", "").upper() == mac for r in reservations):
                raise HTTPException(status_code=400, detail="A reservation for this MAC already exists")
            entry = body.model_dump()
            entry["mac"] = mac
            reservations.append(entry)

        scopes = _dhcp_scope_mutate(index, _fn)
        return scopes[_ref_index(scopes, index, "No such DHCP scope")].get("reservations", [])

    @app.delete("/api/dhcp/scopes/{index}/reservations/{mac}")
    def delete_dhcp_reservation(
        index: str, mac: str, _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        mac = mac.upper()

        def _fn(scope: dict[str, Any]) -> None:
            reservations = scope.setdefault("reservations", [])
            scope["reservations"] = [r for r in reservations if r.get("mac", "").upper() != mac]

        scopes = _dhcp_scope_mutate(index, _fn)
        return scopes[_ref_index(scopes, index, "No such DHCP scope")].get("reservations", [])

    @app.get("/api/dhcp/leases")
    def list_dhcp_leases(_: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        if dhcp_server is None:
            return []
        return dhcp_server.lease_store.all_active()

    @app.delete("/api/dhcp/leases/{mac}")
    def delete_dhcp_lease(mac: str, _: dict[str, Any] = Depends(require_admin)) -> dict[str, str]:
        if dhcp_server is None:
            raise HTTPException(status_code=400, detail="DHCP server is not running")
        dhcp_server.lease_store.release(mac.upper())
        return {"status": "released"}

    @app.post("/api/dhcp/leases/{mac}/reserve")
    def reserve_dhcp_lease(mac: str, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        if dhcp_server is None:
            raise HTTPException(status_code=400, detail="DHCP server is not running")
        mac = mac.upper()
        lease = dhcp_server.lease_store.get_by_mac(mac)
        if lease is None:
            raise HTTPException(status_code=404, detail="No active lease for this MAC")

        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            scopes = data.setdefault("dhcp", {}).setdefault("scopes", [])
            for scope in scopes:
                if scope.get("name") != lease["scope"]:
                    continue
                reservations = scope.setdefault("reservations", [])
                if any(r.get("mac", "").upper() == mac for r in reservations):
                    raise HTTPException(status_code=400, detail="A reservation for this MAC already exists")
                reservations.append({
                    "mac": mac, "ip": lease["ip"], "hostname": lease.get("hostname"),
                    "dns_servers": [], "custom_options": [],
                })
                return scope
            raise HTTPException(status_code=404, detail="Scope for this lease no longer exists")

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/dhcp")
    def update_dhcp_settings(body: DhcpSettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            dhcp_cfg = data.setdefault("dhcp", {})
            dhcp_cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return {"enabled": bool(dhcp_cfg.get("enabled", False))}

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/rogue-dhcp-detection")
    def update_rogue_dhcp_settings(
        body: RogueDhcpSettingsIn, _: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            cfg = data.setdefault("rogue_dhcp_detection", {})
            cfg.update({k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None})
            return _rogue_dhcp_settings(cfg)

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/new-client-detection")
    def update_new_client_detection_settings(
        body: NewClientDetectionSettingsIn, _: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        payload = body.model_dump(exclude_unset=True)
        was_dns_enabled = bool(config_store.get("new_client_detection", "dns_enabled", default=False))
        was_dhcp_enabled = bool(config_store.get("new_client_detection", "dhcp_enabled", default=False))

        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            cfg = data.setdefault("new_client_detection", {})
            cfg.update({k: v for k, v in payload.items() if v is not None})
            if payload.get("dns_enabled") and not was_dns_enabled:
                cfg["dns_learning_started_at"] = time.time()
            if payload.get("dhcp_enabled") and not was_dhcp_enabled:
                cfg["dhcp_learning_started_at"] = time.time()
            return _new_client_detection_settings(cfg)

        return config_store.mutate(_mutate)

    @app.post("/api/new-client-detection/reset-dns")
    def reset_new_dns_clients(_: dict[str, Any] = Depends(require_admin)) -> dict[str, str]:
        if anomaly is not None:
            anomaly.reset_new_dns_clients()
        return {"status": "reset"}

    @app.post("/api/new-client-detection/reset-dhcp")
    def reset_new_dhcp_clients(_: dict[str, Any] = Depends(require_admin)) -> dict[str, str]:
        if dhcp_server is not None:
            dhcp_server.lease_store.reset_known_macs()
        new_client_detection.reset_learning(config_store, "new_client_detection", "dhcp_learning_started_at")
        return {"status": "reset"}
