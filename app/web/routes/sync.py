# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Primary/secondary config sync: the primary's export, the secondary's settings and status."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException

from app.sync import DEFAULT_SECTIONS, NEVER_SYNCED, syncable_view
from app.web.context import AppContext
from app.web.models import SyncSettingsIn


def register(app: FastAPI, ctx: AppContext) -> None:
    config_store = ctx.config_store
    require_admin = ctx.require_admin
    sync_client = ctx.sync_client

    @app.get("/api/sync/config")
    def get_sync_config(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        """What a secondary copies: every section except accounts, sign-in,
        the web UI, DHCP, the proxy and this machine's DNS listeners."""
        snapshot = config_store.snapshot()
        return {"config": syncable_view(snapshot, [key for key in snapshot if key not in NEVER_SYNCED])}

    def _public_settings() -> dict[str, Any]:
        cfg = dict(config_store.get("sync", default={}) or {})
        token = cfg.pop("token", "")
        cfg["token_set"] = bool(token)
        cfg.setdefault("sections", list(DEFAULT_SECTIONS))
        return cfg

    @app.get("/api/sync/status")
    def get_sync_status(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        return {"settings": _public_settings(), "status": sync_client.status(), "default_sections": list(DEFAULT_SECTIONS)}

    @app.patch("/api/settings/sync")
    def update_sync_settings(body: SyncSettingsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> None:
            cfg = data.setdefault("sync", {})
            values = body.model_dump(exclude_unset=True)
            token = values.pop("token", None)
            if token:
                cfg["token"] = token
            cfg.update({key: value for key, value in values.items() if value is not None})

        config_store.mutate(_mutate)
        sync_client.trigger()
        return _public_settings()

    @app.post("/api/sync/now")
    def sync_now(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        if not sync_client.enabled():
            raise HTTPException(status_code=400, detail="Sync is off, or the primary's URL or API token is missing")
        changed = sync_client.sync_once()
        status = sync_client.status()
        if status.get("last_error"):
            raise HTTPException(status_code=502, detail=f"Sync failed: {status['last_error']}")
        return {"changed": changed, "status": status}
