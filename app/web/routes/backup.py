# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Import from AdGuard Home / Pi-hole, export and backup restore."""

from __future__ import annotations

import difflib
import io
import sqlite3
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

import yaml
from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import Response

from app.import_adguard import import_config
from app.import_pihole import import_config as import_pihole_config
from app.web.context import AppContext


def register(app: FastAPI, ctx: AppContext) -> None:
    blocklist = ctx.blocklist
    config_store = ctx.config_store
    require_admin = ctx.require_admin
    users = ctx.users

    @app.post("/api/import/adguard")
    def import_adguard(file: UploadFile = File(...), _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        raw = file.file.read()
        try:
            adguard = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise HTTPException(status_code=400, detail=f"Not valid YAML: {exc}") from exc
        if not isinstance(adguard, dict):
            raise HTTPException(status_code=400, detail="Doesn't look like an AdGuardHome.yaml (not a YAML mapping)")

        result, warnings = import_config(adguard, config_store.snapshot())

        def _mutate(data: dict[str, Any]) -> None:
            data.clear()
            data.update(result)

        config_store.mutate(_mutate)
        blocklist.request_refresh()

        return {"ok": True, "warnings": warnings}

    @app.post("/api/import/pihole")
    def import_pihole(file: UploadFile = File(...), _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        raw = file.file.read()
        with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
            tmp.write(raw)
            tmp.flush()
            try:
                result, warnings = import_pihole_config(Path(tmp.name), config_store.snapshot())
            except sqlite3.DatabaseError as exc:
                raise HTTPException(status_code=400, detail=f"Not a valid gravity.db (SQLite file): {exc}") from exc

        def _mutate(data: dict[str, Any]) -> None:
            data.clear()
            data.update(result)

        config_store.mutate(_mutate)
        blocklist.request_refresh()

        return {"ok": True, "warnings": warnings}

    _EXPORT_README = """DNS-shield configuration backup
================================

config.yaml is a full snapshot of this instance's config.db at the time of
export: blocklists, allow/deny rules, client groups, DNS/web settings,
custom DNS records - and yes, any threat-intel API keys in plain text and
every user's bcrypt password hash (same as data/config.backup.yaml already
on disk). A bcrypt hash can't be turned back into the original password,
but treat this file like a password anyway: back it up somewhere you'd
store a password, not somewhere public.

To restore into a FRESH instance (no data/config.db yet):
  cp config.yaml <your data volume>/config.backup.yaml
  # then start the container as usual - it seeds config.db from that file

To restore into an EXISTING instance (data/config.db already exists):
  docker compose down
  cp config.yaml <your data volume>/config.backup.yaml
  rm <your data volume>/config.db <your data volume>/config.db-wal <your data volume>/config.db-shm
  docker compose up -d
"""

    @app.get("/api/config-history")
    def get_config_history(
        limit: int = Query(50, ge=1, le=200), _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        """Saved versions of the config (newest first): when, who/what changed
        it, and which sections."""
        versions = config_store.history(limit)
        if versions:
            versions[0]["current"] = True
        return versions

    @app.get("/api/config-history/{version_id}")
    def get_config_version(version_id: int, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        """What this version changed, as a unified diff of the YAML against the version before it."""
        found = config_store.history_version(version_id)
        if found is None:
            raise HTTPException(status_code=404, detail="No such config version (only the newest 200 are kept)")
        data, before = found

        def _yaml(value: dict[str, Any] | None) -> list[str]:
            if value is None:
                return []
            return yaml.safe_dump(value, sort_keys=True, allow_unicode=True).splitlines(keepends=True)

        diff = "".join(
            difflib.unified_diff(_yaml(before), _yaml(data), fromfile="before", tofile=f"version {version_id}", n=2)
        )
        return {"id": version_id, "diff": diff}

    @app.post("/api/config-history/{version_id}/restore")
    def restore_config_version(version_id: int, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        """Roll the config back to this version. Users and single sign-on are
        left as they are now; ports, addresses and TLS need a restart."""
        changed = config_store.restore_version(version_id)
        if changed is None:
            raise HTTPException(status_code=404, detail="No such config version (only the newest 200 are kept)")
        blocklist.request_refresh()
        users.ensure_default_admin()
        return {"ok": True, "changed": changed}

    @app.get("/api/export")
    def export_config(_: dict[str, Any] = Depends(require_admin)) -> Response:
        snap = config_store.snapshot()
        config_yaml = yaml.safe_dump(snap, sort_keys=False)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("config.yaml", config_yaml)
            zf.writestr("README.txt", _EXPORT_README)

        filename = f"dnsshield-backup-{time.strftime('%Y%m%d-%H%M%S')}.zip"
        return Response(
            content=buf.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.post("/api/import/backup")
    def import_backup(file: UploadFile = File(...), _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        raw = file.file.read()
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                config_yaml = zf.read("config.yaml")
        except zipfile.BadZipFile as exc:
            raise HTTPException(status_code=400, detail=f"Not a valid zip file: {exc}") from exc
        except KeyError as exc:
            raise HTTPException(
                status_code=400, detail="Not a DNS-shield backup - no config.yaml inside this zip"
            ) from exc

        try:
            result = yaml.safe_load(config_yaml)
        except yaml.YAMLError as exc:
            raise HTTPException(status_code=400, detail=f"config.yaml in this backup isn't valid YAML: {exc}") from exc
        if not isinstance(result, dict):
            raise HTTPException(status_code=400, detail="config.yaml in this backup isn't a YAML mapping")

        def _mutate(data: dict[str, Any]) -> None:
            data.clear()
            data.update(result)

        config_store.mutate(_mutate)
        blocklist.request_refresh()
        users.ensure_default_admin()

        return {"ok": True}
