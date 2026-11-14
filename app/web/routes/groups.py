# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Client groups: membership, rules, upstreams, SafeSearch, schedules and group blocklists."""

from __future__ import annotations

import time
from typing import Any

from fastapi import Depends, FastAPI, HTTPException

from app.netmatch import normalize_client_pattern, normalize_client_patterns
from app.url_safety import check_public_url
from app.web.common import _ref_index
from app.web.context import AppContext
from app.web.models import (
    AllowNowIn,
    BlocklistSourceIn,
    ClientGroupIn,
    DomainIn,
    GroupEnabledIn,
    GroupMatchIn,
    GroupNameIn,
    GroupSafeSearchIn,
    GroupScheduleIn,
    InternetOffIn,
    UpstreamsIn,
)


def register(app: FastAPI, ctx: AppContext) -> None:
    blocklist = ctx.blocklist
    config_store = ctx.config_store
    require_admin = ctx.require_admin

    @app.get("/api/client-groups")
    def list_client_groups(_: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        return config_store.get("client_groups", default=[]) or []

    @app.post("/api/client-groups")
    def add_client_group(group: ClientGroupIn, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            groups = data.setdefault("client_groups", [])
            if any(str(g.get("name", "")).casefold() == group.name.casefold() for g in groups):
                raise HTTPException(status_code=409, detail=f'A client group named "{group.name}" already exists')
            groups.append(group.model_dump())
            return groups

        return config_store.mutate(_mutate)

    @app.delete("/api/client-groups/{index}")
    def delete_client_group(index: str, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            groups = data.setdefault("client_groups", [])
            pos = _ref_index(groups, index, "No such client group")
            groups.pop(pos)
            return groups

        return config_store.mutate(_mutate)

    @app.post("/api/client-groups/{index}/toggle")
    def toggle_client_group(index: str, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            groups = data.setdefault("client_groups", [])
            pos = _ref_index(groups, index, "No such client group")
            groups[pos]["enabled"] = not groups[pos].get("enabled", True)
            return groups

        return config_store.mutate(_mutate)

    @app.put("/api/client-groups/{index}/name")
    def rename_client_group(
        index: str, body: GroupNameIn, _: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> tuple[dict[str, Any], str]:
            groups = data.setdefault("client_groups", [])
            pos = _ref_index(groups, index, "No such client group")
            old_name = str(groups[pos].get("name", ""))
            for position, other in enumerate(groups):
                if position != pos and str(other.get("name", "")).casefold() == body.name.casefold():
                    raise HTTPException(status_code=409, detail=f'A client group named "{body.name}" already exists')
            if old_name == body.name:
                return groups[pos], old_name
            groups[pos]["name"] = body.name
            for user in data.get("users", []) or []:
                permissions = user.get("permissions")
                allowed = permissions.get("allowed_groups") if isinstance(permissions, dict) else None
                if allowed and old_name in allowed:
                    renamed: list[str] = []
                    for entry in allowed:
                        entry = body.name if entry == old_name else entry
                        if entry not in renamed:
                            renamed.append(entry)
                    permissions["allowed_groups"] = renamed
            return groups[pos], old_name

        group, old_name = config_store.mutate(_mutate)
        if old_name != body.name:
            blocklist.rename_group(old_name, body.name)
        return group

    @app.put("/api/client-groups/{index}/enabled")
    def set_client_group_enabled(
        index: str, body: GroupEnabledIn, _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            groups = data.setdefault("client_groups", [])
            pos = _ref_index(groups, index, "No such client group")
            groups[pos]["enabled"] = body.enabled
            return groups

        return config_store.mutate(_mutate)

    def _group_mutate(index: str, fn) -> dict[str, Any]:
        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            groups = data.setdefault("client_groups", [])
            pos = _ref_index(groups, index, "No such client group")
            return fn(groups[pos])

        return config_store.mutate(_mutate)

    def _add_group_rule(index: str, list_name: str, domain: str) -> dict[str, Any]:
        domain = domain.strip().lower().rstrip(".")
        if not domain:
            raise HTTPException(status_code=400, detail="Empty domain")

        def _fn(group: dict[str, Any]) -> dict[str, Any]:
            items = group.setdefault(list_name, [])
            if domain not in items:
                items.append(domain)
            return group

        return _group_mutate(index, _fn)

    def _remove_group_rule(index: str, list_name: str, domain: str) -> dict[str, Any]:
        domain = domain.strip().lower().rstrip(".")

        def _fn(group: dict[str, Any]) -> dict[str, Any]:
            items = group.setdefault(list_name, [])
            if domain in items:
                items.remove(domain)
            return group

        return _group_mutate(index, _fn)

    @app.post("/api/client-groups/{index}/match")
    def add_group_match(index: str, body: GroupMatchIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        try:
            patterns = normalize_client_patterns(body.patterns)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        def _fn(group: dict[str, Any]) -> dict[str, Any]:
            items = group.setdefault("match", [])
            for pattern in patterns:
                if pattern not in items:
                    items.append(pattern)
            return group

        return _group_mutate(index, _fn)

    @app.delete("/api/client-groups/{index}/match")
    def remove_group_match(index: str, pattern: str, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _fn(group: dict[str, Any]) -> dict[str, Any]:
            items = group.setdefault("match", [])
            target = pattern if pattern in items else None
            if target is None:
                try:
                    normalized = normalize_client_pattern(pattern)
                except ValueError:
                    normalized = None
                target = normalized if normalized in items else None
            if target is None:
                raise HTTPException(status_code=404, detail="No such pattern in this group")
            if len(items) <= 1:
                raise HTTPException(
                    status_code=400, detail="A group needs at least one pattern - delete the group instead"
                )
            items.remove(target)
            return group

        return _group_mutate(index, _fn)

    @app.post("/api/client-groups/{index}/allow")
    def add_group_allow(index: str, body: DomainIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        return _add_group_rule(index, "allowlist", body.domain)

    @app.delete("/api/client-groups/{index}/allow/{domain:path}")
    def remove_group_allow(index: str, domain: str, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        return _remove_group_rule(index, "allowlist", domain)

    @app.post("/api/client-groups/{index}/deny")
    def add_group_deny(index: str, body: DomainIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        return _add_group_rule(index, "denylist", body.domain)

    @app.delete("/api/client-groups/{index}/deny/{domain:path}")
    def remove_group_deny(index: str, domain: str, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        return _remove_group_rule(index, "denylist", domain)

    @app.put("/api/client-groups/{index}/upstreams")
    def set_group_upstreams(index: str, body: UpstreamsIn, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _fn(group: dict[str, Any]) -> dict[str, Any]:
            group["upstreams"] = body.upstreams
            return group

        return _group_mutate(index, _fn)

    @app.put("/api/client-groups/{index}/safe-search")
    def set_group_safe_search(
        index: str, body: GroupSafeSearchIn, _: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        def _fn(group: dict[str, Any]) -> dict[str, Any]:
            group["safe_search"] = body.safe_search
            return group

        return _group_mutate(index, _fn)

    @app.put("/api/client-groups/{index}/internet-off")
    def set_group_internet_off(
        index: str, body: InternetOffIn, _: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        """Cut the group's internet now - for a while, or until turned back on."""

        def _fn(group: dict[str, Any]) -> dict[str, Any]:
            until = time.time() + body.minutes * 60 if body.minutes else None
            group["internet_off"] = {"active": True, "until": until}
            group.pop("allow_until", None)
            return group

        return _group_mutate(index, _fn)

    @app.delete("/api/client-groups/{index}/internet-off")
    def clear_group_internet_off(index: str, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _fn(group: dict[str, Any]) -> dict[str, Any]:
            group.pop("internet_off", None)
            return group

        return _group_mutate(index, _fn)

    @app.put("/api/client-groups/{index}/allow-now")
    def set_group_allow_now(
        index: str, body: AllowNowIn, _: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        """Give the group its internet back for a while, even inside its
        bedtime schedule ("30 more minutes"); also ends an "internet off"."""

        def _fn(group: dict[str, Any]) -> dict[str, Any]:
            group["allow_until"] = time.time() + body.minutes * 60
            group.pop("internet_off", None)
            return group

        return _group_mutate(index, _fn)

    @app.delete("/api/client-groups/{index}/allow-now")
    def clear_group_allow_now(index: str, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        def _fn(group: dict[str, Any]) -> dict[str, Any]:
            group.pop("allow_until", None)
            return group

        return _group_mutate(index, _fn)

    @app.put("/api/client-groups/{index}/schedule")
    def set_group_schedule(
        index: str, body: GroupScheduleIn, _: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        def _fn(group: dict[str, Any]) -> dict[str, Any]:
            group["schedule"] = {
                "enabled": body.enabled,
                "timezone": body.timezone.strip(),
                "windows": [
                    {"days": sorted({d for d in w.days if 0 <= d <= 6}), "start": w.start.strip(), "end": w.end.strip()}
                    for w in body.windows
                ],
            }
            return group

        return _group_mutate(index, _fn)

    def _group_source_mutate(index: str, fn) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            groups = data.setdefault("client_groups", [])
            pos = _ref_index(groups, index, "No such client group")
            sources = groups[pos].setdefault("blocklist_sources", [])
            return fn(sources)

        result = config_store.mutate(_mutate)
        blocklist.request_refresh()
        return result

    @app.get("/api/client-groups/{index}/blocklist-sources")
    def list_group_blocklist_sources(index: str, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        groups = config_store.get("client_groups", default=[]) or []
        pos = _ref_index(groups, index, "No such client group")
        return groups[pos].get("blocklist_sources", []) or []

    @app.post("/api/client-groups/{index}/blocklist-sources")
    def add_group_blocklist_source(
        index: str, source: BlocklistSourceIn, _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        try:
            check_public_url(source.url)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        def _fn(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
            sources.append(source.model_dump())
            return sources

        return _group_source_mutate(index, _fn)

    @app.delete("/api/client-groups/{index}/blocklist-sources/{source_index}")
    def delete_group_blocklist_source(
        index: str, source_index: str, _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        def _fn(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
            source_pos = _ref_index(sources, source_index, "No such list")
            sources.pop(source_pos)
            return sources

        return _group_source_mutate(index, _fn)

    @app.post("/api/client-groups/{index}/blocklist-sources/{source_index}/toggle")
    def toggle_group_blocklist_source(
        index: str, source_index: str, _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        def _fn(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
            source_pos = _ref_index(sources, source_index, "No such list")
            sources[source_pos]["enabled"] = not sources[source_pos].get("enabled", True)
            return sources

        return _group_source_mutate(index, _fn)
