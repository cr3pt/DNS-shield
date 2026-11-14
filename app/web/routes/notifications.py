# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""E-mail and webhook notifications."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException

from app.web.common import (
    _notification_email_settings,
    _notification_webhook_public,
    _ref_index,
)
from app.web.context import AppContext
from app.web.models import NotificationEmailSettingsIn, NotificationWebhookIn


def register(app: FastAPI, ctx: AppContext) -> None:
    config_store = ctx.config_store
    notifications = ctx.notifications
    require_admin = ctx.require_admin

    @app.patch("/api/settings/notifications/email")
    def update_notification_email_settings(
        body: NotificationEmailSettingsIn, _: dict[str, Any] = Depends(require_admin)
    ) -> dict[str, Any]:
        data_in = body.model_dump(exclude_unset=True)
        payload = {k: v for k, v in data_in.items() if (v if k == "smtp_password" else v is not None)}

        def _mutate(data: dict[str, Any]) -> dict[str, Any]:
            email_cfg = data.setdefault("notifications", {}).setdefault("email", {})
            email_cfg.update(payload)
            return _notification_email_settings(email_cfg)

        return config_store.mutate(_mutate)

    @app.post("/api/notifications/test-email")
    def send_test_email(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        if notifications is None:
            raise HTTPException(status_code=503, detail="Notifications are not available")
        try:
            notifications.send_test_email()
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"ok": True}

    @app.post("/api/settings/notifications/webhooks")
    def add_notification_webhook(
        body: NotificationWebhookIn, _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        if body.type not in ("discord", "slack", "telegram"):
            raise HTTPException(status_code=400, detail="type must be discord, slack, or telegram")
        entry = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
        entry.setdefault("enabled", True)
        entry.setdefault("min_severity", "medium")

        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            webhooks = data.setdefault("notifications", {}).setdefault("webhooks", [])
            webhooks.append(entry)
            return [_notification_webhook_public(w) for w in webhooks]

        return config_store.mutate(_mutate)

    @app.patch("/api/settings/notifications/webhooks/{index}")
    def update_notification_webhook(
        index: str, body: NotificationWebhookIn, _: dict[str, Any] = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        data_in = body.model_dump(exclude_unset=True)
        payload = {
            k: v for k, v in data_in.items() if (v if k in ("url", "telegram_bot_token") else v is not None)
        }

        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            webhooks = data.setdefault("notifications", {}).setdefault("webhooks", [])
            pos = _ref_index(webhooks, index, "No such webhook")
            webhooks[pos].update(payload)
            return [_notification_webhook_public(w) for w in webhooks]

        return config_store.mutate(_mutate)

    @app.delete("/api/settings/notifications/webhooks/{index}")
    def delete_notification_webhook(index: str, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            webhooks = data.setdefault("notifications", {}).setdefault("webhooks", [])
            pos = _ref_index(webhooks, index, "No such webhook")
            webhooks.pop(pos)
            return [_notification_webhook_public(w) for w in webhooks]

        return config_store.mutate(_mutate)

    @app.post("/api/settings/notifications/webhooks/{index}/toggle")
    def toggle_notification_webhook(index: str, _: dict[str, Any] = Depends(require_admin)) -> list[dict[str, Any]]:
        def _mutate(data: dict[str, Any]) -> list[dict[str, Any]]:
            webhooks = data.setdefault("notifications", {}).setdefault("webhooks", [])
            pos = _ref_index(webhooks, index, "No such webhook")
            webhooks[pos]["enabled"] = not webhooks[pos].get("enabled", True)
            return [_notification_webhook_public(w) for w in webhooks]

        return config_store.mutate(_mutate)

    @app.post("/api/notifications/test-webhook/{index}")
    def send_test_webhook(index: str, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
        if notifications is None:
            raise HTTPException(status_code=503, detail="Notifications are not available")
        webhooks = config_store.get("notifications", "webhooks", default=[]) or []
        pos = _ref_index(webhooks, index, "No such webhook")
        try:
            notifications.send_test_webhook(pos)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"ok": True}
