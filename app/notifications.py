# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

import requests

from app.url_safety import check_public_url, public_dns_guard

logger = logging.getLogger("dnsshield.notifications")

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}
_WEBHOOK_TIMEOUT = 10
_WEBHOOK_MAX_LENGTH = {"discord": 2000, "slack": 4000, "telegram": 4000}


def _relevant(anomalies: list[dict[str, Any]], min_severity: str) -> list[dict[str, Any]]:
    min_rank = _SEVERITY_RANK.get(min_severity, 1)
    return [a for a in anomalies if _SEVERITY_RANK.get(a.get("severity", "medium"), 1) >= min_rank]


class NotificationSender:
    def __init__(self, config_store):
        self._config = config_store

    def _email_settings(self) -> dict[str, Any]:
        return self._config.get("notifications", "email", default={}) or {}

    def _webhook_configs(self) -> list[dict[str, Any]]:
        return list(self._config.get("notifications", "webhooks", default=[]) or [])

    def notify_anomalies(self, anomalies: list[dict[str, Any]]) -> None:
        if not anomalies:
            return
        try:
            self._notify_email(anomalies)
        except Exception:
            logger.exception("failed to send anomaly notification email")

        for index, cfg in enumerate(self._webhook_configs()):
            try:
                self._notify_webhook(cfg, anomalies)
            except Exception:
                logger.exception("failed to send anomaly webhook notification (%s)", cfg.get("name") or index)

    def _notify_email(self, anomalies: list[dict[str, Any]]) -> None:
        cfg = self._email_settings()
        if not cfg.get("enabled"):
            return
        relevant = _relevant(anomalies, cfg.get("min_severity", "medium"))
        if not relevant:
            return

        count = len(relevant)
        subject = f"DNS-shield: {count} new anomal{'y' if count == 1 else 'ies'} detected"
        lines = [f"- [{a['severity'].upper()}] {a['client']}: {a['summary']}" for a in relevant]
        body = "\n".join(lines) + "\n\nOpen your DNS-shield dashboard's Settings -> Anomalies tab for details."
        self._send(cfg, subject, body)
        logger.info("sent anomaly notification email for %d anomalies", count)

    def _notify_webhook(self, cfg: dict[str, Any], anomalies: list[dict[str, Any]]) -> None:
        if not cfg.get("enabled", True):
            return
        relevant = _relevant(anomalies, cfg.get("min_severity", "medium"))
        if not relevant:
            return

        count = len(relevant)
        lines = [f"[{a['severity'].upper()}] {a['client']}: {a['summary']}" for a in relevant]
        text = f"DNS-shield: {count} new anomal{'y' if count == 1 else 'ies'} detected\n" + "\n".join(lines)
        self._send_webhook(cfg, text)
        logger.info("sent anomaly webhook notification (%s) for %d anomalies", cfg.get("name") or cfg.get("type"), count)

    def send_test_email(self) -> None:
        cfg = self._email_settings()
        if not cfg.get("enabled"):
            raise ValueError("Email notifications are not enabled")
        self._send(
            cfg,
            "DNS-shield: test email",
            "This is a test email from DNS-shield's notification settings.\n"
            "If you received this, your SMTP configuration works.",
        )

    def send_test_webhook(self, index: int) -> None:
        webhooks = self._webhook_configs()
        if not 0 <= index < len(webhooks):
            raise ValueError("No such webhook")
        self._send_webhook(
            webhooks[index],
            "This is a test message from DNS-shield's notification settings. "
            "If you received this, your webhook configuration works.",
        )

    def _send_webhook(self, cfg: dict[str, Any], text: str) -> None:
        wtype = cfg.get("type")
        text = text[: _WEBHOOK_MAX_LENGTH.get(wtype, 4000)]

        if wtype == "discord":
            url = (cfg.get("url") or "").strip()
            if not url:
                raise ValueError("Discord webhook URL is required")
            check_public_url(url)
            with public_dns_guard(url):
                resp = requests.post(url, json={"content": text}, timeout=_WEBHOOK_TIMEOUT)
            resp.raise_for_status()
        elif wtype == "slack":
            url = (cfg.get("url") or "").strip()
            if not url:
                raise ValueError("Slack webhook URL is required")
            check_public_url(url)
            with public_dns_guard(url):
                resp = requests.post(url, json={"text": text}, timeout=_WEBHOOK_TIMEOUT)
            resp.raise_for_status()
        elif wtype == "telegram":
            token = (cfg.get("telegram_bot_token") or "").strip()
            chat_id = (cfg.get("telegram_chat_id") or "").strip()
            if not token or not chat_id:
                raise ValueError("Telegram bot token and chat ID are required")
            resp = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": text},
                timeout=_WEBHOOK_TIMEOUT,
            )
            resp.raise_for_status()
        else:
            raise ValueError(f"Unknown webhook type: {wtype!r}")

    def _send(self, cfg: dict[str, Any], subject: str, body: str) -> None:
        host = (cfg.get("smtp_host") or "").strip()
        to_addresses = [a.strip() for a in (cfg.get("to_addresses") or []) if a.strip()]
        from_address = (cfg.get("from_address") or cfg.get("smtp_username") or "").strip()
        if not host or not to_addresses or not from_address:
            raise ValueError("SMTP host, a from address, and at least one recipient are required")

        port = int(cfg.get("smtp_port") or 587)
        security = cfg.get("smtp_security") or "starttls"
        username = (cfg.get("smtp_username") or "").strip() or None
        password = cfg.get("smtp_password") or None

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = from_address
        msg["To"] = ", ".join(to_addresses)
        msg.set_content(body)

        timeout = 15
        if security == "ssl":
            with smtplib.SMTP_SSL(host, port, timeout=timeout, context=ssl.create_default_context()) as server:
                if username:
                    server.login(username, password or "")
                server.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as server:
                if security == "starttls":
                    server.starttls(context=ssl.create_default_context())
                if username:
                    server.login(username, password or "")
                server.send_message(msg)
