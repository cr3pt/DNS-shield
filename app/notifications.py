"""Optional outbound email notifications for anomaly alerts.

This is not a third-party cloud service: DNS-shield speaks SMTP directly
to whatever mail server *you* configure (your own mail server, or your
own account at any provider) - the exact same thing any desktop mail
client does, using nothing but Python's standard library (smtplib). Off
by default; nothing is ever sent unless notifications.email.enabled is
on and at least one recipient is configured.

The other half of "notifications" - a browser popup - needs no server
component at all and isn't handled here: see the dashboard's own
Web Notification API polling in web/static/index.html, which asks your
browser directly, never a server.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

logger = logging.getLogger("dnsshield.notifications")

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


class NotificationSender:
    def __init__(self, config_store):
        self._config = config_store

    def _email_settings(self) -> dict[str, Any]:
        return self._config.get("notifications", "email", default={}) or {}

    # -- called by AnomalyDetector -----------------------------------------
    def notify_anomalies(self, anomalies: list[dict[str, Any]]) -> None:
        """Fired right after AnomalyDetector.check_once() records new
        anomalies. Never raises - a mail-sending failure must never affect
        anomaly detection itself, so every error is caught and logged here.
        """
        try:
            self._notify_anomalies_impl(anomalies)
        except Exception:  # noqa: BLE001
            logger.exception("failed to send anomaly notification email")

    def _notify_anomalies_impl(self, anomalies: list[dict[str, Any]]) -> None:
        if not anomalies:
            return
        cfg = self._email_settings()
        if not cfg.get("enabled"):
            return
        min_rank = _SEVERITY_RANK.get(cfg.get("min_severity", "medium"), 1)
        relevant = [a for a in anomalies if _SEVERITY_RANK.get(a.get("severity", "medium"), 1) >= min_rank]
        if not relevant:
            return

        count = len(relevant)
        subject = f"DNS-shield: {count} new anomal{'y' if count == 1 else 'ies'} detected"
        lines = [f"- [{a['severity'].upper()}] {a['client']}: {a['summary']}" for a in relevant]
        body = "\n".join(lines) + "\n\nOpen your DNS-shield dashboard's Settings -> Anomalies tab for details."
        self._send(cfg, subject, body)
        logger.info("sent anomaly notification email for %d anomalies", count)

    # -- Settings -> Notifications "Send test email" button -----------------
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

    # -- transport ------------------------------------------------------
    def _send(self, cfg: dict[str, Any], subject: str, body: str) -> None:
        host = (cfg.get("smtp_host") or "").strip()
        to_addresses = [a.strip() for a in (cfg.get("to_addresses") or []) if a.strip()]
        from_address = (cfg.get("from_address") or cfg.get("smtp_username") or "").strip()
        if not host or not to_addresses or not from_address:
            raise ValueError("SMTP host, a from address, and at least one recipient are required")

        port = int(cfg.get("smtp_port") or 587)
        security = cfg.get("smtp_security") or "starttls"  # "none" | "starttls" | "ssl"
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
