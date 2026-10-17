# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import logging
import threading

import requests

from app.url_safety import check_public_url, public_dns_guard

logger = logging.getLogger("dnsshield.url_ping")

_TIMEOUT = 10


class UrlPingTask:
    def __init__(self, config_store):
        self._config = config_store
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._config.get("url_ping", "enabled", default=False):
            self._ping_once()
        self._thread = threading.Thread(target=self._loop, name="url-ping", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _ping_once(self) -> None:
        url = (self._config.get("url_ping", "url", default="") or "").strip()
        if not url:
            return
        try:
            check_public_url(url)
            with public_dns_guard(url):
                resp = requests.get(url, timeout=_TIMEOUT)
            logger.info("url ping to %s completed with status %d", url, resp.status_code)
        except (requests.RequestException, ValueError) as exc:
            logger.warning("url ping to %s failed: %s", url, exc)

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            interval_minutes = self._config.get("url_ping", "interval_minutes", default=15) or 15
            interval = max(float(interval_minutes), 1.0) * 60
            if self._stop_event.wait(interval):
                return
            if not self._config.get("url_ping", "enabled", default=False):
                continue
            self._ping_once()
