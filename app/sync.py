# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Primary/secondary sync: a secondary DNS-shield copies the filtering
config from a primary, so two resolvers (say, DNS 1 and DNS 2 handed out by
DHCP) block the same things without editing both.

The primary needs nothing extra: it serves GET /api/sync/config to an admin
API token. The secondary (sync.enabled, sync.primary_url, sync.token)
fetches it every sync.interval_seconds and replaces its own copy of the
synced sections. Node-specific settings are never copied: accounts, single
sign-on, the web UI, DHCP (two DHCP servers on one network would fight),
the reverse proxy, the sync settings themselves, and the DNS listen
addresses, ports and thread counts."""

from __future__ import annotations

import copy
import logging
import threading
import time
from typing import Any

import requests

from app.config import config_actor

logger = logging.getLogger("dnsshield.sync")

DEFAULT_SECTIONS = (
    "blocklists",
    "allowlist",
    "denylist",
    "denylist_regex",
    "blocked_services",
    "blocked_tlds",
    "blocked_clients",
    "blocked_answer_ips",
    "blocked_answer_ip_sources",
    "dns_rewrites",
    "domain_upstreams",
    "client_groups",
    "dns",
)
# Sections that can never be synced, whatever sync.sections says.
NEVER_SYNCED = frozenset({"users", "sso", "web", "dhcp", "proxy", "sync"})
# dns.* keys that belong to this machine (listen addresses, ports, threads)
# or to its own cache.
LOCAL_DNS_KEYS = frozenset(
    {
        "listen_address",
        "listen_port",
        "dot_enabled",
        "dot_port",
        "doq_enabled",
        "doq_port",
        "server_threads",
        "block_page_enabled",
        "block_page_port",
        "cache_generation",
        "client_name_resolver",
    }
)
_MIN_INTERVAL = 30.0


def syncable_view(data: dict[str, Any], sections: list[str] | tuple[str, ...] = DEFAULT_SECTIONS) -> dict[str, Any]:
    """The part of a config a secondary takes over."""
    view: dict[str, Any] = {}
    for section in sections:
        if section in NEVER_SYNCED or section not in data:
            continue
        value = copy.deepcopy(data[section])
        if section == "dns" and isinstance(value, dict):
            value = {key: v for key, v in value.items() if key not in LOCAL_DNS_KEYS}
        view[section] = value
    return view


def apply_view(data: dict[str, Any], view: dict[str, Any], sections: list[str] | tuple[str, ...]) -> list[str]:
    """Write a primary's sections into this config (in place); returns the sections that changed."""
    changed: list[str] = []
    for section in sections:
        if section in NEVER_SYNCED or section not in view:
            continue
        incoming = view[section]
        if section == "dns" and isinstance(incoming, dict):
            local = {key: v for key, v in (data.get("dns") or {}).items() if key in LOCAL_DNS_KEYS}
            merged = {key: v for key, v in incoming.items() if key not in LOCAL_DNS_KEYS}
            merged.update(local)
            incoming = merged
        if data.get(section) != incoming:
            data[section] = copy.deepcopy(incoming)
            changed.append(section)
    return changed


class SyncClient:
    def __init__(self, config_store, blocklist=None, session: requests.Session | None = None):
        self._config = config_store
        self._blocklist = blocklist
        self._session = session or requests.Session()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._lock = threading.Lock()
        self._status: dict[str, Any] = {"last_attempt": None, "last_success": None, "last_error": None, "changed": []}

    def _settings(self) -> dict[str, Any]:
        cfg = self._config.get("sync", default={}) or {}
        return cfg if isinstance(cfg, dict) else {}

    def _sections(self) -> list[str]:
        sections = self._settings().get("sections") or list(DEFAULT_SECTIONS)
        return [s for s in sections if s not in NEVER_SYNCED]

    def enabled(self) -> bool:
        cfg = self._settings()
        return bool(cfg.get("enabled")) and bool(cfg.get("primary_url")) and bool(cfg.get("token"))

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {"enabled": self.enabled(), **copy.deepcopy(self._status)}

    def start(self) -> None:
        threading.Thread(target=self._loop, name="config-sync", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def trigger(self) -> None:
        """Sync now instead of at the next interval."""
        self._wake.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            if self.enabled():
                self.sync_once()
            interval = max(_MIN_INTERVAL, float(self._settings().get("interval_seconds") or 300))
            self._wake.wait(interval)
            self._wake.clear()

    def sync_once(self) -> list[str]:
        """Fetch the primary's config and apply it; returns the changed sections."""
        cfg = self._settings()
        url = str(cfg.get("primary_url") or "").rstrip("/") + "/api/sync/config"
        now = time.time()
        with self._lock:
            self._status["last_attempt"] = now
        try:
            response = self._session.get(
                url,
                headers={"Authorization": f"Bearer {cfg.get('token', '')}"},
                timeout=15,
                verify=bool(cfg.get("verify_tls", True)),
                allow_redirects=False,
            )
            if response.status_code != 200:
                raise RuntimeError(f"primary answered HTTP {response.status_code}")
            payload = response.json()
            view = payload.get("config") if isinstance(payload, dict) else None
            if not isinstance(view, dict):
                raise RuntimeError("primary sent no config")
        except (requests.RequestException, ValueError, RuntimeError) as exc:
            message = str(exc)
            with self._lock:
                self._status["last_error"] = message
            logger.warning("config sync from %s failed: %s", url, message)
            return []

        sections = self._sections()
        changed: list[str] = []
        if apply_view(self._config.snapshot(), view, sections):
            token = config_actor.set(f"sync from {cfg.get('primary_url')}")
            try:
                changed = self._config.mutate(lambda data: apply_view(data, view, sections))
            finally:
                config_actor.reset(token)
        if changed:
            logger.info("config sync: updated %s from the primary", ", ".join(changed))
            if self._blocklist is not None and ("blocklists" in changed or "client_groups" in changed):
                self._blocklist.request_refresh()
        with self._lock:
            self._status.update(last_success=time.time(), last_error=None, changed=changed)
        return changed
