"""Blocklist fetching, parsing and matching.

Supported input formats (auto-detected per line):
  - hosts file syntax:      0.0.0.0 ads.example.com
  - AdBlock/uBlock syntax:  ||ads.example.com^
  - plain domain list:      ads.example.com

Every list source is a URL *you* configure in config.yaml - DNS-shield
never talks to any address that isn't either an upstream resolver or a
blocklist URL from your own config.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from pathlib import Path
from typing import Any, Iterable

import requests

from app.netmatch import ip_matches

logger = logging.getLogger("dnsshield.blocklist")

_HOSTS_PREFIXES = ("0.0.0.0 ", "127.0.0.1 ", "::1 ", "0.0.0.0\t", "127.0.0.1\t")
_ADBLOCK_RE = re.compile(r"^\|\|([a-z0-9.\-_]+)\^")
_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$")


def _parse_line(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith(("#", "!", ";")):
        return None

    if line.startswith("||"):
        m = _ADBLOCK_RE.match(line)
        if m:
            domain = m.group(1)
        else:
            return None
    elif line.startswith(_HOSTS_PREFIXES):
        parts = line.split()
        if len(parts) < 2:
            return None
        domain = parts[1]
    else:
        # Plain domain list - but skip lines that are clearly something else.
        domain = line.split()[0] if line.split() else ""

    domain = domain.strip().rstrip(".").lower()
    if domain in ("localhost", "local", "broadcasthost"):
        return None
    if not _DOMAIN_RE.match(domain):
        return None
    return domain


def parse_list(text: str) -> set[str]:
    domains: set[str] = set()
    for raw_line in text.splitlines():
        domain = _parse_line(raw_line)
        if domain:
            domains.add(domain)
    return domains


class BlocklistManager:
    """Owns the merged set of blocked domains and keeps it up to date."""

    def __init__(self, config_store, cache_dir: Path):
        self._config = config_store
        self._cache_dir = cache_dir
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._blocked: frozenset[str] = frozenset()
        self._allowed: frozenset[str] = frozenset()
        self._source_counts: dict[str, int] = {}
        self._allow_source_counts: dict[str, int] = {}
        self._last_refresh: float | None = None
        self._refresh_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # -- matching -----------------------------------------------------
    def is_blocked(self, qname: str, client_ip: str | None = None) -> bool:
        """Precedence: group allow > global allow > allow-list sources >
        group deny > global deny > group disabled (pass-through) >
        blocklists. A client not matching any configured group behaves
        exactly as if client_groups were empty.
        """
        qname = qname.rstrip(".").lower()
        group = self._find_group(client_ip)

        def matches(domains: Iterable[str] | None) -> bool:
            return any(qname == d or qname.endswith("." + d) for d in (domains or []))

        if group and matches(group.get("allowlist")):
            return False
        if matches(self._config.get("allowlist", default=[])):
            return False

        with self._lock:
            allowed, blocked = self._allowed, self._blocked

        if self._in_domain_set(qname, allowed):
            return False
        if group and matches(group.get("denylist")):
            return True
        if matches(self._config.get("denylist", default=[])):
            return True
        if group is not None and not group.get("enabled", True):
            return False

        return self._in_domain_set(qname, blocked)

    @staticmethod
    def _in_domain_set(qname: str, domain_set: frozenset[str]) -> bool:
        if qname in domain_set:
            return True
        # Subdomain match: block sub.ads.example.com if ads.example.com listed.
        labels = qname.split(".")
        for i in range(1, len(labels)):
            if ".".join(labels[i:]) in domain_set:
                return True
        return False

    def _find_group(self, client_ip: str | None) -> dict[str, Any] | None:
        if not client_ip:
            return None
        groups = self._config.get("client_groups", default=[]) or []
        for group in groups:
            for pattern in group.get("match", []) or []:
                if ip_matches(client_ip, pattern):
                    return group
        return None

    # -- stats ----------------------------------------------------------
    def source_counts(self) -> dict[str, int]:
        with self._lock:
            return dict(self._source_counts)

    def total_count(self) -> int:
        with self._lock:
            return len(self._blocked)

    def allow_source_counts(self) -> dict[str, int]:
        with self._lock:
            return dict(self._allow_source_counts)

    def allowed_count(self) -> int:
        with self._lock:
            return len(self._allowed)

    def last_refresh(self) -> float | None:
        return self._last_refresh

    # -- fetching ---------------------------------------------------------
    def _cache_path(self, name: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", name)
        return self._cache_dir / f"{safe}.cache"

    def _fetch_one(self, name: str, url: str) -> set[str]:
        cache_path = self._cache_path(name)
        try:
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            text = resp.text
            cache_path.write_text(text, encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            logger.warning("failed to fetch blocklist %r (%s): %s", name, url, exc)
            if cache_path.exists():
                text = cache_path.read_text(encoding="utf-8")
            else:
                return set()
        return parse_list(text)

    def _fetch_sources(self, sources: Iterable[dict]) -> tuple[set[str], dict[str, int]]:
        merged: set[str] = set()
        counts: dict[str, int] = {}
        for source in sources:
            if not source.get("enabled", True):
                continue
            name = source.get("name") or source.get("url", "unnamed")
            url = source.get("url")
            if not url:
                continue
            domains = self._fetch_one(name, url)
            counts[name] = len(domains)
            merged |= domains
        return merged, counts

    def refresh(self) -> None:
        with self._refresh_lock:
            sources = self._config.get("blocklists", "sources", default=[]) or []
            merged, counts = self._fetch_sources(sources)

            allow_sources = self._config.get("blocklists", "allow_sources", default=[]) or []
            allow_merged, allow_counts = self._fetch_sources(allow_sources)

            with self._lock:
                self._blocked = frozenset(merged)
                self._source_counts = counts
                self._allowed = frozenset(allow_merged)
                self._allow_source_counts = allow_counts
                self._last_refresh = time.time()
            logger.info(
                "blocklist refresh complete: %d blocked domains from %d sources, "
                "%d allow-listed domains from %d sources",
                len(merged), len(counts), len(allow_merged), len(allow_counts),
            )

    # -- background thread ------------------------------------------------
    def start(self) -> None:
        self.refresh()
        self._thread = threading.Thread(target=self._loop, name="blocklist-refresh", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            hours = self._config.get("blocklists", "refresh_interval_hours", default=24) or 24
            interval = max(float(hours), 0.25) * 3600
            if self._stop_event.wait(interval):
                return
            self.refresh()
