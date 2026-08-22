from __future__ import annotations

import logging
import re
import threading
import time
import unicodedata
from pathlib import Path
from typing import Any, Iterable

import requests

from app.netmatch import ip_matches
from app.upstream import protected_hostnames

logger = logging.getLogger("dnsshield.blocklist")

_HOSTS_PREFIXES = ("0.0.0.0 ", "127.0.0.1 ", "::1 ", "0.0.0.0\t", "127.0.0.1\t")
_ADBLOCK_RE = re.compile(r"^\|\|([a-z0-9.\-_]+)\^")
_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$")


def is_non_latin_domain(domain: str) -> bool:
    if "xn--" in domain:
        decoded_labels = []
        for label in domain.split("."):
            if label.startswith("xn--"):
                try:
                    label = label.encode("ascii").decode("idna")
                except (UnicodeError, UnicodeDecodeError):
                    pass
            decoded_labels.append(label)
        domain = ".".join(decoded_labels)

    for ch in domain:
        if ch in ".-_" or ch.isdigit() or ch.isascii():
            continue
        name = unicodedata.name(ch, "")
        if not name or (not name.startswith("LATIN") and "COMBINING" not in name):
            return True
    return False


_FORMAT_LABELS = {
    "hosts": "hosts file (0.0.0.0/127.0.0.1 domain)",
    "adblock": "AdBlock/uBlock syntax (||domain^)",
    "plain": "plain domain list",
}


def _parse_line(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line or line.startswith(("#", "!", ";")):
        return None

    if line.startswith("||"):
        m = _ADBLOCK_RE.match(line)
        if m:
            domain = m.group(1)
            fmt = "adblock"
        else:
            return None
    elif line.startswith(_HOSTS_PREFIXES):
        parts = line.split()
        if len(parts) < 2:
            return None
        domain = parts[1]
        fmt = "hosts"
    else:
        domain = line.split()[0] if line.split() else ""
        fmt = "plain"

    domain = domain.strip().rstrip(".").lower()
    if domain in ("localhost", "local", "broadcasthost"):
        return None
    if not _DOMAIN_RE.match(domain):
        return None
    return domain, fmt


def parse_list(text: str) -> tuple[set[str], dict[str, int]]:
    domains: set[str] = set()
    format_counts: dict[str, int] = {}
    for raw_line in text.splitlines():
        parsed = _parse_line(raw_line)
        if parsed:
            domain, fmt = parsed
            domains.add(domain)
            format_counts[fmt] = format_counts.get(fmt, 0) + 1
    return domains, format_counts


_MIXED_FORMAT_THRESHOLD = 0.02


def describe_format(format_counts: dict[str, int]) -> str:
    if not format_counts:
        return "unknown"
    total = sum(format_counts.values())
    present = [fmt for fmt, count in format_counts.items() if count / total >= _MIXED_FORMAT_THRESHOLD]
    if len(present) == 1:
        return _FORMAT_LABELS.get(present[0], present[0])
    labels = " + ".join(_FORMAT_LABELS.get(fmt, fmt) for fmt in sorted(present, key=lambda f: -format_counts[f]))
    return f"mixed formats ({labels})"


class BlocklistManager:

    def __init__(self, config_store, cache_dir: Path):
        self._config = config_store
        self._cache_dir = cache_dir
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._blocked: frozenset[str] = frozenset()
        self._allowed: frozenset[str] = frozenset()
        self._domain_source: dict[str, str] = {}
        self._source_counts: dict[str, int] = {}
        self._source_formats: dict[str, str] = {}
        self._allow_source_counts: dict[str, int] = {}
        self._allow_source_formats: dict[str, str] = {}
        self._group_blocked: dict[str, frozenset[str]] = {}
        self._group_domain_source: dict[str, dict[str, str]] = {}
        self._group_source_counts: dict[str, dict[str, int]] = {}
        self._group_source_formats: dict[str, dict[str, str]] = {}
        self._alert_matched: frozenset[str] = frozenset()
        self._alert_domain_source: dict[str, str] = {}
        self._alert_source_counts: dict[str, int] = {}
        self._alert_source_formats: dict[str, str] = {}
        self._last_refresh: float | None = None
        self._refresh_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        self._regex_lock = threading.Lock()
        self._regex_cache_key: tuple[str, ...] | None = None
        self._regex_cache_compiled: list[tuple[str, re.Pattern]] = []

    def is_blocked(self, qname: str, client_ip: str | None = None) -> bool:
        return self.block_reason(qname, client_ip) is not None

    def is_paused(self) -> bool:
        if not self._config.get("pause", "active", default=False):
            return False
        until = self._config.get("pause", "until", default=None)
        return until is None or time.time() < until

    def block_reason(self, qname: str, client_ip: str | None = None) -> str | None:
        qname = qname.rstrip(".").lower()

        if self.is_paused():
            return None

        group = self._find_group(client_ip)

        def matches(domains: Iterable[str] | None) -> bool:
            return any(qname == d or qname.endswith("." + d) for d in (domains or []))

        if matches(protected_hostnames(self._config)):
            return None
        if self._is_client_blocked(client_ip):
            return "Client blocked (manually)"
        if group and matches(group.get("denylist")):
            return f"Denylist (client group \"{group.get('name', '')}\")"
        if matches(self._config.get("denylist", default=[])):
            return "Denylist (manually added)"
        if self._config.get("dns", "regex_denylist_enabled", default=False):
            for pattern_text, pattern in self._compiled_regex_patterns():
                if pattern.search(qname):
                    return f"Denylist (regex, experimental): {pattern_text}"
        if group and matches(group.get("allowlist")):
            return None
        if matches(self._config.get("allowlist", default=[])):
            return None

        with self._lock:
            allowed, blocked, domain_source = self._allowed, self._blocked, self._domain_source
            group_blocked = self._group_blocked
            group_domain_source = self._group_domain_source

        if self._find_match(qname, allowed) is not None:
            return None
        if group is not None and not group.get("enabled", True):
            return None

        if self._config.get("dns", "block_non_latin", default=False) and is_non_latin_domain(qname):
            return "Non-Latin-script domain filter"

        matched = self._find_match(qname, blocked)
        if matched is not None:
            source = domain_source.get(matched)
            return f"Blocklist: {source}" if source else "Blocklist"

        if group is not None:
            group_name = group.get("name", "")
            matched = self._find_match(qname, group_blocked.get(group_name, frozenset()))
            if matched is not None:
                source = group_domain_source.get(group_name, {}).get(matched)
                label = f'Blocklist (client group "{group_name}")'
                return f"{label}: {source}" if source else label

        return None

    def alert_match(self, qname: str) -> tuple[str, str | None] | None:
        qname = qname.rstrip(".").lower()
        with self._lock:
            alert_matched, alert_domain_source = self._alert_matched, self._alert_domain_source
        matched = self._find_match(qname, alert_matched)
        if matched is None:
            return None
        return matched, alert_domain_source.get(matched)

    def _compiled_regex_patterns(self) -> list[tuple[str, re.Pattern]]:
        patterns = tuple(self._config.get("denylist_regex", default=[]) or [])
        with self._regex_lock:
            if patterns != self._regex_cache_key:
                compiled = []
                for pat in patterns:
                    try:
                        compiled.append((pat, re.compile(pat)))
                    except re.error as exc:
                        logger.warning("skipping invalid regex denylist pattern %r: %s", pat, exc)
                self._regex_cache_compiled = compiled
                self._regex_cache_key = patterns
            return self._regex_cache_compiled

    @staticmethod
    def _find_match(qname: str, domain_set: frozenset[str]) -> str | None:
        if qname in domain_set:
            return qname
        labels = qname.split(".")
        for i in range(1, len(labels)):
            candidate = ".".join(labels[i:])
            if candidate in domain_set:
                return candidate
        return None

    def _find_group(self, client_ip: str | None) -> dict[str, Any] | None:
        if not client_ip:
            return None
        groups = self._config.get("client_groups", default=[]) or []
        for group in groups:
            for pattern in group.get("match", []) or []:
                if ip_matches(client_ip, pattern):
                    return group
        return None

    def _is_client_blocked(self, client_ip: str | None) -> bool:
        if not client_ip:
            return False
        for pattern in self._config.get("blocked_clients", default=[]) or []:
            if ip_matches(client_ip, pattern):
                return True
        return False

    def answer_ip_blocked(self, ip: str | None) -> str | None:
        if not ip:
            return None
        for pattern in self._config.get("blocked_answer_ips", default=[]) or []:
            if ip_matches(ip, pattern):
                return pattern
        return None

    def source_counts(self) -> dict[str, int]:
        with self._lock:
            return dict(self._source_counts)

    def source_formats(self) -> dict[str, str]:
        with self._lock:
            return dict(self._source_formats)

    def total_count(self) -> int:
        with self._lock:
            return len(self._blocked)

    def allow_source_counts(self) -> dict[str, int]:
        with self._lock:
            return dict(self._allow_source_counts)

    def allow_source_formats(self) -> dict[str, str]:
        with self._lock:
            return dict(self._allow_source_formats)

    def allowed_count(self) -> int:
        with self._lock:
            return len(self._allowed)

    def group_source_counts(self, group_name: str) -> dict[str, int]:
        with self._lock:
            return dict(self._group_source_counts.get(group_name, {}))

    def group_source_formats(self, group_name: str) -> dict[str, str]:
        with self._lock:
            return dict(self._group_source_formats.get(group_name, {}))

    def group_total_count(self, group_name: str) -> int:
        with self._lock:
            return len(self._group_blocked.get(group_name, frozenset()))

    def alert_source_counts(self) -> dict[str, int]:
        with self._lock:
            return dict(self._alert_source_counts)

    def alert_source_formats(self) -> dict[str, str]:
        with self._lock:
            return dict(self._alert_source_formats)

    def alert_total_count(self) -> int:
        with self._lock:
            return len(self._alert_matched)

    def last_refresh(self) -> float | None:
        return self._last_refresh

    def _cache_path(self, name: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", name)
        return self._cache_dir / f"{safe}.cache"

    def _fetch_one(self, name: str, url: str) -> tuple[set[str], dict[str, int]]:
        cache_path = self._cache_path(name)
        try:
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            text = resp.text
            cache_path.write_text(text, encoding="utf-8")
        except Exception as exc:
            logger.warning("failed to fetch blocklist %r (%s): %s", name, url, exc)
            if cache_path.exists():
                text = cache_path.read_text(encoding="utf-8")
            else:
                return set(), {}
        return parse_list(text)

    def _fetch_sources(
        self, sources: Iterable[dict]
    ) -> tuple[set[str], dict[str, int], dict[str, str], dict[str, str]]:
        merged: set[str] = set()
        counts: dict[str, int] = {}
        formats: dict[str, str] = {}
        domain_source: dict[str, str] = {}
        for source in sources:
            if not source.get("enabled", True):
                continue
            name = source.get("name") or source.get("url", "unnamed")
            url = source.get("url")
            if not url:
                continue
            domains, format_counts = self._fetch_one(name, url)
            counts[name] = len(domains)
            formats[name] = describe_format(format_counts)
            merged |= domains
            for domain in domains:
                domain_source.setdefault(domain, name)
        return merged, counts, formats, domain_source

    def refresh(self) -> None:
        with self._refresh_lock:
            sources = self._config.get("blocklists", "sources", default=[]) or []
            merged, counts, formats, domain_source = self._fetch_sources(sources)

            allow_sources = self._config.get("blocklists", "allow_sources", default=[]) or []
            allow_merged, allow_counts, allow_formats, _ = self._fetch_sources(allow_sources)

            alert_sources = self._config.get("alert_rules", "sources", default=[]) or []
            alert_merged, alert_counts, alert_formats, alert_domain_source = self._fetch_sources(alert_sources)
            manual_alert_domains = {
                d.strip().rstrip(".").lower() for d in (self._config.get("alert_rules", "domains", default=[]) or [])
                if d.strip()
            }
            alert_merged |= manual_alert_domains
            for domain in manual_alert_domains:
                alert_domain_source.setdefault(domain, "manually added")

            group_blocked: dict[str, frozenset[str]] = {}
            group_domain_source: dict[str, dict[str, str]] = {}
            group_source_counts: dict[str, dict[str, int]] = {}
            group_source_formats: dict[str, dict[str, str]] = {}
            for group in self._config.get("client_groups", default=[]) or []:
                group_sources = group.get("blocklist_sources") or []
                if not group_sources:
                    continue
                name = group.get("name", "")
                g_merged, g_counts, g_formats, g_domain_source = self._fetch_sources(group_sources)
                group_blocked[name] = frozenset(g_merged)
                group_domain_source[name] = g_domain_source
                group_source_counts[name] = g_counts
                group_source_formats[name] = g_formats

            with self._lock:
                self._blocked = frozenset(merged)
                self._source_counts = counts
                self._source_formats = formats
                self._domain_source = domain_source
                self._allowed = frozenset(allow_merged)
                self._allow_source_counts = allow_counts
                self._allow_source_formats = allow_formats
                self._group_blocked = group_blocked
                self._group_domain_source = group_domain_source
                self._group_source_counts = group_source_counts
                self._group_source_formats = group_source_formats
                self._alert_matched = frozenset(alert_merged)
                self._alert_domain_source = alert_domain_source
                self._alert_source_counts = alert_counts
                self._alert_source_formats = alert_formats
                self._last_refresh = time.time()
            logger.info(
                "blocklist refresh complete: %d blocked domains from %d sources, "
                "%d allow-listed domains from %d sources, %d client group(s) with extra sources, "
                "%d alert-rule domain(s)",
                len(merged), len(counts), len(allow_merged), len(allow_counts), len(group_blocked),
                len(alert_merged),
            )

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
