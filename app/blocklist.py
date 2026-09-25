from __future__ import annotations

import ipaddress
import logging
import re
import threading
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable

import requests

from app.netmatch import client_matches
from app.schedule import is_schedule_blocked
from app.typosquat import DEFAULT_PROTECTED_DOMAINS, find_typosquat_match
from app.upstream import protected_hostnames

logger = logging.getLogger("dnsshield.blocklist")

_HOSTS_PREFIXES = ("0.0.0.0 ", "127.0.0.1 ", "::1 ", "0.0.0.0\t", "127.0.0.1\t")
_ADBLOCK_RE = re.compile(r"^\|\|([a-z0-9.\-_]+)\^")
_ADBLOCK_EXCEPTION_RE = re.compile(r"^@@\|\|([a-z0-9.\-_]+)\^")
_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$")

DEFAULT_LOCAL_TLDS = ("local", "lan", "home", "internal", "corp", "home.arpa")

_FETCH_CACHE_TTL_SECONDS = 60.0


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
    "adblock_exception": "AdBlock exception (@@||domain^)",
    "plain": "plain domain list",
}


def _parse_line(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line or line.startswith(("#", "!", ";")):
        return None

    if line.startswith("@@||"):
        m = _ADBLOCK_EXCEPTION_RE.match(line)
        if m:
            domain = m.group(1)
            fmt = "adblock_exception"
        else:
            return None
    elif line.startswith("||"):
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
    elif line.startswith("@@"):
        return None
    else:
        domain = line.split()[0] if line.split() else ""
        fmt = "plain"

    domain = domain.strip().rstrip(".").lower()
    if domain in ("localhost", "local", "broadcasthost"):
        return None
    if not _DOMAIN_RE.match(domain):
        return None
    return domain, fmt


def parse_list(text: str) -> tuple[set[str], dict[str, int], set[str]]:
    domains: set[str] = set()
    exceptions: set[str] = set()
    format_counts: dict[str, int] = {}
    for raw_line in text.splitlines():
        parsed = _parse_line(raw_line)
        if parsed:
            domain, fmt = parsed
            format_counts[fmt] = format_counts.get(fmt, 0) + 1
            if fmt == "adblock_exception":
                exceptions.add(domain)
            else:
                domains.add(domain)
    return domains, format_counts, exceptions


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


_IP_FORMAT_LABELS = {"ip": "IP list", "cidr": "CIDR list"}


def parse_ip_list(text: str) -> tuple[set[str], dict[str, int], set[str]]:
    entries: set[str] = set()
    format_counts: dict[str, int] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "!", ";")):
            continue
        candidate = line.split()[0] if line.split() else ""
        candidate = candidate.rstrip(",")
        if not candidate:
            continue
        if "/" in candidate:
            try:
                ipaddress.ip_network(candidate, strict=False)
            except ValueError:
                continue
            fmt = "cidr"
        else:
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            fmt = "ip"
        entries.add(candidate)
        format_counts[fmt] = format_counts.get(fmt, 0) + 1
    return entries, format_counts, set()


def describe_ip_format(format_counts: dict[str, int]) -> str:
    if not format_counts:
        return "unknown"
    present = list(format_counts.keys())
    if len(present) == 1:
        return _IP_FORMAT_LABELS.get(present[0], present[0])
    labels = " + ".join(_IP_FORMAT_LABELS.get(fmt, fmt) for fmt in sorted(present, key=lambda f: -format_counts[f]))
    return f"mixed ({labels})"


class BlocklistManager:
    def __init__(self, config_store, cache_dir: Path, mac_resolver=None, client_names=None):
        self._config = config_store
        self._cache_dir = cache_dir
        self._mac_resolver = mac_resolver
        self._client_names = client_names
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

        self._fetch_cache: dict[tuple[str, Any], tuple[float, set[str], dict[str, int], set[str]]] = {}
        self._fetch_cache_lock = threading.Lock()

        self._regex_lock = threading.Lock()
        self._regex_cache_key: tuple[str, ...] | None = None
        self._regex_cache_compiled: list[tuple[str, re.Pattern]] = []

        self._answer_ip_exact: frozenset[str] = frozenset()
        self._answer_ip_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._answer_ip_source: dict[str, str] = {}
        self._answer_ip_source_counts: dict[str, int] = {}
        self._answer_ip_source_formats: dict[str, str] = {}

        self._typosquat_lock = threading.Lock()
        self._typosquat_cache: dict[str, tuple[str, str, int] | None] = {}

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
        if group is not None and is_schedule_blocked(group.get("schedule")):
            return f'Scheduled block (client group "{group.get("name", "")}")'
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

    def typosquat_match(self, qname: str) -> tuple[str, str, int] | None:
        if not self._config.get("dns", "typosquat_enabled", default=False):
            return None
        qname = qname.rstrip(".").lower()
        with self._typosquat_lock:
            if qname in self._typosquat_cache:
                return self._typosquat_cache[qname]

        extra = self._config.get("dns", "typosquat_extra_domains", default=[]) or []
        protected = list(DEFAULT_PROTECTED_DOMAINS) + list(extra)
        max_distance = int(self._config.get("dns", "typosquat_max_distance", default=2))
        result = find_typosquat_match(qname, protected, max_distance)

        with self._typosquat_lock:
            if len(self._typosquat_cache) > 50000:
                self._typosquat_cache.clear()
            self._typosquat_cache[qname] = result
        return result

    def clear_typosquat_cache(self) -> None:
        with self._typosquat_lock:
            self._typosquat_cache.clear()

    def local_tlds(self) -> list[str]:
        tlds = self._config.get("dns", "local_tld_list", default=None)
        return list(tlds) if tlds else list(DEFAULT_LOCAL_TLDS)

    def local_tld_match(self, qname: str) -> str | None:
        if not self._config.get("dns", "local_tld_alert_enabled", default=False):
            return None
        return self.local_tld_match_ignoring_toggle(qname)

    def local_tld_match_ignoring_toggle(self, qname: str) -> str | None:
        qname = qname.rstrip(".").lower()
        if not qname:
            return None
        for tld in self.local_tlds():
            tld = tld.strip(".").lower()
            if tld and (qname == tld or qname.endswith("." + tld)):
                return tld
        return None

    def lookup_domain(self, qname: str) -> dict[str, Any]:
        qname = qname.rstrip(".").lower()
        reason = self.block_reason(qname)
        alert = self.alert_match(qname)
        typo = self.typosquat_match(qname)
        local_tld = self.local_tld_match_ignoring_toggle(qname)
        with self._lock:
            on_allowlist = self._find_match(qname, self._allowed) is not None
        return {
            "domain": qname,
            "blocked": reason is not None,
            "block_reason": reason,
            "on_allowlist": on_allowlist,
            "alert_rule": {"domain": alert[0], "source": alert[1]} if alert else None,
            "typosquat": {"protected": typo[0], "kind": typo[1], "distance": typo[2]} if typo else None,
            "local_tld": local_tld,
        }

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

    def mac_for(self, client_ip: str) -> str | None:
        return self._mac_resolver.mac_for(client_ip) if self._mac_resolver is not None else None

    def _client_hostname(self, client_ip: str) -> str | None:
        return self._client_names.get(client_ip) if self._client_names is not None else None

    def _find_group(self, client_ip: str | None) -> dict[str, Any] | None:
        if not client_ip:
            return None
        groups = self._config.get("client_groups", default=[]) or []
        for group in groups:
            for pattern in group.get("match", []) or []:
                if client_matches(
                    client_ip, pattern, mac=self.mac_for(client_ip), hostname=self._client_hostname(client_ip)
                ):
                    return group
        return None

    def safe_search_enabled_for(self, client_ip: str | None) -> bool:
        group = self._find_group(client_ip)
        if group is not None and group.get("safe_search") is not None:
            return bool(group.get("safe_search"))
        return bool(self._config.get("dns", "safe_search_enabled", default=False))

    def _is_client_blocked(self, client_ip: str | None) -> bool:
        if not client_ip:
            return False
        for pattern in self._config.get("blocked_clients", default=[]) or []:
            if client_matches(
                client_ip, pattern, mac=self.mac_for(client_ip), hostname=self._client_hostname(client_ip)
            ):
                return True
        return False

    def answer_ip_blocked(self, ip: str | None) -> str | None:
        if not ip:
            return None
        with self._lock:
            exact, nets, source = self._answer_ip_exact, self._answer_ip_nets, self._answer_ip_source
        if ip in exact:
            return source.get(ip, ip)
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net in nets:
            if addr in net:
                return str(net)
        return None

    def answer_ip_source_counts(self) -> dict[str, int]:
        with self._lock:
            return dict(self._answer_ip_source_counts)

    def answer_ip_source_formats(self) -> dict[str, str]:
        with self._lock:
            return dict(self._answer_ip_source_formats)

    def answer_ip_total_count(self) -> int:
        with self._lock:
            return len(self._answer_ip_exact) + len(self._answer_ip_nets)

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

    def _fetch_one(
        self, name: str, url: str, parser=parse_list, network: bool = True
    ) -> tuple[set[str], dict[str, int], set[str]]:
        cache_path = self._cache_path(name)

        if not network:
            # Disk-only warm start (no network I/O) - never touches the in-memory
            # fetch cache, so the live refresh that follows shortly after isn't
            # short-circuited by a memoized "just fetched" entry.
            if cache_path.exists():
                return parser(cache_path.read_text(encoding="utf-8"))
            return (set(), {}, set())

        cache_key = (url, parser)
        now = time.time()
        with self._fetch_cache_lock:
            cached = self._fetch_cache.get(cache_key)
            if cached is not None and now - cached[0] < _FETCH_CACHE_TTL_SECONDS:
                return cached[1], cached[2], cached[3]

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
                result = (set(), {}, set())
                with self._fetch_cache_lock:
                    self._fetch_cache[cache_key] = (now, *result)
                return result
        result = parser(text)
        with self._fetch_cache_lock:
            self._fetch_cache[cache_key] = (now, *result)
        return result

    def _fetch_sources(
        self, sources: Iterable[dict], parser=parse_list, describer=describe_format, network: bool = True
    ) -> tuple[set[str], dict[str, int], dict[str, str], dict[str, str], set[str]]:
        merged: set[str] = set()
        counts: dict[str, int] = {}
        formats: dict[str, str] = {}
        domain_source: dict[str, str] = {}
        exceptions: set[str] = set()

        enabled: list[tuple[str, str]] = [
            (source.get("name") or source.get("url", "unnamed"), source.get("url"))
            for source in sources
            if source.get("enabled", True) and source.get("url")
        ]
        if not enabled:
            return merged, counts, formats, domain_source, exceptions

        # Sources are fetched concurrently (each is an independent HTTP round-trip) -
        # merged below in original list order so a domain's credited source stays
        # deterministic regardless of which request happens to finish first.
        results: dict[str, tuple[set[str], dict[str, int], set[str]]] = {}
        with ThreadPoolExecutor(max_workers=min(8, len(enabled))) as executor:
            future_to_name = {
                executor.submit(self._fetch_one, name, url, parser, network): name for name, url in enabled
            }
            for future in as_completed(future_to_name):
                results[future_to_name[future]] = future.result()

        for name, _url in enabled:
            domains, format_counts, source_exceptions = results[name]
            counts[name] = len(domains)
            formats[name] = describer(format_counts)
            merged |= domains
            exceptions |= source_exceptions
            for domain in domains:
                domain_source.setdefault(domain, name)
        return merged, counts, formats, domain_source, exceptions

    def refresh(self, network: bool = True) -> None:
        with self._refresh_lock:
            sources = self._config.get("blocklists", "sources", default=[]) or []
            merged, counts, formats, domain_source, block_exceptions = self._fetch_sources(
                sources, network=network
            )

            allow_sources = self._config.get("blocklists", "allow_sources", default=[]) or []
            allow_merged, allow_counts, allow_formats, _, allow_exceptions = self._fetch_sources(
                allow_sources, network=network
            )
            allow_merged |= block_exceptions | allow_exceptions

            alert_sources = self._config.get("alert_rules", "sources", default=[]) or []
            alert_merged, alert_counts, alert_formats, alert_domain_source, _ = self._fetch_sources(
                alert_sources, network=network
            )
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
                g_merged, g_counts, g_formats, g_domain_source, g_exceptions = self._fetch_sources(
                    group_sources, network=network
                )
                group_blocked[name] = frozenset(g_merged - g_exceptions)
                group_domain_source[name] = g_domain_source
                group_source_counts[name] = g_counts
                group_source_formats[name] = g_formats

            answer_ip_sources = self._config.get("blocked_answer_ip_sources", default=[]) or []
            answer_ip_merged, answer_ip_counts, answer_ip_formats, answer_ip_source, _ = self._fetch_sources(
                answer_ip_sources, parser=parse_ip_list, describer=describe_ip_format, network=network
            )
            manual_answer_ips = {
                v.strip() for v in (self._config.get("blocked_answer_ips", default=[]) or []) if v.strip()
            }
            answer_ip_merged |= manual_answer_ips
            for value in manual_answer_ips:
                answer_ip_source.setdefault(value, "manually added")
            answer_ip_exact: set[str] = set()
            answer_ip_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
            for value in answer_ip_merged:
                if "/" in value:
                    try:
                        answer_ip_nets.append(ipaddress.ip_network(value, strict=False))
                    except ValueError:
                        continue
                else:
                    answer_ip_exact.add(value)

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
                self._answer_ip_exact = frozenset(answer_ip_exact)
                self._answer_ip_nets = answer_ip_nets
                self._answer_ip_source = answer_ip_source
                self._answer_ip_source_counts = answer_ip_counts
                self._answer_ip_source_formats = answer_ip_formats
                if network:
                    self._last_refresh = time.time()
            logger.info(
                "blocklist %s complete: %d blocked domains from %d sources, "
                "%d allow-listed domains from %d sources, %d client group(s) with extra sources, "
                "%d alert-rule domain(s), %d blocked destination IP entries from %d sources",
                "refresh" if network else "warm start from disk cache",
                len(merged), len(counts), len(allow_merged), len(allow_counts), len(group_blocked),
                len(alert_merged), len(answer_ip_exact) + len(answer_ip_nets), len(answer_ip_counts),
            )

    def start(self) -> None:
        # Load whatever was cached on disk from the last successful fetch
        # synchronously (no network, effectively instant) so DNS/web start
        # already protected - then fetch live in the background thread. Only
        # a truly first-ever run (nothing cached yet) waits on the network.
        try:
            self.refresh(network=False)
        except Exception:
            logger.exception("blocklist warm start from disk cache failed")
        self._thread = threading.Thread(target=self._loop, name="blocklist-refresh", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _loop(self) -> None:
        self.refresh()
        while not self._stop_event.is_set():
            hours = self._config.get("blocklists", "refresh_interval_hours", default=24) or 24
            interval = max(float(hours), 0.25) * 3600
            if self._stop_event.wait(interval):
                return
            self.refresh()
