from __future__ import annotations

import time
from typing import Any


def _line(buf: list[str], name: str, help_text: str, metric_type: str, value: float) -> None:
    buf.append(f"# HELP {name} {help_text}")
    buf.append(f"# TYPE {name} {metric_type}")
    buf.append(f"{name} {value}")


def render_metrics(
    stats,
    blocklist,
    started_at: float,
    cache=None,
    anomaly=None,
    dnssec_cache=None,
) -> str:
    buf: list[str] = []

    _line(buf, "dnsshield_uptime_seconds", "Time since the process started, in seconds.", "gauge", time.time() - started_at)

    _line(buf, "dnsshield_queries_total", "Total DNS queries handled, across all workers.", "counter", stats.total_count())
    _line(buf, "dnsshield_blocked_total", "Total DNS queries blocked, across all workers.", "counter", stats.blocked_count())

    _line(buf, "dnsshield_blocklist_domains", "Number of distinct domains currently on the active blocklist.", "gauge", blocklist.total_count())
    _line(buf, "dnsshield_allowlist_domains", "Number of distinct domains currently on the active allowlist.", "gauge", blocklist.allowed_count())

    if cache is not None:
        cache_stats = cache.stats()
        _line(buf, "dnsshield_cache_entries", "Number of entries currently held in the DNS answer cache.", "gauge", cache_stats.get("entries", 0))
        _line(buf, "dnsshield_cache_hits_total", "Total DNS answer cache hits since process start.", "counter", cache_stats.get("hits", 0))
        _line(buf, "dnsshield_cache_misses_total", "Total DNS answer cache misses since process start.", "counter", cache_stats.get("misses", 0))
        _line(buf, "dnsshield_cache_stale_hits_total", "Total DNS answer cache hits served stale (upstream unreachable) since process start.", "counter", cache_stats.get("stale_hits", 0))

    if anomaly is not None:
        _line(buf, "dnsshield_anomalies_unacknowledged", "Number of detected anomalies not yet acknowledged.", "gauge", anomaly.unacknowledged_count())

    if dnssec_cache is not None:
        counts = dnssec_cache.counts()
        _line(buf, "dnsshield_dnssec_secure_cached", "Domains currently cached as DNSSEC-secure (this process only).", "gauge", counts.get("secure", 0))
        _line(buf, "dnsshield_dnssec_insecure_cached", "Domains currently cached as DNSSEC-insecure (this process only).", "gauge", counts.get("insecure", 0))

    return "\n".join(buf) + "\n"
