# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Per-client query rate limiting (dns.rate_limit_qps, off by default).

Each client IP gets a token bucket: dns.rate_limit_qps tokens a second, up to
dns.rate_limit_burst saved up (default: twice the rate, at least 20). A query
over the limit is answered REFUSED straight away, before any filtering,
caching or upstream work, so one misbehaving device (a looping app, malware,
a flood) can't starve everyone else or burn the upstreams' quota.

Loopback and dns.rate_limit_exempt (IPs/CIDRs) are never limited. With
several DNS worker processes each one counts on its own, so the effective
limit is up to workers x qps."""

from __future__ import annotations

import ipaddress
import logging
import threading
import time

from app.netmatch import ip_matches

logger = logging.getLogger("dnsshield.rate_limit")

# Buckets idle this long are full again anyway, so they can be forgotten.
_IDLE_SECONDS = 60.0
_PRUNE_EVERY = 4096
_WARN_INTERVAL = 60.0


class ClientRateLimiter:
    def __init__(self, config_store, clock=time.monotonic):
        self._config = config_store
        self._clock = clock
        self._lock = threading.Lock()
        # client -> (tokens, last refill time)
        self._buckets: dict[str, tuple[float, float]] = {}
        self._calls = 0
        self._limited: dict[str, int] = {}
        self._last_warned: dict[str, float] = {}

    def _settings(self) -> tuple[float, float]:
        qps = float(self._config.get("dns", "rate_limit_qps", default=0) or 0)
        if qps <= 0:
            return 0.0, 0.0
        burst = float(self._config.get("dns", "rate_limit_burst", default=0) or 0)
        if burst <= 0:
            burst = max(qps * 2, 20.0)
        return qps, max(burst, 1.0)

    def _exempt(self, client_ip: str) -> bool:
        try:
            if ipaddress.ip_address(client_ip).is_loopback:
                return True
        except ValueError:
            return True
        exempt = self._config.get("dns", "rate_limit_exempt", default=[]) or []
        return any(ip_matches(client_ip, pattern) for pattern in exempt)

    def allow(self, client_ip: str) -> bool:
        qps, burst = self._settings()
        if qps <= 0 or self._exempt(client_ip):
            return True
        now = self._clock()
        with self._lock:
            self._calls += 1
            if self._calls % _PRUNE_EVERY == 0:
                self._prune(now)
            tokens, last = self._buckets.get(client_ip, (burst, now))
            tokens = min(burst, tokens + (now - last) * qps)
            if tokens >= 1.0:
                self._buckets[client_ip] = (tokens - 1.0, now)
                return True
            self._buckets[client_ip] = (tokens, now)
            self._limited[client_ip] = self._limited.get(client_ip, 0) + 1
            warn = now - self._last_warned.get(client_ip, -_WARN_INTERVAL) >= _WARN_INTERVAL
            if warn:
                self._last_warned[client_ip] = now
        if warn:
            logger.warning("client %s is over the query rate limit (%.0f/s) - refusing its queries", client_ip, qps)
        return False

    def _prune(self, now: float) -> None:
        idle = [ip for ip, (_tokens, last) in self._buckets.items() if now - last > _IDLE_SECONDS]
        for ip in idle:
            del self._buckets[ip]
        for ip in [ip for ip, at in self._last_warned.items() if now - at > _WARN_INTERVAL]:
            del self._last_warned[ip]
        if len(self._limited) > 10000:
            self._limited.clear()

    def limited_counts(self) -> dict[str, int]:
        """Refused queries per client since start (this process)."""
        with self._lock:
            return dict(self._limited)
