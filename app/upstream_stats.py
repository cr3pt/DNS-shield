"""Per-upstream latency/success tracking, for picking a "best" upstream.

Every real query already records how long its upstream took to answer
(or whether it failed) via record(). On top of that, a background thread
periodically probes *every* configured upstream directly (not just the
ones real traffic happens to use) so stats stay fresh even for a server
that a "fastest"/"most_stable" strategy has stopped picking - otherwise
a losing server's numbers would go stale and it could never be picked
again even if it improved. Probes only ever go to upstream hosts you
configured yourself, at a low, capped rate.

Everything here is in-process memory only - nothing persisted to disk,
nothing sent anywhere beyond the upstreams already in your config.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque

from dnslib import DNSRecord

from app import upstream as upstream_transport

logger = logging.getLogger("dnsshield.upstream_stats")

Sample = tuple[float, float, bool]  # (timestamp, latency_seconds, success)


class UpstreamStats:
    def __init__(self, config_store, probe_domain: str = "example.com", probe_timeout: float = 3.0):
        self._config = config_store
        self._probe_domain = probe_domain
        self._probe_timeout = probe_timeout
        self._lock = threading.Lock()
        self._samples: dict[str, deque[Sample]] = defaultdict(deque)
        self._stop_event = threading.Event()

        threading.Thread(target=self._probe_loop, name="upstream-prober", daemon=True).start()

    def _window_seconds(self) -> float:
        minutes = float(self._config.get("dns", "upstream_stats_window_minutes", default=15))
        return max(1.0, minutes) * 60

    # -- recording ------------------------------------------------------
    def record(self, upstream: str, latency: float, success: bool) -> None:
        now = time.time()
        cutoff = now - self._window_seconds()
        with self._lock:
            dq = self._samples[upstream]
            dq.append((now, latency, success))
            while dq and dq[0][0] < cutoff:
                dq.popleft()

    def _entries(self, upstream: str) -> list[Sample]:
        cutoff = time.time() - self._window_seconds()
        with self._lock:
            dq = self._samples.get(upstream)
            if not dq:
                return []
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            return list(dq)

    # -- ranking ----------------------------------------------------------
    def average_latency(self, upstream: str) -> float | None:
        oks = [lat for _, lat, ok in self._entries(upstream) if ok]
        return sum(oks) / len(oks) if oks else None

    def stability_penalty(self, upstream: str) -> float | None:
        """Lower is better: failures dominate, then latency variability."""
        entries = self._entries(upstream)
        if not entries:
            return None
        oks = [lat for _, lat, ok in entries if ok]
        failure_rate = 1 - (len(oks) / len(entries))
        if not oks:
            return None
        mean = sum(oks) / len(oks)
        variance = sum((x - mean) ** 2 for x in oks) / len(oks)
        coeff_of_variation = (variance**0.5) / mean if mean > 0 else 0.0
        return failure_rate * 10 + coeff_of_variation

    def rank(self, upstreams: list[str], strategy: str) -> list[str]:
        """Best-first ordering of upstreams under the given strategy.

        Upstreams with no data yet are tried last-but-still-tried, in
        their original relative order, so they get a chance to build up
        stats (and so a brand new upstream isn't ignored forever).
        """
        if strategy not in ("fastest", "most_stable"):
            return list(upstreams)

        scored: list[tuple[float, str]] = []
        unscored: list[str] = []
        for u in upstreams:
            value = self.average_latency(u) if strategy == "fastest" else self.stability_penalty(u)
            if value is None:
                unscored.append(u)
            else:
                scored.append((value, u))
        scored.sort(key=lambda pair: pair[0])
        return [u for _, u in scored] + unscored

    def snapshot(self) -> dict[str, dict]:
        result = {}
        for upstream in list(self._samples.keys()):
            entries = self._entries(upstream)
            if not entries:
                continue
            oks = [lat for _, lat, ok in entries if ok]
            result[upstream] = {
                "samples": len(entries),
                "success_rate": len(oks) / len(entries),
                "avg_latency_ms": round(sum(oks) / len(oks) * 1000, 1) if oks else None,
            }
        return result

    # -- background health probing -----------------------------------------
    def _probe_loop(self) -> None:
        while not self._stop_event.wait(120):
            upstreams = self._config.get("dns", "upstreams", default=[]) or []
            for upstream in upstreams:
                threading.Thread(target=self._probe_one, args=(upstream,), daemon=True).start()

    def _probe_one(self, upstream: str) -> None:
        request = DNSRecord.question(self._probe_domain, qtype="A").pack()
        start = time.monotonic()
        try:
            upstream_transport.forward(request, upstream, self._probe_timeout)
            self.record(upstream, time.monotonic() - start, True)
        except Exception as exc:  # noqa: BLE001
            self.record(upstream, time.monotonic() - start, False)
            logger.debug("health probe for upstream %s failed: %s", upstream, exc)

    def stop(self) -> None:
        self._stop_event.set()
