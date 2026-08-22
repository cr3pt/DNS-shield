from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque

from dnslib import DNSRecord

from app import upstream as upstream_transport

logger = logging.getLogger("dnsshield.upstream_stats")

Sample = tuple[float, float, bool]


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

    def average_latency(self, upstream: str) -> float | None:
        oks = [lat for _, lat, ok in self._entries(upstream) if ok]
        return sum(oks) / len(oks) if oks else None

    def stability_penalty(self, upstream: str) -> float | None:
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
        except Exception as exc:
            self.record(upstream, time.monotonic() - start, False)
            logger.debug("health probe for upstream %s failed: %s", upstream, exc)

    def stop(self) -> None:
        self._stop_event.set()
