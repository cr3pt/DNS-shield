from __future__ import annotations

import threading
import time
from collections import OrderedDict

from dnslib import RCODE, RR, DNSRecord

CacheKey = tuple[str, int, int]


class DNSCache:
    def __init__(self, config_store):
        self._config = config_store
        self._lock = threading.Lock()
        self._store: OrderedDict[CacheKey, tuple[float, list[RR]]] = OrderedDict()
        self._hits = 0
        self._misses = 0

    def _enabled(self) -> bool:
        return bool(self._config.get("dns", "cache_enabled", default=True))

    @staticmethod
    def _key(request: DNSRecord) -> CacheKey:
        q = request.q
        return (str(q.qname).lower(), q.qtype, q.qclass)

    def get(self, request: DNSRecord) -> DNSRecord | None:
        if not self._enabled():
            return None

        key = self._key(request)
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return None
            expires_at, answers = entry
            remaining = expires_at - time.time()
            if remaining <= 0:
                del self._store[key]
                self._misses += 1
                return None
            self._store.move_to_end(key)
            self._hits += 1
            ttl = max(1, int(remaining))

        reply = request.reply()
        for rr in answers:
            reply.add_answer(RR(rr.rname, rr.rtype, rclass=rr.rclass, ttl=ttl, rdata=rr.rdata))
        return reply

    def put(self, request: DNSRecord, response: DNSRecord) -> None:
        if not self._enabled():
            return
        if response.header.rcode != RCODE.NOERROR or response.header.tc:
            return
        answers = list(response.rr)
        if not answers:
            return

        min_ttl = int(self._config.get("dns", "cache_min_ttl_seconds", default=0))
        max_ttl = int(self._config.get("dns", "cache_max_ttl_seconds", default=3600))
        ttl = min(rr.ttl for rr in answers)
        ttl = max(min_ttl, min(ttl, max_ttl))
        if ttl <= 0:
            return

        max_entries = int(self._config.get("dns", "cache_max_entries", default=10000))
        key = self._key(request)
        with self._lock:
            self._store[key] = (time.time() + ttl, answers)
            self._store.move_to_end(key)
            while len(self._store) > max_entries:
                self._store.popitem(last=False)

    def stats(self) -> dict:
        with self._lock:
            return {"enabled": self._enabled(), "entries": len(self._store), "hits": self._hits, "misses": self._misses}

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._hits = 0
            self._misses = 0
