"""In-memory, TTL-respecting cache for upstream DNS answers.

Without this, every allowed query is forwarded to the upstream resolver
every single time, even for a domain that was just looked up a second
ago - and repeat lookups (CDN/ad/tracker hostnames requested by many
devices) are most of a home network's DNS traffic. Caching cuts both
latency and the number of queries that leave the network at all.

Purely local: an OrderedDict in process memory, bounded by max_entries
with LRU eviction. Nothing is written to disk and nothing is sent
anywhere else.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict

from dnslib import RCODE, RR, DNSRecord

CacheKey = tuple[str, int, int]


class DNSCache:
    def __init__(self, max_entries: int = 10000, min_ttl: int = 0, max_ttl: int = 3600):
        self._max_entries = max_entries
        self._min_ttl = min_ttl
        self._max_ttl = max_ttl
        self._lock = threading.Lock()
        self._store: OrderedDict[CacheKey, tuple[float, list[RR]]] = OrderedDict()
        self._hits = 0
        self._misses = 0

    @staticmethod
    def _key(request: DNSRecord) -> CacheKey:
        q = request.q
        return (str(q.qname).lower(), q.qtype, q.qclass)

    def get(self, request: DNSRecord) -> DNSRecord | None:
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
        if response.header.rcode != RCODE.NOERROR or response.header.tc:
            return
        answers = list(response.rr)
        if not answers:
            return

        ttl = min(rr.ttl for rr in answers)
        ttl = max(self._min_ttl, min(ttl, self._max_ttl))
        if ttl <= 0:
            return

        key = self._key(request)
        with self._lock:
            self._store[key] = (time.time() + ttl, answers)
            self._store.move_to_end(key)
            while len(self._store) > self._max_entries:
                self._store.popitem(last=False)

    def stats(self) -> dict:
        with self._lock:
            return {"entries": len(self._store), "hits": self._hits, "misses": self._misses}

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._hits = 0
            self._misses = 0
