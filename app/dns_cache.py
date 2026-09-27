from __future__ import annotations

import base64
import json
import threading
import time
from collections import OrderedDict
from pathlib import Path

from dnslib import RCODE, RR, DNSBuffer, DNSError, DNSRecord

CacheKey = tuple[str, int, int]
CacheEntry = tuple[float, list[RR], int]


class DNSCache:
    def __init__(self, config_store, persist_path: Path | None = None):
        self._config = config_store
        self._persist_path = persist_path
        self._lock = threading.Lock()
        self._store: OrderedDict[CacheKey, CacheEntry] = OrderedDict()
        self._prefetch_inflight: set[CacheKey] = set()
        self._hits = 0
        self._misses = 0
        self._stale_hits = 0
        if self._persist_path is not None:
            self._load()

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
            expires_at, answers, hits = entry
            remaining = expires_at - time.time()
            if remaining <= 0:
                self._misses += 1
                return None
            self._store[key] = (expires_at, answers, hits + 1)
            self._store.move_to_end(key)
            self._hits += 1
            ttl = max(1, int(remaining))

        reply = request.reply()
        for rr in answers:
            reply.add_answer(RR(rr.rname, rr.rtype, rclass=rr.rclass, ttl=ttl, rdata=rr.rdata))
        return reply

    def get_stale(self, request: DNSRecord, grace_seconds: float) -> DNSRecord | None:
        key = self._key(request)
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            expires_at, answers, _hits = entry
            if time.time() - expires_at > grace_seconds:
                return None
            self._stale_hits += 1

        reply = request.reply()
        for rr in answers:
            reply.add_answer(RR(rr.rname, rr.rtype, rclass=rr.rclass, ttl=1, rdata=rr.rdata))
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
            previous_hits = self._store[key][2] if key in self._store else 0
            self._store[key] = (time.time() + ttl, answers, previous_hits)
            self._store.move_to_end(key)
            self._prefetch_inflight.discard(key)
            while len(self._store) > max_entries:
                self._store.popitem(last=False)

    def expiring_soon(self, threshold_seconds: float, min_hits: int) -> list[CacheKey]:
        now = time.time()
        due = []
        with self._lock:
            for key, (expires_at, _answers, hits) in self._store.items():
                remaining = expires_at - now
                if 0 < remaining <= threshold_seconds and hits >= min_hits and key not in self._prefetch_inflight:
                    due.append(key)
        return due

    def mark_prefetching(self, key: CacheKey) -> None:
        with self._lock:
            self._prefetch_inflight.add(key)

    def clear_prefetching(self, key: CacheKey) -> None:
        with self._lock:
            self._prefetch_inflight.discard(key)

    def purge_expired(self, grace_seconds: float) -> None:
        now = time.time()
        with self._lock:
            stale_keys = [key for key, (expires_at, _a, _h) in self._store.items() if now - expires_at > grace_seconds]
            for key in stale_keys:
                del self._store[key]
                self._prefetch_inflight.discard(key)

    def stats(self) -> dict:
        with self._lock:
            return {
                "enabled": self._enabled(),
                "entries": len(self._store),
                "hits": self._hits,
                "misses": self._misses,
                "stale_hits": self._stale_hits,
            }

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._prefetch_inflight.clear()
            self._hits = 0
            self._misses = 0
            self._stale_hits = 0

    @staticmethod
    def _encode_rr(rr: RR) -> str:
        buf = DNSBuffer()
        rr.pack(buf)
        return base64.b64encode(buf.data).decode("ascii")

    @staticmethod
    def _decode_rr(blob: str) -> RR:
        return RR.parse(DNSBuffer(base64.b64decode(blob)))

    def _load(self) -> None:
        try:
            with open(self._persist_path, "r", encoding="utf-8") as f:
                saved = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, OSError, ValueError):
            return
        if not isinstance(saved, dict) or saved.get("version") != 1:
            return

        now = time.time()
        with self._lock:
            for entry in saved.get("entries", []):
                try:
                    qname, qtype, qclass = entry["key"]
                    expires_at = float(entry["expires_at"])
                    hits = int(entry["hits"])
                    answers = [self._decode_rr(blob) for blob in entry["answers"]]
                except (KeyError, TypeError, ValueError, DNSError):
                    continue
                if expires_at > now and answers:
                    self._store[(qname, qtype, qclass)] = (expires_at, answers, hits)

    def save(self) -> None:
        if self._persist_path is None:
            return
        with self._lock:
            snapshot = list(self._store.items())
        entries = [
            {
                "key": list(key),
                "expires_at": expires_at,
                "hits": hits,
                "answers": [self._encode_rr(rr) for rr in answers],
            }
            for key, (expires_at, answers, hits) in snapshot
        ]
        try:
            self._persist_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self._persist_path.with_suffix(".tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump({"version": 1, "entries": entries}, f)
            tmp_path.replace(self._persist_path)
        except OSError:
            pass
