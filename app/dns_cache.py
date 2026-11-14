# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import base64
import json
import threading
import time
from collections import OrderedDict
from pathlib import Path

from dnslib import QTYPE, RCODE, RR, DNSBuffer, DNSError, DNSRecord

# (qname, qtype, qclass, variant). The variant separates answers that differ per
# client profile (SafeSearch, client-group upstreams), so one client's answer is
# never served to a client with a different policy. "" = the default profile.
CacheKey = tuple[str, int, int, str]
CacheEntry = tuple[float, list[RR], int]

_DNSSEC_RTYPES = frozenset({QTYPE.RRSIG, QTYPE.NSEC, QTYPE.NSEC3, QTYPE.NSEC3PARAM, QTYPE.DNSKEY, QTYPE.DS})
_EDNS_DO_BIT = 1 << 15
_PERSIST_VERSION = 2


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
        self._generation = config_store.get("dns", "cache_generation", default=0)
        if self._persist_path is not None:
            self._load()

    def _enabled(self) -> bool:
        if self._config.get("dns", "cache_generation", default=0) != self._generation:
            # Another process asked every cache to be flushed.
            self.clear()
        return bool(self._config.get("dns", "cache_enabled", default=True))

    def sync_generation(self) -> None:
        self._generation = self._config.get("dns", "cache_generation", default=0)

    @staticmethod
    def _key(request: DNSRecord, variant: str = "") -> CacheKey:
        q = request.q
        return (str(q.qname).lower(), q.qtype, q.qclass, variant)

    def get(self, request: DNSRecord, variant: str = "") -> DNSRecord | None:
        if not self._enabled():
            return None

        key = self._key(request, variant)
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

        reply = request.reply(aa=0)
        for rr in self._matching_answers(request, answers):
            reply.add_answer(
                RR(self._match_case(request, rr.rname), rr.rtype, rclass=rr.rclass, ttl=ttl, rdata=rr.rdata)
            )
        return reply

    def get_stale(self, request: DNSRecord, grace_seconds: float, variant: str = "") -> DNSRecord | None:
        key = self._key(request, variant)
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            expires_at, answers, _hits = entry
            if time.time() - expires_at > grace_seconds:
                return None
            self._stale_hits += 1

        reply = request.reply(aa=0)
        for rr in self._matching_answers(request, answers):
            reply.add_answer(
                RR(self._match_case(request, rr.rname), rr.rtype, rclass=rr.rclass, ttl=1, rdata=rr.rdata)
            )
        return reply

    @classmethod
    def _matching_answers(cls, request: DNSRecord, answers: list[RR]) -> list[RR]:
        if cls._wants_dnssec(request):
            return answers
        return [rr for rr in answers if rr.rtype not in _DNSSEC_RTYPES]

    @staticmethod
    def _wants_dnssec(request: DNSRecord) -> bool:
        for rr in request.ar:
            if rr.rtype == QTYPE.OPT:
                return bool(rr.ttl & _EDNS_DO_BIT)
        return False

    @staticmethod
    def _match_case(request: DNSRecord, rname):
        original = request.q.qname
        if str(rname).rstrip(".").lower() == str(original).rstrip(".").lower():
            return original
        return rname

    def put(self, request: DNSRecord, response: DNSRecord, variant: str = "") -> None:
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
        key = self._key(request, variant)
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
        self._generation = self._config.get("dns", "cache_generation", default=0)
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
        # Version 1 files predate the per-profile variant and may hold answers
        # that belong to another client's policy, so they are dropped.
        if not isinstance(saved, dict) or saved.get("version") != _PERSIST_VERSION:
            return

        now = time.time()
        with self._lock:
            for entry in saved.get("entries", []):
                try:
                    qname, qtype, qclass, variant = entry["key"]
                    expires_at = float(entry["expires_at"])
                    hits = int(entry["hits"])
                    answers = [self._decode_rr(blob) for blob in entry["answers"]]
                except (KeyError, TypeError, ValueError, DNSError):
                    continue
                if expires_at > now and answers:
                    self._store[(str(qname), int(qtype), int(qclass), str(variant))] = (expires_at, answers, hits)

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
                json.dump({"version": _PERSIST_VERSION, "entries": entries}, f)
            tmp_path.replace(self._persist_path)
        except OSError:
            pass
