"""Best-effort client hostname display via reverse DNS (PTR lookups).

Point this at your router (not the ad-filtering upstream) - most home
routers answer PTR queries for their DHCP clients with the name the
device advertised, e.g. "laptop-jan.lan". This is purely a display aid
for the dashboard: `touch()` is called on every DNS query but only ever
does a cheap dict lookup on the hot path - if a client IP is new or its
cached name has expired, the actual PTR lookup is handed off to a
background worker thread so it never delays answering the client's real
query. Nothing here is written to disk; the name cache is in memory only.
"""

from __future__ import annotations

import logging
import queue
import threading
import time

from dnslib import QTYPE, DNSRecord

logger = logging.getLogger("dnsshield.client_names")


class ClientNameResolver:
    def __init__(self, resolver: str, timeout: float = 1.0, cache_ttl: float = 3600.0, negative_ttl: float = 60.0):
        host, _, port_str = resolver.partition(":")
        self._host = host
        self._port = int(port_str) if port_str else 53
        self._timeout = timeout
        self._cache_ttl = cache_ttl
        self._negative_ttl = negative_ttl

        self._lock = threading.Lock()
        self._cache: dict[str, tuple[str | None, float]] = {}
        self._pending: set[str] = set()
        self._queue: "queue.Queue[str]" = queue.Queue()

        threading.Thread(target=self._worker, name="client-name-resolver", daemon=True).start()

    def touch(self, client_ip: str) -> None:
        """Non-blocking: refreshes the background resolution if needed."""
        with self._lock:
            entry = self._cache.get(client_ip)
            if entry is not None and entry[1] > time.time():
                return
            if client_ip in self._pending:
                return
            self._pending.add(client_ip)
        self._queue.put(client_ip)

    def snapshot(self) -> dict[str, str]:
        with self._lock:
            return {ip: name for ip, (name, _) in self._cache.items() if name}

    def _worker(self) -> None:
        while True:
            client_ip = self._queue.get()
            name = self._resolve(client_ip)
            ttl = self._cache_ttl if name else self._negative_ttl
            with self._lock:
                self._cache[client_ip] = (name, time.time() + ttl)
                self._pending.discard(client_ip)

    def _resolve(self, client_ip: str) -> str | None:
        octets = client_ip.split(".")
        if len(octets) != 4 or not all(o.isdigit() for o in octets):
            return None  # only IPv4 in-addr.arpa lookups are supported

        ptr_name = ".".join(reversed(octets)) + ".in-addr.arpa"
        try:
            request = DNSRecord.question(ptr_name, qtype="PTR")
            data = request.send(self._host, self._port, timeout=self._timeout)
            response = DNSRecord.parse(data)
        except Exception as exc:  # noqa: BLE001
            logger.debug("PTR lookup for %s via %s failed: %s", client_ip, self._host, exc)
            return None

        for rr in response.rr:
            if rr.rtype == QTYPE.PTR:
                return str(rr.rdata).rstrip(".")
        return None
