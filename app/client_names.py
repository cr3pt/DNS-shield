"""Best-effort client hostname display via reverse DNS (PTR lookups).

Point dns.client_name_resolver at your router (not the ad-filtering
upstream) - most home routers answer PTR queries for their DHCP clients
with the name the device advertised, e.g. "laptop-jan.lan". This is
purely a display aid for the dashboard: `touch()` is called on every DNS
query but only ever does a cheap dict lookup on the hot path - if a
client IP is new or its cached name has expired, the actual PTR lookup is
handed off to a background worker thread so it never delays answering
the client's real query. Nothing here is written to disk; the name cache
is in memory only.

Whether this is active, and which resolver/TTL to use, is read from the
config store on every use, so toggling it from the web UI takes effect
immediately without a restart.
"""

from __future__ import annotations

import logging
import queue
import threading
import time

from dnslib import QTYPE, DNSRecord

logger = logging.getLogger("dnsshield.client_names")


class ClientNameResolver:
    def __init__(self, config_store, timeout: float = 1.0, negative_ttl: float = 60.0):
        self._config = config_store
        self._timeout = timeout
        self._negative_ttl = negative_ttl

        self._lock = threading.Lock()
        self._cache: dict[str, tuple[str | None, float]] = {}
        self._pending: set[str] = set()
        self._queue: "queue.Queue[str]" = queue.Queue()

        threading.Thread(target=self._worker, name="client-name-resolver", daemon=True).start()

    def _enabled(self) -> bool:
        return bool(self._config.get("dns", "resolve_client_names", default=False)) and bool(
            self._config.get("dns", "client_name_resolver", default="")
        )

    def touch(self, client_ip: str) -> None:
        """Non-blocking: refreshes the background resolution if needed."""
        if not self._enabled():
            return
        with self._lock:
            entry = self._cache.get(client_ip)
            if entry is not None and entry[1] > time.time():
                return
            if client_ip in self._pending:
                return
            self._pending.add(client_ip)
        self._queue.put(client_ip)

    def snapshot(self) -> dict[str, str]:
        if not self._enabled():
            return {}
        with self._lock:
            return {ip: name for ip, (name, _) in self._cache.items() if name}

    def _worker(self) -> None:
        while True:
            client_ip = self._queue.get()
            name = self._resolve(client_ip)
            cache_ttl = float(self._config.get("dns", "client_name_cache_seconds", default=3600))
            ttl = cache_ttl if name else self._negative_ttl
            with self._lock:
                self._cache[client_ip] = (name, time.time() + ttl)
                self._pending.discard(client_ip)

    def _resolve(self, client_ip: str) -> str | None:
        resolver = self._config.get("dns", "client_name_resolver", default="")
        if not resolver:
            return None
        host, _, port_str = resolver.partition(":")
        port = int(port_str) if port_str else 53

        octets = client_ip.split(".")
        if len(octets) != 4 or not all(o.isdigit() for o in octets):
            return None  # only IPv4 in-addr.arpa lookups are supported

        ptr_name = ".".join(reversed(octets)) + ".in-addr.arpa"
        try:
            request = DNSRecord.question(ptr_name, qtype="PTR")
            data = request.send(host, port, timeout=self._timeout)
            response = DNSRecord.parse(data)
        except Exception as exc:  # noqa: BLE001
            logger.debug("PTR lookup for %s via %s failed: %s", client_ip, host, exc)
            return None

        for rr in response.rr:
            if rr.rtype == QTYPE.PTR:
                return str(rr.rdata).rstrip(".")
        return None
