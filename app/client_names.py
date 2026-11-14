# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import ipaddress
import logging
import queue
import sqlite3
import threading
import time
from pathlib import Path

from dnslib import QTYPE, DNSRecord

logger = logging.getLogger("dnsshield.client_names")

# How often the DHCP lease table is re-read for hostnames.
_LEASE_REFRESH_SECONDS = 30.0


def _normalize_ip(client_ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(client_ip.split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _resolver_address(resolver: str) -> tuple[str, int]:
    """"192.168.1.1", "192.168.1.1:5353", "[fd00::1]:53" or a bare "fd00::1"."""
    resolver = resolver.strip()
    if resolver.startswith("["):
        host, _, rest = resolver[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") and rest[1:] else 53
    if resolver.count(":") == 1:
        host, _, port = resolver.partition(":")
        return host, int(port) if port else 53
    return resolver, 53


class ClientNameResolver:
    """A display name for each client IP: the hostname the client gave the
    built-in DHCP server (leases and reservations, dns.client_names_from_dhcp,
    on by default), otherwise a PTR lookup at dns.client_name_resolver
    (dns.resolve_client_names), IPv4 and IPv6 alike."""

    def __init__(
        self, config_store, timeout: float = 1.0, negative_ttl: float = 60.0, leases_db: Path | None = None
    ):
        self._config = config_store
        self._timeout = timeout
        self._negative_ttl = negative_ttl
        self._leases_db = leases_db
        self._dhcp_lock = threading.Lock()
        self._dhcp_names: dict[str, str] = {}
        self._dhcp_loaded_at = 0.0
        self._dhcp_version = None

        self._lock = threading.Lock()
        self._cache: dict[str, tuple[str | None, float]] = {}
        self._pending: set[str] = set()
        self._queue: queue.Queue[str] = queue.Queue()

        threading.Thread(target=self._worker, name="client-name-resolver", daemon=True).start()

    def _dhcp_enabled(self) -> bool:
        return bool(self._config.get("dns", "client_names_from_dhcp", default=True))

    def _dhcp_snapshot(self) -> dict[str, str]:
        if not self._dhcp_enabled():
            return {}
        now = time.monotonic()
        version = getattr(self._config, "version", None)
        with self._dhcp_lock:
            if now - self._dhcp_loaded_at < _LEASE_REFRESH_SECONDS and version == self._dhcp_version:
                return self._dhcp_names
        names = self._load_dhcp_names()
        with self._dhcp_lock:
            self._dhcp_names, self._dhcp_loaded_at, self._dhcp_version = names, now, version
        return names

    def _load_dhcp_names(self) -> dict[str, str]:
        names: dict[str, str] = {}
        if self._leases_db is not None and self._leases_db.exists():
            try:
                conn = sqlite3.connect(f"file:{self._leases_db}?mode=ro", uri=True, timeout=2)
                try:
                    rows = conn.execute(
                        "SELECT ip, hostname FROM leases WHERE hostname IS NOT NULL AND hostname != '' "
                        "AND expires_at > ? ORDER BY expires_at",
                        (time.time(),),
                    ).fetchall()
                finally:
                    conn.close()
            except sqlite3.Error as exc:
                logger.debug("reading DHCP leases for client names failed: %s", exc)
                rows = []
            for ip, hostname in rows:
                names[str(ip)] = str(hostname).rstrip(".")
        # Reservations name a device even before (or without) a lease.
        for scope in self._config.get("dhcp", "scopes", default=[]) or []:
            for reservation in scope.get("reservations") or []:
                ip, hostname = reservation.get("ip"), reservation.get("hostname")
                if ip and hostname:
                    names[str(ip)] = str(hostname).rstrip(".")
        return names

    def _enabled(self) -> bool:
        return bool(self._config.get("dns", "resolve_client_names", default=False)) and bool(
            self._config.get("dns", "client_name_resolver", default="")
        )

    def touch(self, client_ip: str) -> None:
        if not self._enabled() or client_ip in self._dhcp_snapshot():
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
        names: dict[str, str] = {}
        if self._enabled():
            with self._lock:
                names = {ip: name for ip, (name, _) in self._cache.items() if name}
        names.update(self._dhcp_snapshot())
        return names

    def get(self, client_ip: str) -> str | None:
        name = self._dhcp_snapshot().get(client_ip)
        if name:
            return name
        if not self._enabled():
            return None
        with self._lock:
            entry = self._cache.get(client_ip)
        return entry[0] if entry else None

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
        try:
            host, port = _resolver_address(resolver)
        except ValueError:
            logger.debug("invalid dns.client_name_resolver %r", resolver)
            return None
        address = _normalize_ip(client_ip)
        if address is None:
            return None

        ptr_name = address.reverse_pointer
        try:
            request = DNSRecord.question(ptr_name, qtype="PTR")
            data = request.send(host, port, timeout=self._timeout, ipv6=":" in host)
            response = DNSRecord.parse(data)
        except Exception as exc:
            logger.debug("PTR lookup for %s via %s failed: %s", client_ip, host, exc)
            return None

        for rr in response.rr:
            if rr.rtype == QTYPE.PTR:
                return str(rr.rdata).rstrip(".")
        return None
