# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import secrets
import socket
import ssl
import struct
import time
import weakref
from collections.abc import Set as AbstractSet
from urllib.parse import urlparse

import aiohttp
from dnslib import DNSRecord

from app.enrichment import THREAT_INTEL_HOSTNAMES

DOH_CONTENT_TYPE = "application/dns-message"

# Async TTL cache for forward_plain: keyed by (query_hash, upstream).
_cache: dict[tuple[str, str], tuple[bytes, float]] = {}
_cache_lock = asyncio.Lock()
_CACHE_TTL_SECONDS = 60.0


def _query_hash(query: bytes) -> str:
    """Deterministic hash of a DNS query for cache keying."""
    return hashlib.sha256(query).hexdigest()


async def _forward_plain_cached(
    data: bytes, upstream: str, timeout: float,
) -> bytes:
    """Cache wrapper around forward_plain with TTL expiration."""
    qhash = _query_hash(data)
    key = (qhash, upstream)
    async with _cache_lock:
        entry = _cache.get(key)
        if entry is not None:
            resp, expires = entry
            if time.monotonic() < expires:
                return resp
    resp = await forward_plain(data, upstream, timeout)
    async with _cache_lock:
        _cache[key] = (resp, time.monotonic() + _CACHE_TTL_SECONDS)
    return resp


# Lazy-initialized async session for DNS-over-HTTPS.
_doh_session: aiohttp.ClientSession | None = None
_doh_connector: aiohttp.TCPConnector | None = None


def _get_doh_session() -> aiohttp.ClientSession:
    global _doh_session, _doh_connector
    if _doh_session is None:
        _doh_connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=20,
            enable_cleanup_closed=True,
        )
        _doh_session = aiohttp.ClientSession(connector=_doh_connector)
    return _doh_session


# DNS-over-QUIC (RFC 9250). "quic://" is what AdGuard Home and dnsproxy call it.
DOQ_PREFIXES = ("quic://", "doq://")


def _split_host_port(entry: str, default_port: int) -> tuple[str, int]:
    entry = entry.strip()
    if entry.startswith("["):
        closing = entry.find("]")
        if closing != -1:
            host = entry[1:closing]
            rest = entry[closing + 1 :]
            if rest.startswith(":") and rest[1:].isdigit():
                return host, int(rest[1:])
            return host, default_port
    if entry.count(":") > 1:
        return entry, default_port
    host, _, port_str = entry.partition(":")
    return host, int(port_str) if port_str.isdigit() else default_port


async def forward(data: bytes, upstream: str, timeout: float) -> bytes:
    if upstream.startswith("dot://"):
        return await forward_dot(data, upstream[len("dot://") :], timeout)
    if upstream.startswith(DOQ_PREFIXES):
        from app import doq  # aioquic is only loaded once a DoQ upstream is used

        host, port = _split_host_port(upstream.split("://", 1)[1].split("/", 1)[0], doq.DEFAULT_PORT)
        return await asyncio.to_thread(doq.forward, data, host, port, timeout)
    if upstream.startswith("doh://"):
        return await forward_doh(data, "https://" + upstream[len("doh://") :], timeout)
    if upstream.startswith("https://"):
        return await forward_doh(data, upstream, timeout)
    return await _forward_plain_cached(data, upstream, timeout)


def _question_of(packet: bytes) -> tuple[str, int, int] | None:
    """(qname exactly as written - case preserved, qtype, qclass) of the
    first question in a DNS message, or None if it can't be parsed."""
    try:
        record = DNSRecord.parse(packet)
    except Exception:
        return None
    if not record.questions:
        return None
    q = record.questions[0]
    return str(q.qname), q.qtype, q.qclass


def _check_response(query: bytes, resp: bytes) -> str:
    """Return "ok", "case" (same question but different letter case - the
    upstream doesn't preserve 0x20 randomization) or "mismatch"."""
    if len(resp) < 12 or resp[:2] != query[:2]:
        return "mismatch"
    if not resp[2] & 0x80:  # QR bit: must be a response
        return "mismatch"
    sent = _question_of(query)
    got = _question_of(resp)
    if sent is None or got is None:
        return "mismatch"
    if sent == got:
        return "ok"
    if (sent[0].lower(), sent[1], sent[2]) == (got[0].lower(), got[1], got[2]):
        return "case"
    return "mismatch"


class _DNSDatagramProtocol(asyncio.DatagramProtocol):
    """Minimal UDP datagram protocol for DNS: sends a query and waits for a response."""

    def __init__(self, query: bytes, family: int, destination: tuple[str, int]):
        self.query = query
        self.family = family
        self.destination = destination
        self.response: bytes | None = None
        self.response_event = asyncio.Event()

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport  # type: ignore[attr-defined]
        self.transport.sendto(self.query, self.destination)

    def datagram_received(self, data: bytes, addr: tuple):
        if self.response is not None:
            return  # Already got a valid response.
        verdict = _check_response(self.query, data)
        if verdict == "ok":
            self.response = data
            self.response_event.set()

    def error_received(self, exc: Exception | None):
        pass

    def connection_lost(self, exc: Exception | None):
        pass


async def forward_plain(data: bytes, upstream: str, timeout: float) -> bytes:
    host, port = _split_host_port(upstream, 53)
    family = socket.AF_INET6 if ":" in host else socket.AF_INET

    # A fresh random transaction ID per upstream query, independent of the
    # client's ID, so an off-path attacker has to guess both it and the
    # source port. The client's ID is put back on the way out.
    original_id = data[:2]
    query = secrets.token_bytes(2) + data[2:]
    deadline = time.monotonic() + timeout

    loop = asyncio.get_running_loop()
    protocol = _DNSDatagramProtocol(query, family, (host, port))
    transport, _ = await loop.create_datagram_endpoint(
        lambda: protocol,
        sock=socket.socket(family, socket.SOCK_DGRAM),
    )

    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"no matching response from {upstream}")
        await asyncio.wait_for(protocol.response_event.wait(), timeout=remaining)
    except asyncio.TimeoutError:
        raise TimeoutError(f"no matching response from {upstream}")

    resp = protocol.response
    verdict = _check_response(query, resp)

    if verdict == "case":
        return await forward_tcp(data, host, port, max(0.1, deadline - time.monotonic()))
    if len(resp) >= 3 and resp[2] & 0x02:
        return await forward_tcp(data, host, port, timeout)

    return original_id + resp[2:]


async def forward_tcp(data: bytes, host: str, port: int, timeout: float) -> bytes:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port),
        timeout=timeout,
    )
    try:
        writer.write(struct.pack("!H", len(data)) + data)
        await writer.drain()

        length_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        length = struct.unpack("!H", length_bytes)[0]
        resp = await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
        return resp
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# DNS-over-TLS connections are kept open and reused (RFC 7858 s3.4): a new
# TCP + TLS handshake per query costs several round trips. Servers close idle
# connections after a while, so one idle longer than this isn't reused.
_DOT_IDLE_SECONDS = 15.0
_DOT_MAX_IDLE_PER_UPSTREAM = 4
_dot_context: ssl.SSLContext | None = None


def _dot_ssl_context() -> ssl.SSLContext:
    # Loading the CA store is slow; one context serves every connection.
    global _dot_context
    if _dot_context is None:
        _dot_context = ssl.create_default_context()
    return _dot_context


async def forward_dot(data: bytes, hostport: str, timeout: float) -> bytes:
    host, port = _split_host_port(hostport, 853)

    raw_sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock = _dot_ssl_context().wrap_socket(raw_sock, server_hostname=host)
    except BaseException:
        raw_sock.close()
        raise
    try:
        sock.settimeout(timeout)
        sock.sendall(struct.pack("!H", len(data)) + data)
        length = struct.unpack("!H", _recv_exact(sock, 2))[0]
        resp = _recv_exact(sock, length)
        if resp[:2] != data[:2]:
            raise ConnectionError("DoT response for a different query")
        return resp
    except BaseException:
        sock.close()
        raise


async def forward_doh(data: bytes, url: str, timeout: float) -> bytes:
    session = _get_doh_session()
    resp = await session.post(
        url,
        data=data,
        headers={"Content-Type": DOH_CONTENT_TYPE, "Accept": DOH_CONTENT_TYPE},
        timeout=aiohttp.ClientTimeout(total=timeout),
    )
    resp.raise_for_status()
    return await resp.read()


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("upstream closed connection early")
        buf += chunk
    return buf


def is_disabled(entry: str) -> bool:
    return entry.strip().startswith("#")


def address(entry: str) -> str:
    return entry.strip().lstrip("#").strip()


def hostname_of(upstream: str) -> str | None:
    entry = address(upstream)
    for prefix in ("dot://", "doh://", "https://", *DOQ_PREFIXES):
        if entry.startswith(prefix):
            entry = entry[len(prefix) :]
            break
    entry = entry.split("/", 1)[0]

    host, _port = _split_host_port(entry, 0)
    host = host.lower()
    if not host:
        return None

    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        return host


_PROTECTED_CACHE: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


def matches_domain_or_parent(qname: str, names: AbstractSet[str]) -> bool:
    """True if qname or any parent domain of it is in names: a few set
    lookups (one per label) instead of a suffix test against every name."""
    while True:
        if qname in names:
            return True
        dot = qname.find(".")
        if dot < 0:
            return False
        qname = qname[dot + 1 :]


def protected_hostnames(config_store) -> frozenset[str]:
    """Hostnames DNS-shield itself must always be able to resolve (upstreams,
    blocklist hosts, threat-intel services). Asked on every query, so it's
    worked out once per config version."""
    version = getattr(config_store, "version", None)
    if version is not None:
        try:
            cached = _PROTECTED_CACHE.get(config_store)
        except TypeError:
            cached = None
        if cached is not None and cached[0] == version:
            return cached[1]
    result = frozenset(_collect_protected_hostnames(config_store))
    if version is not None:
        try:
            _PROTECTED_CACHE[config_store] = (version, result)
        except TypeError:
            pass
    return result


def _collect_protected_hostnames(config_store) -> set[str]:
    hostnames: set[str] = set()

    if config_store.get("enrichment", "public_enabled", default=False):
        hostnames |= THREAT_INTEL_HOSTNAMES

    if config_store.get("enrichment", "local_enabled", default=False):
        local_url = config_store.get("enrichment", "local_url", default="") or ""
        local_host = urlparse(local_url).hostname if local_url else None
        if local_host:
            hostnames.add(local_host.lower())

    def _collect_upstreams(entries) -> None:
        for entry in entries or []:
            host = hostname_of(entry)
            if host:
                hostnames.add(host)

    _collect_upstreams(config_store.get("dns", "upstreams", default=[]))
    for rule in config_store.get("domain_upstreams", default=[]) or []:
        _collect_upstreams(rule.get("upstreams"))
    for group in config_store.get("client_groups", default=[]) or []:
        _collect_upstreams(group.get("upstreams"))

    def _collect_source_urls(sources) -> None:
        for source in sources or []:
            url = source.get("url") if isinstance(source, dict) else None
            if not url:
                continue
            host = urlparse(url).hostname
            if host:
                hostnames.add(host.lower())

    _collect_source_urls(config_store.get("blocklists", "sources", default=[]))
    _collect_source_urls(config_store.get("blocklists", "allow_sources", default=[]))

    return hostnames
