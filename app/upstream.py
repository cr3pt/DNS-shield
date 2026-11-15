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
import threading
import time
import weakref
from collections.abc import Set as AbstractSet
from urllib.parse import urlparse

import aiohttp
from aiohttp.abc import AbstractResolver
from dnslib import DNSRecord

from app import bootstrap
from app.enrichment import THREAT_INTEL_HOSTNAMES

DOH_CONTENT_TYPE = "application/dns-message"

# The resolver (app/dns_server.py) calls forward() from plain worker threads,
# while the transports below are coroutines. One shared event loop runs in a
# daemon thread; forward() hands work to it when the caller isn't already
# inside a running loop.
_bg_loop: asyncio.AbstractEventLoop | None = None
_bg_loop_lock = threading.Lock()


def _background_loop() -> asyncio.AbstractEventLoop:
    global _bg_loop
    with _bg_loop_lock:
        if _bg_loop is None or _bg_loop.is_closed() or not _bg_loop.is_running():
            loop = asyncio.new_event_loop()
            started = threading.Event()

            def _run() -> None:
                asyncio.set_event_loop(loop)
                loop.call_soon(started.set)
                loop.run_forever()

            threading.Thread(target=_run, name="dnsshield-upstream-loop", daemon=True).start()
            started.wait(5)
            _bg_loop = loop
        return _bg_loop


# TTL cache for forward_plain: keyed by (hash of the question without the
# transaction ID, upstream). A threading lock is used because the critical
# sections never await and callers may run on different event loops.
_cache: dict[tuple[str, str], tuple[bytes, float]] = {}
_cache_lock = threading.Lock()
_CACHE_TTL_SECONDS = 60.0
_CACHE_MAX_ENTRIES = 4096


def _query_hash(query: bytes) -> str:
    """Deterministic hash of a DNS query for cache keying (transaction ID excluded)."""
    return hashlib.sha256(query[2:]).hexdigest()


def _cacheable(resp: bytes) -> bool:
    # Only NOERROR / NXDOMAIN, and never a truncated answer.
    return len(resp) >= 12 and not resp[2] & 0x02 and (resp[3] & 0x0F) in (0, 3)


def _cache_prune(now: float) -> None:
    for key in [k for k, (_, expires) in _cache.items() if expires <= now]:
        del _cache[key]
    while len(_cache) >= _CACHE_MAX_ENTRIES:
        _cache.pop(next(iter(_cache)))


async def _forward_plain_cached(
    data: bytes,
    upstream: str,
    timeout: float,
) -> bytes:
    """Cache wrapper around forward_plain with TTL expiration."""
    key = (_query_hash(data), upstream)
    with _cache_lock:
        entry = _cache.get(key)
        if entry is not None and time.monotonic() < entry[1]:
            return data[:2] + entry[0][2:]
    resp = await forward_plain(data, upstream, timeout)
    if _cacheable(resp):
        now = time.monotonic()
        with _cache_lock:
            _cache_prune(now)
            _cache[key] = (resp, now + _CACHE_TTL_SECONDS)
    return resp


class _BootstrapResolver(AbstractResolver):
    """aiohttp resolver that falls back to the bootstrap servers (app/bootstrap.py)
    when the system resolver can't answer for a DoH upstream's hostname."""

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_UNSPEC) -> list[dict]:
        infos = await bootstrap.getaddrinfo(host, port or 443, type=socket.SOCK_STREAM)
        return [
            {
                "hostname": host,
                "host": sockaddr[0],
                "port": port,
                "family": found_family,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST | socket.AI_NUMERICSERV,
            }
            for found_family, _type, _proto, _name, sockaddr in infos
            if family in (socket.AF_UNSPEC, found_family)
        ]

    async def close(self) -> None:
        pass


# DNS-over-HTTPS sessions, one per event loop (an aiohttp session is bound to
# the loop it was created in).
_doh_sessions: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


def _get_doh_session() -> aiohttp.ClientSession:
    loop = asyncio.get_running_loop()
    session = _doh_sessions.get(loop)
    if session is None or session.closed:
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=20,
            enable_cleanup_closed=True,
            resolver=_BootstrapResolver(),
        )
        session = aiohttp.ClientSession(connector=connector)
        _doh_sessions[loop] = session
    return session


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


async def aforward(data: bytes, upstream: str, timeout: float) -> bytes:
    """Coroutine form of forward(): send one query to one upstream."""
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


def forward(data: bytes, upstream: str, timeout: float):
    """Send one query to one upstream.

    From a plain thread (the resolver's workers) this blocks and returns the
    response bytes. From inside a running event loop it returns a coroutine to
    await, so both kinds of caller work.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        future = asyncio.run_coroutine_threadsafe(aforward(data, upstream, timeout), _background_loop())
        try:
            return future.result(timeout + 2.0)
        except BaseException:
            future.cancel()
            raise
    return aforward(data, upstream, timeout)


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
        if verdict in ("ok", "case"):
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
    except asyncio.TimeoutError:  # noqa: UP041 - a distinct class before Python 3.11
        raise TimeoutError(f"no matching response from {upstream}") from None
    finally:
        transport.close()

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


# DNS-over-TLS (RFC 7858). Connections are kept open and reused (s3.4): a new
# TCP + TLS handshake per query costs several round trips. Servers close idle
# connections after a while, so one idle longer than _DOT_IDLE_SECONDS isn't
# reused. A connection is taken out of the pool while a query is on it, so
# concurrent queries use separate connections. Streams belong to the event
# loop that opened them, hence the loop id in the pool key.
_DOT_IDLE_SECONDS = 15.0
_DOT_MAX_IDLE_PER_UPSTREAM = 4
_dot_idle: dict[tuple[str, int, int], list[tuple[asyncio.StreamReader, asyncio.StreamWriter, float]]] = {}
_dot_context: ssl.SSLContext | None = None


def _dot_ssl_context() -> ssl.SSLContext:
    # Loading the CA store is slow; one context serves every connection.
    global _dot_context
    if _dot_context is None:
        _dot_context = ssl.create_default_context()
    return _dot_context


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass


async def _dot_take(key: tuple[str, int, int]):
    pool = _dot_idle.get(key)
    while pool:
        reader, writer, last_used = pool.pop()
        if time.monotonic() - last_used >= _DOT_IDLE_SECONDS or writer.is_closing() or reader.at_eof():
            await _close_writer(writer)
            continue
        return reader, writer
    return None


async def _dot_give(key: tuple[str, int, int], reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    pool = _dot_idle.setdefault(key, [])
    pool.append((reader, writer, time.monotonic()))
    while len(pool) > _DOT_MAX_IDLE_PER_UPSTREAM:
        _, oldest, _ = pool.pop(0)
        await _close_writer(oldest)


async def _dot_exchange(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, data: bytes, timeout: float) -> bytes:
    writer.write(struct.pack("!H", len(data)) + data)
    await asyncio.wait_for(writer.drain(), timeout=timeout)
    length = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), timeout=timeout))[0]
    resp = await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
    if resp[:2] != data[:2]:
        raise ConnectionError("DoT response for a different query")
    return resp


async def _dot_connect(host: str, port: int, timeout: float):
    """Open a TLS connection to a DoT upstream. The name is resolved by the
    system resolver, or by the bootstrap servers when that can't answer; the
    certificate is checked against the hostname either way."""
    infos = await bootstrap.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    last_error: Exception | None = None
    for _family, _type, _proto, _name, sockaddr in infos[:4]:
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(sockaddr[0], port, ssl=_dot_ssl_context(), server_hostname=host),
                timeout=timeout,
            )
        except (OSError, TimeoutError) as exc:
            last_error = exc
    raise last_error if last_error is not None else OSError(f"no address for {host}")


async def forward_dot(data: bytes, hostport: str, timeout: float) -> bytes:
    host, port = _split_host_port(hostport, 853)
    key = (host, port, id(asyncio.get_running_loop()))

    # A pooled connection may have been closed by the server in the meantime;
    # if the query fails on one, try again once on a fresh connection.
    pooled = await _dot_take(key)
    if pooled is not None:
        reader, writer = pooled
        try:
            resp = await _dot_exchange(reader, writer, data, timeout)
        except Exception:
            await _close_writer(writer)
        else:
            await _dot_give(key, reader, writer)
            return resp

    reader, writer = await _dot_connect(host, port, timeout)
    try:
        resp = await _dot_exchange(reader, writer, data, timeout)
    except BaseException:
        await _close_writer(writer)
        raise
    await _dot_give(key, reader, writer)
    return resp


async def forward_doh(data: bytes, url: str, timeout: float) -> bytes:
    session = _get_doh_session()
    async with session.post(
        url,
        data=data,
        headers={"Content-Type": DOH_CONTENT_TYPE, "Accept": DOH_CONTENT_TYPE},
        timeout=aiohttp.ClientTimeout(total=timeout),
    ) as resp:
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
