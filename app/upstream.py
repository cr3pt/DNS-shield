from __future__ import annotations

import ipaddress
import socket
import ssl
import struct
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

from app.enrichment import THREAT_INTEL_HOSTNAMES

DOH_CONTENT_TYPE = "application/dns-message"

_doh_session = requests.Session()
_doh_adapter = HTTPAdapter(pool_connections=20, pool_maxsize=100)
_doh_session.mount("https://", _doh_adapter)
_doh_session.mount("http://", _doh_adapter)


def _split_host_port(entry: str, default_port: int) -> tuple[str, int]:
    """Split a "host[:port]" upstream entry into (host, port).

    A plain colon-split breaks on IPv6 literals, which contain colons
    themselves - "2606:4700:4700::1111:53" is ambiguous between "port 53 on
    that /64" and "no port on ...::1111:53". Bracket notation ([addr]:port,
    the same convention curl/browsers use) resolves that; a bare IPv6
    literal without brackets is accepted too, just without a custom port,
    since there'd be no way to tell where the address ends.

    A non-numeric port falls back to default_port rather than raising -
    this runs on every single DNS query via hostname_of()/block_reason(),
    unguarded by a try/except unlike the actual forward() call sites, so a
    typo in a hand-edited upstream entry must never be able to take down
    resolution for every query.
    """
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


def forward(data: bytes, upstream: str, timeout: float) -> bytes:
    if upstream.startswith("dot://"):
        return _forward_dot(data, upstream[len("dot://") :], timeout)
    if upstream.startswith("doh://"):
        return _forward_doh(data, "https://" + upstream[len("doh://") :], timeout)
    if upstream.startswith("https://"):
        return _forward_doh(data, upstream, timeout)
    return _forward_plain(data, upstream, timeout)


def _forward_plain(data: bytes, upstream: str, timeout: float) -> bytes:
    host, port = _split_host_port(upstream, 53)
    # _split_host_port() never returns a colon in a hostname or IPv4 host -
    # a colon here means this really is an IPv6 literal, which needs AF_INET6
    # (an AF_INET socket can't send to one at all).
    family = socket.AF_INET6 if ":" in host else socket.AF_INET

    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(data, (host, port))
        resp, _ = sock.recvfrom(65535)

    if len(resp) >= 3 and resp[2] & 0x02:
        return _forward_tcp(data, host, port, timeout)
    return resp


def _forward_tcp(data: bytes, host: str, port: int, timeout: float) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(struct.pack("!H", len(data)) + data)
        length = struct.unpack("!H", _recv_exact(sock, 2))[0]
        return _recv_exact(sock, length)


def _forward_dot(data: bytes, hostport: str, timeout: float) -> bytes:
    host, port = _split_host_port(hostport, 853)

    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=host) as sock:
            sock.sendall(struct.pack("!H", len(data)) + data)
            length = struct.unpack("!H", _recv_exact(sock, 2))[0]
            return _recv_exact(sock, length)


def _forward_doh(data: bytes, url: str, timeout: float) -> bytes:
    resp = _doh_session.post(
        url,
        data=data,
        headers={"Content-Type": DOH_CONTENT_TYPE, "Accept": DOH_CONTENT_TYPE},
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.content


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
    for prefix in ("dot://", "doh://", "https://"):
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


def protected_hostnames(config_store) -> set[str]:
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
