"""Upstream DNS transports: plain UDP/TCP, DNS-over-TLS, DNS-over-HTTPS.

An `upstreams` entry in config.yaml is plain "host:port" (UDP, with an
automatic TCP retry if the reply is truncated) unless prefixed:

  - "dot://host"            or "dot://host:853"   -> DNS-over-TLS (RFC 7858)
  - "doh://host/path"       or a full "https://…"  -> DNS-over-HTTPS (RFC 8484)

DoT/DoH hide the *content* of queries from anything on the path between
this box and the upstream resolver (e.g. your ISP) - the upstream
operator itself can of course still see what you ask it, same as with
plain DNS. Both verify the upstream's TLS certificate by default.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import struct
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

DOH_CONTENT_TYPE = "application/dns-message"

# One shared, connection-pooling Session for all DoH upstreams, reused
# across every DNS query. requests.post() at module level (the original
# implementation here) opens a brand-new connection every single call and
# relies on the OS to eventually reclaim it (TCP TIME_WAIT can hold a
# closed socket's file descriptor for a minute or more) - under real,
# sustained query volume that exhausts the process's file descriptor
# limit ("Too many open files") long before the OS catches up. A shared
# Session's connection pool actually reuses the same open sockets instead.
# pool_maxsize is generous because dnslib handles each query in its own
# thread, so many DoH requests can be in flight at once.
_doh_session = requests.Session()
_doh_adapter = HTTPAdapter(pool_connections=20, pool_maxsize=100)
_doh_session.mount("https://", _doh_adapter)
_doh_session.mount("http://", _doh_adapter)


def forward(data: bytes, upstream: str, timeout: float) -> bytes:
    if upstream.startswith("dot://"):
        return _forward_dot(data, upstream[len("dot://") :], timeout)
    if upstream.startswith("doh://"):
        return _forward_doh(data, "https://" + upstream[len("doh://") :], timeout)
    if upstream.startswith("https://"):
        return _forward_doh(data, upstream, timeout)
    return _forward_plain(data, upstream, timeout)


def _forward_plain(data: bytes, upstream: str, timeout: float) -> bytes:
    host, _, port_str = upstream.partition(":")
    port = int(port_str) if port_str else 53

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(data, (host, port))
        resp, _ = sock.recvfrom(65535)

    if len(resp) >= 3 and resp[2] & 0x02:  # TC (truncated) bit set - retry over TCP
        return _forward_tcp(data, host, port, timeout)
    return resp


def _forward_tcp(data: bytes, host: str, port: int, timeout: float) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(struct.pack("!H", len(data)) + data)
        length = struct.unpack("!H", _recv_exact(sock, 2))[0]
        return _recv_exact(sock, length)


def _forward_dot(data: bytes, hostport: str, timeout: float) -> bytes:
    host, _, port_str = hostport.partition(":")
    port = int(port_str) if port_str else 853

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


def hostname_of(upstream: str) -> str | None:
    """The bare hostname an upstream spec needs DNS to resolve, or None
    if it's a literal IP (nothing to protect for those).
    """
    entry = upstream.strip()
    for prefix in ("dot://", "doh://", "https://"):
        if entry.startswith(prefix):
            entry = entry[len(prefix) :]
            break
    entry = entry.split("/", 1)[0]  # drop a DoH path, if any

    host = entry
    if entry.count(":") == 1:  # "host:port" - but not an IPv6 literal
        host, _, _port = entry.partition(":")
    host = host.lower()
    if not host:
        return None

    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        return host


def protected_hostnames(config_store) -> set[str]:
    """Hostnames DNS-shield must always be able to resolve to keep working
    at all: every configured upstream resolver (global, per-domain routing,
    per-client-group) and every blocklist/allow-list subscription URL.
    Blocking or hiding either would be self-defeating - a coincidental
    blocklist match on an upstream's hostname would cut DNS-shield off from
    that resolver, and one on a blocklist source's hostname would stop
    blocklists from ever refreshing.

    These are always exempt from blocking and excluded from the query log
    by default (it's DNS-shield's own background traffic, not something a
    user browsed to). Recomputed from the live config on every call, so it
    stays correct the moment upstreams or list sources change - there is
    nothing to configure separately.
    """
    hostnames: set[str] = set()

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
