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

import socket
import ssl
import struct

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
