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

DOH_CONTENT_TYPE = "application/dns-message"


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
    resp = requests.post(
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
