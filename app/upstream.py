# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import ipaddress
import secrets
import socket
import ssl
import struct
import time
from urllib.parse import urlparse

import requests
from dnslib import DNSRecord
from requests.adapters import HTTPAdapter

from app.enrichment import THREAT_INTEL_HOSTNAMES

DOH_CONTENT_TYPE = "application/dns-message"

_doh_session = requests.Session()
_doh_adapter = HTTPAdapter(pool_connections=20, pool_maxsize=100)
_doh_session.mount("https://", _doh_adapter)
_doh_session.mount("http://", _doh_adapter)


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


def forward(data: bytes, upstream: str, timeout: float) -> bytes:
    if upstream.startswith("dot://"):
        return _forward_dot(data, upstream[len("dot://") :], timeout)
    if upstream.startswith("doh://"):
        return _forward_doh(data, "https://" + upstream[len("doh://") :], timeout)
    if upstream.startswith("https://"):
        return _forward_doh(data, upstream, timeout)
    return _forward_plain(data, upstream, timeout)


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


def _forward_plain(data: bytes, upstream: str, timeout: float) -> bytes:
    host, port = _split_host_port(upstream, 53)
    family = socket.AF_INET6 if ":" in host else socket.AF_INET

    # A fresh random transaction ID per upstream query, independent of the
    # client's ID, so an off-path attacker has to guess both it and the
    # source port. The client's ID is put back on the way out.
    original_id = data[:2]
    query = secrets.token_bytes(2) + data[2:]
    deadline = time.monotonic() + timeout

    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        # connect() makes the kernel drop datagrams from any other address/port.
        sock.connect((host, port))
        sock.send(query)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout(f"no matching response from {upstream}")
            sock.settimeout(remaining)
            resp = sock.recv(65535)
            verdict = _check_response(query, resp)
            if verdict == "ok":
                break
            if verdict == "case":
                # The upstream doesn't echo the randomized case - fall back to
                # TCP, which isn't open to blind spoofing anyway.
                return _forward_tcp(data, host, port, max(0.1, deadline - time.monotonic()))
            # Spoofed, stale or malformed packet: ignore it and keep waiting.

    if len(resp) >= 3 and resp[2] & 0x02:
        return _forward_tcp(data, host, port, timeout)
    return original_id + resp[2:]


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
