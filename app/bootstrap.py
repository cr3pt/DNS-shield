# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Finding the address of an encrypted upstream (DoQ) by name.

The system resolver is tried first. Where it can't answer - typically because
it points at DNS-shield itself (which needs this very upstream to answer
anything) or at a Docker-internal forwarder that is gone - the name is looked
up with plain DNS over UDP on a bootstrap server instead. Only the hostname of
the upstream is sent there; the queries DNS-shield answers never are.

Bootstrap servers: DNSSHIELD_BOOTSTRAP (comma separated, "ip" or "ip:port"),
default 1.1.1.1 and 9.9.9.9."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import secrets
import socket
import struct
import time

logger = logging.getLogger("dnsshield.bootstrap")

DEFAULT_SERVERS = ("1.1.1.1", "9.9.9.9")
_SYSTEM_TIMEOUT = 3.0
_QUERY_TIMEOUT = 2.0
_CACHE_SECONDS = 300.0
_TYPE_A, _TYPE_AAAA = 1, 28

_cache: dict[tuple[str, int, int], tuple[float, list]] = {}


def bootstrap_servers() -> list[tuple[str, int]]:
    raw = os.environ.get("DNSSHIELD_BOOTSTRAP", "")
    entries = [e.strip() for e in raw.split(",") if e.strip()] or list(DEFAULT_SERVERS)
    servers = []
    for entry in entries:
        host, port = entry, 53
        if entry.count(":") == 1:
            host, _, port_text = entry.partition(":")
            port = int(port_text) if port_text.isdigit() else 53
        servers.append((host, port))
    return servers


def _encode_query(host: str, qtype: int) -> bytes:
    name = b"".join(bytes([len(p)]) + p.encode("idna") for p in host.rstrip(".").split(".")) + b"\0"
    return secrets.token_bytes(2) + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", qtype, 1)


def _skip_name(packet: bytes, pos: int) -> int:
    while True:
        length = packet[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:
            return pos + 2
        pos += 1 + length


def _parse_addresses(query: bytes, packet: bytes, qtype: int) -> list[str]:
    if len(packet) < 12 or packet[:2] != query[:2] or not packet[2] & 0x80 or packet[3] & 0x0F:
        return []
    questions, answers = struct.unpack("!HH", packet[4:8])
    pos = 12
    for _ in range(questions):
        pos = _skip_name(packet, pos) + 4
    found = []
    for _ in range(answers):
        pos = _skip_name(packet, pos)
        rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", packet[pos : pos + 10])
        pos += 10
        rdata = packet[pos : pos + rdlength]
        pos += rdlength
        if rtype == qtype and qtype == _TYPE_A and rdlength == 4:
            found.append(socket.inet_ntop(socket.AF_INET, rdata))
        elif rtype == qtype and qtype == _TYPE_AAAA and rdlength == 16:
            found.append(socket.inet_ntop(socket.AF_INET6, rdata))
    return found


def _ask(server: tuple[str, int], host: str, qtype: int) -> list[str]:
    query = _encode_query(host, qtype)
    family = socket.AF_INET6 if ":" in server[0] else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(_QUERY_TIMEOUT)
        sock.sendto(query, server)
        while True:
            packet, _ = sock.recvfrom(4096)
            if packet[:2] == query[:2]:
                return _parse_addresses(query, packet, qtype)


def _lookup(host: str) -> list[str]:
    """IPv4 addresses first, then IPv6, from the first bootstrap server that answers."""
    last_error: Exception | None = None
    for server in bootstrap_servers():
        try:
            addresses = _ask(server, host, _TYPE_A)
            try:
                addresses += _ask(server, host, _TYPE_AAAA)
            except OSError:
                pass
        except OSError as exc:
            last_error = exc
            continue
        if addresses:
            return addresses
    raise OSError(f"bootstrap lookup of {host} failed" + (f": {last_error}" if last_error else ""))


def _entry(address: str, port: int, socktype: int):
    ip = ipaddress.ip_address(address)
    if ip.version == 6:
        return (socket.AF_INET6, socktype, 0, "", (address, port, 0, 0))
    return (socket.AF_INET, socktype, 0, "", (address, port))


async def getaddrinfo(host: str, port: int, type: int = socket.SOCK_DGRAM) -> list:  # noqa: A002
    """Like loop.getaddrinfo, with a bootstrap lookup as the fallback."""
    loop = asyncio.get_running_loop()
    try:
        ipaddress.ip_address(host)
        return await loop.getaddrinfo(host, port, type=type)
    except ValueError:
        pass
    key = (host.lower(), port, type)
    cached = _cache.get(key)
    if cached is not None and cached[0] > time.monotonic():
        return cached[1]
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, port, type=type), _SYSTEM_TIMEOUT)
    except (OSError, TimeoutError) as system_error:
        logger.info("system resolver can't resolve %s (%s) - asking the bootstrap servers", host, system_error)
        try:
            addresses = await loop.run_in_executor(None, _lookup, host)
        except OSError as bootstrap_error:
            raise system_error if isinstance(system_error, OSError) else bootstrap_error from None
        infos = [_entry(address, port, type) for address in addresses]
    _cache[key] = (time.monotonic() + _CACHE_SECONDS, infos)
    return infos
