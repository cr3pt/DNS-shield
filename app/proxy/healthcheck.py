from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from typing import Any
from urllib.parse import urlparse

from dnslib import QTYPE, DNSRecord

from app import upstream as upstream_transport

_TIMEOUT = 4.0


def resolve_address(hostname: str, resolver: str | None = None) -> str | None:
    if resolver:
        for qtype in ("A", "AAAA"):
            try:
                query = DNSRecord.question(hostname, qtype)
                data = upstream_transport.forward(query.pack(), resolver, _TIMEOUT)
                reply = DNSRecord.parse(data)
                for rr in reply.rr:
                    if QTYPE[rr.rtype] == qtype:
                        return str(rr.rdata)
            except Exception:
                continue
        return None
    try:
        infos = socket.getaddrinfo(hostname, None)
        return infos[0][4][0] if infos else None
    except OSError:
        return None


def _check_http(address: str, hostname: str, port: int, use_https: bool) -> bool:
    conn: http.client.HTTPConnection | None = None
    try:
        if use_https:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(address, port, timeout=_TIMEOUT, context=context)
        else:
            conn = http.client.HTTPConnection(address, port, timeout=_TIMEOUT)
        conn.request("HEAD", "/", headers={"Host": hostname})
        resp = conn.getresponse()
        resp.read()
        return True
    except Exception:
        return False
    finally:
        if conn is not None:
            conn.close()


def check_hostname_reachable(hostname: str, use_https: bool, resolver: str | None = None) -> bool:
    address = resolve_address(hostname, resolver)
    if not address:
        return False
    return _check_http(address, hostname, 443 if use_https else 80, use_https)


def check_domain_reachable(hostnames: list[str], use_https: bool, resolver: str | None = None) -> bool:
    return any(check_hostname_reachable(h, use_https, resolver) for h in hostnames)


def check_url_reachable(url: str, resolver: str | None = None) -> bool | None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None

    use_https = parsed.scheme == "https"
    port = parsed.port or (443 if use_https else 80)
    hostname = parsed.hostname

    try:
        ipaddress.ip_address(hostname)
        address = hostname
    except ValueError:
        address = resolve_address(hostname, resolver)
        if not address:
            return False
    return _check_http(address, hostname, port, use_https)


def check_target_reachable(rules: list[dict[str, Any]], resolver: str | None = None) -> dict[str, Any]:
    urls = [r.get("target") if r.get("type") == "redirect" else r.get("upstream") for r in rules or []]
    urls = [u for u in urls if u]
    results = [check_url_reachable(u, resolver) for u in urls]
    checkable = [r for r in results if r is not None]
    if not checkable:
        return {"reachable": False, "checked": False}
    return {"reachable": any(checkable), "checked": True}
