from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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
    # Connects to the resolved address but always presents `hostname` for TLS SNI
    # and the Host header - conflating the two (e.g. passing `address` as both the
    # connection target and the SNI/Host value) breaks any site that relies on
    # name-based virtual hosting, which is most HTTPS hosting today (CDNs, shared
    # certs, etc.) - it would present the IP as SNI and get the wrong vhost/cert.
    conn: http.client.HTTPConnection | None = None
    try:
        sock = socket.create_connection((address, port), timeout=_TIMEOUT)
        if use_https:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=hostname)
        conn = http.client.HTTPConnection(hostname, port, timeout=_TIMEOUT)
        conn.sock = sock
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
    hostnames = [h for h in hostnames or [] if h]
    if not hostnames:
        return False
    # Checked concurrently (one hostname timing out shouldn't make the others
    # wait their turn) and returns as soon as any one succeeds, without waiting
    # for slower stragglers still in flight.
    executor = ThreadPoolExecutor(max_workers=min(8, len(hostnames)))
    try:
        futures = [executor.submit(check_hostname_reachable, h, use_https, resolver) for h in hostnames]
        for future in as_completed(futures):
            if future.result():
                return True
        return False
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


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
    if not urls:
        return {"reachable": False, "checked": False}
    with ThreadPoolExecutor(max_workers=min(8, len(urls))) as executor:
        results = list(executor.map(lambda u: check_url_reachable(u, resolver), urls))
    checkable = [r for r in results if r is not None]
    if not checkable:
        return {"reachable": False, "checked": False}
    return {"reachable": any(checkable), "checked": True}


def check_domain_health(
    hostnames: list[str], rules: list[dict[str, Any]], use_https: bool, resolver: str | None = None
) -> dict[str, Any]:
    with ThreadPoolExecutor(max_workers=2) as executor:
        domain_future = executor.submit(check_domain_reachable, hostnames, use_https, resolver)
        target_future = executor.submit(check_target_reachable, rules, resolver)
        domain_reachable = domain_future.result()
        target = target_future.result()
    return {
        "domain_reachable": domain_reachable,
        "target_reachable": target["reachable"],
        "target_checked": target["checked"],
        "checked_at": time.time(),
    }
