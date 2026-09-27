from __future__ import annotations

import ipaddress
import socket
import threading
from contextlib import contextmanager
from urllib.parse import urlparse


def _is_unsafe_address(address: str) -> bool:
    try:
        addr = ipaddress.ip_address(address)
    except ValueError:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def check_public_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL must be http:// or https://")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL has no hostname")

    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError as exc:
        raise ValueError(f"could not resolve hostname {hostname!r}: {exc}") from None

    resolved = {info[4][0] for info in infos}
    unsafe = [addr for addr in resolved if _is_unsafe_address(addr)]
    if unsafe:
        raise ValueError(
            f"{hostname!r} resolves to a private/loopback/link-local address ({', '.join(sorted(unsafe))}) - "
            "refusing to fetch it to prevent server-side request forgery (SSRF)"
        )


_real_getaddrinfo = socket.getaddrinfo
_guard_state = threading.local()


def _guarded_getaddrinfo(host, *args, **kwargs):
    infos = _real_getaddrinfo(host, *args, **kwargs)
    guarded_hosts = getattr(_guard_state, "hosts", None)
    if guarded_hosts and host in guarded_hosts:
        safe = [info for info in infos if not _is_unsafe_address(info[4][0])]
        if not safe:
            raise socket.gaierror(
                f"{host!r} resolves only to private/loopback/link-local addresses - "
                "refusing to connect (SSRF guard)"
            )
        return safe
    return infos


socket.getaddrinfo = _guarded_getaddrinfo


@contextmanager
def public_dns_guard(url: str):
    hostname = urlparse(url).hostname
    guarded_hosts = getattr(_guard_state, "hosts", None)
    if guarded_hosts is None:
        guarded_hosts = set()
        _guard_state.hosts = guarded_hosts
    guarded_hosts.add(hostname)
    try:
        yield
    finally:
        guarded_hosts.discard(hostname)
