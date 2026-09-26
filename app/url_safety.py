from __future__ import annotations

import ipaddress
import socket
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
