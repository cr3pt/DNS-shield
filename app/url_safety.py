# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

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


def check_public_url(url: str, resolver=None) -> list[str]:
    """Raise ValueError unless url is http(s) to a host whose every address
    is public. Returns the addresses checked.

    resolver(hostname) -> list[str] | None, if given, is asked first (e.g.
    the upstreams directly, bypassing DNS-shield's own filtering); None from
    it falls back to the system resolver. Either way every address goes
    through the same check."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL must be http:// or https://")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL has no hostname")

    resolved: list[str] = []
    via = "the system resolver"
    if resolver is not None:
        try:
            answer = resolver(hostname)
        except Exception:
            answer = None
        if answer:
            resolved = list(dict.fromkeys(answer))
            via = "the upstream DNS servers"
    if not resolved:
        try:
            infos = socket.getaddrinfo(hostname, None)
        except OSError as exc:
            raise ValueError(f"could not resolve hostname {hostname!r}: {exc}") from None
        resolved = list(dict.fromkeys(info[4][0] for info in infos))

    unsafe = [addr for addr in resolved if _is_unsafe_address(addr)]
    if unsafe:
        raise ValueError(
            f"{hostname!r} resolves to a private/loopback/link-local address ({', '.join(sorted(unsafe))}) "
            f"according to {via} - refusing to fetch it to prevent server-side request forgery (SSRF)"
        )
    return resolved


_real_getaddrinfo = socket.getaddrinfo
_guard_state = threading.local()


def _guarded_getaddrinfo(host, *args, **kwargs):
    pinned = getattr(_guard_state, "pinned", None)
    addresses = pinned.get(host) if pinned else None
    if addresses:
        # Connect to the addresses check_public_url() vetted, not to whatever
        # a fresh system lookup says (which may be DNS-shield's own filtered
        # answer). Numeric hosts: no DNS query happens here.
        infos = []
        for addr in addresses:
            try:
                infos.extend(_real_getaddrinfo(addr, *args, **kwargs))
            except OSError:
                continue
        if not infos:
            raise socket.gaierror(f"{host!r}: none of the pinned addresses is usable")
    else:
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
def public_dns_guard(url: str, addresses: list[str] | None = None):
    """Within the block, connections to url's host only go to public
    addresses (re-checked at connect time, closing the DNS-rebinding gap).
    With addresses, the host is also pinned to them - e.g. the ones
    check_public_url() got from the upstreams."""
    hostname = urlparse(url).hostname
    guarded_hosts = getattr(_guard_state, "hosts", None)
    if guarded_hosts is None:
        guarded_hosts = set()
        _guard_state.hosts = guarded_hosts
    pinned = getattr(_guard_state, "pinned", None)
    if pinned is None:
        pinned = {}
        _guard_state.pinned = pinned
    guarded_hosts.add(hostname)
    previous = pinned.get(hostname)
    if addresses:
        pinned[hostname] = [a for a in addresses if not _is_unsafe_address(a)]
    try:
        yield
    finally:
        guarded_hosts.discard(hostname)
        if previous is None:
            pinned.pop(hostname, None)
        else:
            pinned[hostname] = previous


def upstream_resolver(config_store):
    """A resolver for check_public_url() that asks DNS-shield's upstreams
    directly (see app.upstream.resolve_direct)."""
    from app.upstream import resolve_direct

    def resolve(hostname: str) -> list[str] | None:
        return resolve_direct(hostname, config_store)

    return resolve
