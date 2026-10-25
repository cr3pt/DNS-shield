# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import ipaddress
import re


def ip_matches(client_ip: str, pattern: str) -> bool:
    try:
        if "/" in pattern:
            return ipaddress.ip_address(client_ip) in ipaddress.ip_network(pattern, strict=False)
        return ipaddress.ip_address(client_ip) == ipaddress.ip_address(pattern)
    except ValueError:
        return client_ip == pattern


def _mac_matches(mac: str | None, pattern_mac: str) -> bool:
    if not mac:
        return False
    return mac.strip().upper() == pattern_mac.strip().upper()


def _hostname_matches(hostname: str | None, pattern_host: str) -> bool:
    if not hostname:
        return False
    hostname = hostname.rstrip(".").lower()
    pattern_host = pattern_host.rstrip(".").lower()
    if pattern_host.startswith("*."):
        suffix = pattern_host[1:]
        return hostname.endswith(suffix)
    return hostname == pattern_host


def client_matches(client_ip: str, pattern: str, mac: str | None = None, hostname: str | None = None) -> bool:
    if pattern.lower().startswith("mac:"):
        return _mac_matches(mac, pattern[4:])
    if pattern.lower().startswith("host:"):
        return _hostname_matches(hostname, pattern[5:])
    return ip_matches(client_ip, pattern)


_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$")
_HOST_RE = re.compile(r"^(\*\.)?[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?$")
_MAX_PATTERN_LENGTH = 253


def normalize_client_pattern(raw: str) -> str:
    pattern = (raw or "").strip()
    if not pattern or len(pattern) > _MAX_PATTERN_LENGTH:
        raise ValueError("Empty or too long client pattern")
    lowered = pattern.lower()
    if lowered.startswith("mac:"):
        mac = pattern[4:].strip()
        if not _MAC_RE.match(mac):
            raise ValueError(f"Invalid MAC address in {pattern!r} (expected mac:AA:BB:CC:DD:EE:FF)")
        return "mac:" + mac.upper().replace("-", ":")
    if lowered.startswith("host:"):
        host = pattern[5:].strip().rstrip(".").lower()
        if not host or not _HOST_RE.match(host):
            raise ValueError(f"Invalid hostname in {pattern!r} (expected host:name or host:*.suffix)")
        return "host:" + host
    try:
        if "/" in pattern:
            ipaddress.ip_network(pattern, strict=False)
            return pattern
        return str(ipaddress.ip_address(pattern))
    except ValueError:
        raise ValueError(f"{pattern!r} is not an IP address, CIDR, mac:... or host:... pattern") from None


def normalize_client_patterns(raw: list[str]) -> list[str]:
    seen: list[str] = []
    for item in raw:
        normalized = normalize_client_pattern(item)
        if normalized not in seen:
            seen.append(normalized)
    return seen


def pattern_specificity(pattern: str) -> tuple[int, int]:
    lowered = pattern.lower()
    if lowered.startswith("mac:"):
        return (4, 0)
    if lowered.startswith("host:"):
        host = pattern[5:].strip().rstrip(".")
        if host.startswith("*."):
            return (2, len(host) - 2)
        return (3, 0)
    try:
        if "/" in pattern:
            network = ipaddress.ip_network(pattern, strict=False)
            if network.prefixlen == network.max_prefixlen:
                return (5, 0)
            return (1, network.prefixlen)
        ipaddress.ip_address(pattern)
        return (5, 0)
    except ValueError:
        return (3, 0)


def best_matching_group(
    groups: list[dict],
    client_ip: str,
    mac: str | None = None,
    hostname: str | None = None,
) -> dict | None:
    best: dict | None = None
    best_rank: tuple[int, int] | None = None
    for group in groups:
        for pattern in group.get("match", []) or []:
            if not client_matches(client_ip, pattern, mac=mac, hostname=hostname):
                continue
            rank = pattern_specificity(pattern)
            if best_rank is None or rank > best_rank:
                best, best_rank = group, rank
    return best
