# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import ipaddress


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
