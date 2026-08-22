from __future__ import annotations

import ipaddress


def ip_matches(client_ip: str, pattern: str) -> bool:
    try:
        if "/" in pattern:
            return ipaddress.ip_address(client_ip) in ipaddress.ip_network(pattern, strict=False)
        return ipaddress.ip_address(client_ip) == ipaddress.ip_address(pattern)
    except ValueError:
        return client_ip == pattern
