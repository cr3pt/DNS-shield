from __future__ import annotations

import ipaddress
from typing import Any

from app.dhcp import protocol as proto

CUSTOM_OPTION_ENCODERS = {
    "ip": lambda v: ipaddress.IPv4Address(v).packed,
    "ip_list": lambda v: proto.encode_ipv4_list(v if isinstance(v, list) else [v]),
    "string": lambda v: str(v).encode("ascii", errors="ignore"),
    "uint32": lambda v: proto.encode_uint32(int(v)),
    "hex": lambda v: bytes.fromhex(str(v).replace(":", "").replace(" ", "")),
}


def find_reservation(scope: dict[str, Any], mac: str) -> dict[str, Any] | None:
    mac = mac.upper()
    for reservation in scope.get("reservations", []) or []:
        if str(reservation.get("mac", "")).upper() == mac:
            return reservation
    return None


def build_reply_options(
    scope: dict[str, Any],
    reservation: dict[str, Any] | None,
    server_ip: str,
    lease_seconds: float,
) -> dict[int, bytes]:
    options: dict[int, bytes] = {}

    network = ipaddress.ip_network(scope["network"], strict=False)
    options[proto.OPT_SUBNET_MASK] = network.netmask.packed
    options[proto.OPT_SERVER_IDENTIFIER] = ipaddress.IPv4Address(server_ip).packed
    options[proto.OPT_LEASE_TIME] = proto.encode_uint32(lease_seconds)
    options[proto.OPT_RENEWAL_TIME] = proto.encode_uint32(int(lease_seconds * 0.5))
    options[proto.OPT_REBINDING_TIME] = proto.encode_uint32(int(lease_seconds * 0.875))
    options[proto.OPT_BROADCAST_ADDRESS] = network.broadcast_address.packed

    gateway = scope.get("gateway") or ""
    if gateway:
        options[proto.OPT_ROUTER] = proto.encode_ipv4_list([gateway])

    dns_servers = (reservation or {}).get("dns_servers") or scope.get("dns_servers") or [server_ip]
    options[proto.OPT_DNS_SERVERS] = proto.encode_ipv4_list(dns_servers)

    domain_name = scope.get("domain_name") or ""
    if domain_name:
        options[proto.OPT_DOMAIN_NAME] = domain_name.encode("ascii", errors="ignore")

    ntp_servers = scope.get("ntp_servers") or []
    if ntp_servers:
        options[proto.OPT_NTP_SERVERS] = proto.encode_ipv4_list(ntp_servers)

    wins_servers = scope.get("wins_servers") or []
    if wins_servers:
        options[proto.OPT_NETBIOS_NAME_SERVERS] = proto.encode_ipv4_list(wins_servers)

    mtu = scope.get("mtu")
    if mtu:
        options[proto.OPT_INTERFACE_MTU] = proto.encode_uint16(int(mtu))

    tftp_server = scope.get("tftp_server") or ""
    if tftp_server:
        options[proto.OPT_TFTP_SERVER_NAME] = tftp_server.encode("ascii", errors="ignore")

    bootfile_name = scope.get("bootfile_name") or ""
    if bootfile_name:
        options[proto.OPT_BOOTFILE_NAME] = bootfile_name.encode("ascii", errors="ignore")

    static_routes = scope.get("static_routes") or []
    if static_routes:
        routes = [(r["network"], int(r["prefix_len"]), r["gateway"]) for r in static_routes]
        options[proto.OPT_CLASSLESS_STATIC_ROUTES] = proto.encode_classless_routes(routes)

    for custom in (reservation or {}).get("custom_options", []) or []:
        _apply_custom_option(options, custom)
    for custom in scope.get("custom_options", []) or []:
        _apply_custom_option(options, custom)

    return options


def _apply_custom_option(options: dict[int, bytes], custom: dict[str, Any]) -> None:
    try:
        code = int(custom["code"])
        encoder = CUSTOM_OPTION_ENCODERS[custom.get("type", "string")]
        options[code] = encoder(custom["value"])
    except (KeyError, ValueError, TypeError):
        return
