from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field

MAGIC_COOKIE = bytes((99, 130, 83, 99))

BOOTREQUEST = 1
BOOTREPLY = 2

DISCOVER = 1
OFFER = 2
REQUEST = 3
DECLINE = 4
ACK = 5
NAK = 6
RELEASE = 7
INFORM = 8

MESSAGE_TYPE_NAMES = {
    DISCOVER: "DISCOVER",
    OFFER: "OFFER",
    REQUEST: "REQUEST",
    DECLINE: "DECLINE",
    ACK: "ACK",
    NAK: "NAK",
    RELEASE: "RELEASE",
    INFORM: "INFORM",
}

OPT_SUBNET_MASK = 1
OPT_ROUTER = 3
OPT_DNS_SERVERS = 6
OPT_HOSTNAME = 12
OPT_DOMAIN_NAME = 15
OPT_BROADCAST_ADDRESS = 28
OPT_NTP_SERVERS = 42
OPT_NETBIOS_NAME_SERVERS = 44
OPT_REQUESTED_IP = 50
OPT_LEASE_TIME = 51
OPT_MESSAGE_TYPE = 53
OPT_SERVER_IDENTIFIER = 54
OPT_PARAMETER_REQUEST_LIST = 55
OPT_MESSAGE = 56
OPT_MAX_MESSAGE_SIZE = 57
OPT_RENEWAL_TIME = 58
OPT_REBINDING_TIME = 59
OPT_CLIENT_IDENTIFIER = 61
OPT_TFTP_SERVER_NAME = 66
OPT_BOOTFILE_NAME = 67
OPT_INTERFACE_MTU = 26
OPT_CLASSLESS_STATIC_ROUTES = 121
OPT_END = 255
OPT_PAD = 0

FLAG_BROADCAST = 0x8000


def format_mac(chaddr: bytes, hlen: int) -> str:
    return ":".join(f"{b:02x}" for b in chaddr[: hlen or 6]).upper()


def parse_mac(mac: str) -> bytes:
    return bytes(int(part, 16) for part in mac.split(":"))


def encode_ipv4_list(addresses: list[str]) -> bytes:
    out = b""
    for addr in addresses:
        out += ipaddress.IPv4Address(addr).packed
    return out


def decode_ipv4_list(data: bytes) -> list[str]:
    return [str(ipaddress.IPv4Address(data[i : i + 4])) for i in range(0, len(data) - 3, 4)]


def encode_uint32(value: int) -> bytes:
    return struct.pack("!I", int(value))


def encode_uint16(value: int) -> bytes:
    return struct.pack("!H", int(value))


def decode_uint32(data: bytes) -> int:
    return struct.unpack("!I", data[:4])[0]


def encode_classless_routes(routes: list[tuple[str, int, str]]) -> bytes:
    out = b""
    for network, prefix_len, gateway in routes:
        significant_bytes = (prefix_len + 7) // 8
        packed = ipaddress.IPv4Address(network).packed[:significant_bytes]
        out += bytes([prefix_len]) + packed + ipaddress.IPv4Address(gateway).packed
    return out


@dataclass
class DhcpOption:
    code: int
    value: bytes


@dataclass
class DhcpPacket:
    op: int = BOOTREQUEST
    htype: int = 1
    hlen: int = 6
    hops: int = 0
    xid: int = 0
    secs: int = 0
    flags: int = 0
    ciaddr: str = "0.0.0.0"
    yiaddr: str = "0.0.0.0"
    siaddr: str = "0.0.0.0"
    giaddr: str = "0.0.0.0"
    chaddr: bytes = b"\x00" * 16
    sname: bytes = b"\x00" * 64
    file: bytes = b"\x00" * 128
    options: dict[int, bytes] = field(default_factory=dict)

    @property
    def message_type(self) -> int | None:
        raw = self.options.get(OPT_MESSAGE_TYPE)
        return raw[0] if raw else None

    @property
    def client_mac(self) -> str:
        return format_mac(self.chaddr, self.hlen)

    @property
    def requested_ip(self) -> str | None:
        raw = self.options.get(OPT_REQUESTED_IP)
        return str(ipaddress.IPv4Address(raw)) if raw else None

    @property
    def server_identifier(self) -> str | None:
        raw = self.options.get(OPT_SERVER_IDENTIFIER)
        return str(ipaddress.IPv4Address(raw)) if raw else None

    @property
    def hostname(self) -> str | None:
        raw = self.options.get(OPT_HOSTNAME)
        return raw.decode("ascii", errors="ignore") if raw else None

    @property
    def broadcast_requested(self) -> bool:
        return bool(self.flags & FLAG_BROADCAST)


def parse(data: bytes) -> DhcpPacket:
    if len(data) < 240:
        raise ValueError("packet too short to be DHCP")

    op, htype, hlen, hops, xid, secs, flags = struct.unpack("!BBBBIHH", data[0:12])
    ciaddr = str(ipaddress.IPv4Address(data[12:16]))
    yiaddr = str(ipaddress.IPv4Address(data[16:20]))
    siaddr = str(ipaddress.IPv4Address(data[20:24]))
    giaddr = str(ipaddress.IPv4Address(data[24:28]))
    chaddr = data[28:44]
    sname = data[44:108]
    file_field = data[108:236]

    if data[236:240] != MAGIC_COOKIE:
        raise ValueError("missing DHCP magic cookie")

    options: dict[int, bytes] = {}
    pos = 240
    while pos < len(data):
        code = data[pos]
        pos += 1
        if code == OPT_END:
            break
        if code == OPT_PAD:
            continue
        if pos >= len(data):
            break
        length = data[pos]
        pos += 1
        value = data[pos : pos + length]
        pos += length
        if code in options:
            options[code] += value
        else:
            options[code] = value

    return DhcpPacket(
        op=op,
        htype=htype,
        hlen=hlen,
        hops=hops,
        xid=xid,
        secs=secs,
        flags=flags,
        ciaddr=ciaddr,
        yiaddr=yiaddr,
        siaddr=siaddr,
        giaddr=giaddr,
        chaddr=chaddr,
        sname=sname,
        file=file_field,
        options=options,
    )


def build(packet: DhcpPacket) -> bytes:
    header = struct.pack(
        "!BBBBIHH",
        packet.op,
        packet.htype,
        packet.hlen,
        packet.hops,
        packet.xid,
        packet.secs,
        packet.flags,
    )
    header += ipaddress.IPv4Address(packet.ciaddr).packed
    header += ipaddress.IPv4Address(packet.yiaddr).packed
    header += ipaddress.IPv4Address(packet.siaddr).packed
    header += ipaddress.IPv4Address(packet.giaddr).packed
    header += packet.chaddr.ljust(16, b"\x00")[:16]
    header += packet.sname.ljust(64, b"\x00")[:64]
    header += packet.file.ljust(128, b"\x00")[:128]
    header += MAGIC_COOKIE

    options_bytes = b""
    for code, value in packet.options.items():
        for chunk_start in range(0, max(len(value), 1), 255):
            chunk = value[chunk_start : chunk_start + 255]
            options_bytes += bytes([code, len(chunk)]) + chunk
    options_bytes += bytes([OPT_END])

    packet_bytes = header + options_bytes
    if len(packet_bytes) < 300:
        packet_bytes += bytes(300 - len(packet_bytes))
    return packet_bytes
