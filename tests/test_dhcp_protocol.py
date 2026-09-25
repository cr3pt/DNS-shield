import ipaddress

from app.dhcp import protocol as proto


def test_packet_round_trip_preserves_header_fields():
    packet = proto.DhcpPacket(
        op=proto.BOOTREQUEST,
        xid=0x12345678,
        chaddr=proto.parse_mac("AA:BB:CC:DD:EE:FF") + b"\x00" * 10,
        options={
            proto.OPT_MESSAGE_TYPE: bytes([proto.DISCOVER]),
            proto.OPT_HOSTNAME: b"my-laptop",
        },
    )
    parsed = proto.parse(proto.build(packet))

    assert parsed.xid == packet.xid
    assert parsed.client_mac == "AA:BB:CC:DD:EE:FF"
    assert parsed.message_type == proto.DISCOVER
    assert parsed.hostname == "my-laptop"


def test_parse_rejects_short_packet():
    try:
        proto.parse(b"\x00" * 10)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_parse_rejects_missing_magic_cookie():
    packet = proto.DhcpPacket(chaddr=b"\x00" * 16)
    raw = bytearray(proto.build(packet))
    raw[236:240] = b"\x00\x00\x00\x00"
    try:
        proto.parse(bytes(raw))
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_encode_decode_ipv4_list_round_trip():
    ips = ["1.1.1.1", "9.9.9.9", "192.168.1.1"]
    assert proto.decode_ipv4_list(proto.encode_ipv4_list(ips)) == ips


def test_encode_classless_routes_uses_significant_octets_only():
    routes = [("192.168.10.0", 24, "192.168.1.1")]
    encoded = proto.encode_classless_routes(routes)
    assert encoded[0] == 24
    assert encoded[1:4] == ipaddress.IPv4Address("192.168.10.0").packed[:3]
    assert encoded[4:8] == ipaddress.IPv4Address("192.168.1.1").packed


def test_requested_ip_and_server_identifier_properties():
    packet = proto.DhcpPacket(
        options={
            proto.OPT_REQUESTED_IP: ipaddress.IPv4Address("10.0.0.5").packed,
            proto.OPT_SERVER_IDENTIFIER: ipaddress.IPv4Address("10.0.0.1").packed,
        }
    )
    assert packet.requested_ip == "10.0.0.5"
    assert packet.server_identifier == "10.0.0.1"


def test_broadcast_flag_roundtrip():
    packet = proto.DhcpPacket(flags=proto.FLAG_BROADCAST)
    parsed = proto.parse(proto.build(packet))
    assert parsed.broadcast_requested is True

    packet2 = proto.DhcpPacket(flags=0)
    parsed2 = proto.parse(proto.build(packet2))
    assert parsed2.broadcast_requested is False


def test_option_longer_than_255_bytes_is_chunked_and_reassembled():
    long_value = b"x" * 300
    packet = proto.DhcpPacket(options={proto.OPT_MESSAGE: long_value})
    parsed = proto.parse(proto.build(packet))
    assert parsed.options[proto.OPT_MESSAGE] == long_value
