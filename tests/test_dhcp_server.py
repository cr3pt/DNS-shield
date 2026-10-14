# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

import ipaddress

import pytest

from app.dhcp import protocol as proto
from app.dhcp import server as dhcp_server
from app.dhcp.leases import LeaseStore

SERVER_IP = "192.168.1.1"


@pytest.fixture
def lease_store(tmp_path):
    return LeaseStore(tmp_path / "leases.db")


@pytest.fixture
def scope():
    return {
        "name": "lan",
        "network": "192.168.1.0/24",
        "pool_start": "192.168.1.100",
        "pool_end": "192.168.1.110",
        "gateway": "192.168.1.1",
        "dns_servers": ["192.168.1.1"],
        "lease_seconds": 3600,
        "server_ip": SERVER_IP,
        "reservations": [{"mac": "AA:BB:CC:DD:EE:02", "ip": "192.168.1.50", "hostname": "printer"}],
    }


def _discover(mac, xid=1):
    return proto.DhcpPacket(
        op=proto.BOOTREQUEST, xid=xid, chaddr=proto.parse_mac(mac) + b"\x00" * 10,
        options={proto.OPT_MESSAGE_TYPE: bytes([proto.DISCOVER])},
    )


def _request(mac, requested_ip=None, ciaddr="0.0.0.0", xid=1):
    options = {proto.OPT_MESSAGE_TYPE: bytes([proto.REQUEST])}
    if requested_ip:
        options[proto.OPT_REQUESTED_IP] = ipaddress.IPv4Address(requested_ip).packed
    return proto.DhcpPacket(
        op=proto.BOOTREQUEST, xid=xid, chaddr=proto.parse_mac(mac) + b"\x00" * 10,
        ciaddr=ciaddr, options=options,
    )


def test_discover_offers_first_free_pool_address(scope, lease_store):
    reply = dhcp_server.handle_packet(scope, _discover("AA:BB:CC:DD:EE:01"), lease_store, SERVER_IP)
    assert reply.message_type == proto.OFFER
    assert reply.yiaddr == "192.168.1.100"


def test_discover_for_reserved_mac_offers_reserved_ip(scope, lease_store):
    reply = dhcp_server.handle_packet(scope, _discover("AA:BB:CC:DD:EE:02"), lease_store, SERVER_IP)
    assert reply.yiaddr == "192.168.1.50"


def test_discover_for_unreserved_mac_never_offers_an_in_pool_reservation(lease_store):
    scope = {
        "name": "lan",
        "network": "192.168.1.0/24",
        "pool_start": "192.168.1.100",
        "pool_end": "192.168.1.102",
        "gateway": "192.168.1.1",
        "dns_servers": ["192.168.1.1"],
        "lease_seconds": 3600,
        "server_ip": SERVER_IP,
        "reservations": [{"mac": "AA:BB:CC:DD:EE:02", "ip": "192.168.1.100", "hostname": "printer"}],
    }

    reply = dhcp_server.handle_packet(scope, _discover("AA:BB:CC:DD:EE:01"), lease_store, SERVER_IP)

    assert reply.message_type == proto.OFFER
    assert reply.yiaddr != "192.168.1.100"
    assert reply.yiaddr == "192.168.1.101"


def test_request_confirms_offered_address(scope, lease_store):
    offer = dhcp_server.handle_packet(scope, _discover("AA:BB:CC:DD:EE:01"), lease_store, SERVER_IP)
    ack = dhcp_server.handle_packet(
        scope, _request("AA:BB:CC:DD:EE:01", requested_ip=offer.yiaddr), lease_store, SERVER_IP
    )
    assert ack.message_type == proto.ACK
    assert ack.yiaddr == offer.yiaddr


def test_request_for_ip_reserved_to_another_mac_is_nakked(scope, lease_store):
    reply = dhcp_server.handle_packet(
        scope, _request("AA:BB:CC:DD:EE:99", requested_ip="192.168.1.50"), lease_store, SERVER_IP
    )
    assert reply.message_type == proto.NAK


def test_request_for_already_leased_ip_is_nakked(scope, lease_store):
    dhcp_server.handle_packet(scope, _discover("AA:BB:CC:DD:EE:01"), lease_store, SERVER_IP)
    dhcp_server.handle_packet(
        scope, _request("AA:BB:CC:DD:EE:01", requested_ip="192.168.1.100"), lease_store, SERVER_IP
    )
    reply = dhcp_server.handle_packet(
        scope, _request("AA:BB:CC:DD:EE:77", requested_ip="192.168.1.100"), lease_store, SERVER_IP,
    )
    assert reply.message_type == proto.NAK


def test_request_outside_pool_range_is_nakked(scope, lease_store):
    reply = dhcp_server.handle_packet(
        scope, _request("AA:BB:CC:DD:EE:03", requested_ip="10.0.0.5"), lease_store, SERVER_IP
    )
    assert reply.message_type == proto.NAK


def test_request_with_mismatched_server_identifier_is_ignored(scope, lease_store):
    req = _request("AA:BB:CC:DD:EE:01", requested_ip="192.168.1.100")
    req.options[proto.OPT_SERVER_IDENTIFIER] = ipaddress.IPv4Address("10.0.0.9").packed
    reply = dhcp_server.handle_packet(scope, req, lease_store, SERVER_IP)
    assert reply is None


def test_release_removes_the_lease(scope, lease_store):
    offer = dhcp_server.handle_packet(scope, _discover("AA:BB:CC:DD:EE:01"), lease_store, SERVER_IP)
    dhcp_server.handle_packet(
        scope, _request("AA:BB:CC:DD:EE:01", requested_ip=offer.yiaddr), lease_store, SERVER_IP
    )
    release = proto.DhcpPacket(
        op=proto.BOOTREQUEST, chaddr=proto.parse_mac("AA:BB:CC:DD:EE:01") + b"\x00" * 10,
        ciaddr=offer.yiaddr, options={proto.OPT_MESSAGE_TYPE: bytes([proto.RELEASE])},
    )
    result = dhcp_server.handle_packet(scope, release, lease_store, SERVER_IP)
    assert result is None
    assert lease_store.get_by_mac("AA:BB:CC:DD:EE:01") is None


def test_decline_frees_lease_and_blocks_ip_temporarily(scope, lease_store):
    offer = dhcp_server.handle_packet(scope, _discover("AA:BB:CC:DD:EE:01"), lease_store, SERVER_IP)
    decline = proto.DhcpPacket(
        op=proto.BOOTREQUEST, chaddr=proto.parse_mac("AA:BB:CC:DD:EE:01") + b"\x00" * 10,
        options={
            proto.OPT_MESSAGE_TYPE: bytes([proto.DECLINE]),
            proto.OPT_REQUESTED_IP: ipaddress.IPv4Address(offer.yiaddr).packed,
        },
    )
    dhcp_server.handle_packet(scope, decline, lease_store, SERVER_IP)
    assert lease_store.get_by_mac("AA:BB:CC:DD:EE:01") is None
    assert offer.yiaddr in lease_store.declined_ips("lan")


def test_inform_acks_without_assigning_a_lease(scope, lease_store):
    inform = proto.DhcpPacket(
        op=proto.BOOTREQUEST, chaddr=proto.parse_mac("AA:BB:CC:DD:EE:01") + b"\x00" * 10,
        ciaddr="192.168.1.100",
        options={proto.OPT_MESSAGE_TYPE: bytes([proto.INFORM])},
    )
    reply = dhcp_server.handle_packet(scope, inform, lease_store, SERVER_IP)
    assert reply.message_type == proto.ACK
    assert reply.yiaddr == "192.168.1.100"
    assert lease_store.get_by_mac("AA:BB:CC:DD:EE:01") is None


def test_pool_exhaustion_returns_no_reply(scope, lease_store):
    scope["pool_start"] = "192.168.1.100"
    scope["pool_end"] = "192.168.1.100"
    dhcp_server.handle_packet(scope, _discover("AA:BB:CC:DD:EE:01"), lease_store, SERVER_IP)
    reply = dhcp_server.handle_packet(scope, _discover("AA:BB:CC:DD:EE:99"), lease_store, SERVER_IP)
    assert reply is None
