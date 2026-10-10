# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from app.netmatch import client_matches, ip_matches


def test_ip_matches_exact_ipv4():
    assert ip_matches("192.168.1.5", "192.168.1.5") is True
    assert ip_matches("192.168.1.5", "192.168.1.6") is False


def test_ip_matches_cidr():
    assert ip_matches("192.168.1.5", "192.168.1.0/24") is True
    assert ip_matches("192.168.2.5", "192.168.1.0/24") is False


def test_ip_matches_ipv6():
    assert ip_matches("2001:db8::1", "2001:db8::/32") is True
    assert ip_matches("2001:db9::1", "2001:db8::/32") is False


def test_ip_matches_falls_back_to_string_equality_on_garbage():
    assert ip_matches("not-an-ip", "not-an-ip") is True
    assert ip_matches("not-an-ip", "also-not-an-ip") is False


def test_client_matches_plain_ip_and_cidr():
    assert client_matches("10.0.0.5", "10.0.0.0/8") is True
    assert client_matches("10.0.0.5", "10.0.0.5") is True
    assert client_matches("10.0.0.5", "10.0.0.6") is False


def test_client_matches_mac_prefix():
    assert client_matches("10.0.0.5", "mac:AA:BB:CC:DD:EE:FF", mac="aa:bb:cc:dd:ee:ff") is True
    assert client_matches("10.0.0.5", "mac:AA:BB:CC:DD:EE:FF", mac="11:22:33:44:55:66") is False
    assert client_matches("10.0.0.5", "mac:AA:BB:CC:DD:EE:FF", mac=None) is False


def test_client_matches_host_prefix_exact_and_wildcard():
    assert client_matches("10.0.0.5", "host:printer.lan", hostname="printer.lan") is True
    assert client_matches("10.0.0.5", "host:printer.lan", hostname="Printer.LAN.") is True
    assert client_matches("10.0.0.5", "host:printer.lan", hostname="scanner.lan") is False
    assert client_matches("10.0.0.5", "host:*.iot.lan", hostname="bulb1.iot.lan") is True
    assert client_matches("10.0.0.5", "host:*.iot.lan", hostname="iot.lan") is False
    assert client_matches("10.0.0.5", "host:printer.lan", hostname=None) is False
