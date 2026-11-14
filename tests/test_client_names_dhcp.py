# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

import time

from app.client_names import ClientNameResolver, _normalize_ip, _resolver_address
from app.dhcp.leases import LeaseStore


class _Config:
    def __init__(self, data):
        self.data = data
        self.version = 0

    def get(self, *keys, default=None):
        node = self.data
        for key in keys:
            if not isinstance(node, dict) or key not in node:
                return default
            node = node[key]
        return node


def _store(tmp_path):
    store = LeaseStore(tmp_path / "dhcp_leases.db")
    store.commit_lease("aa:bb:cc:dd:ee:01", "192.168.1.50", "lan", "laptop-jan", None, 3600)
    store.commit_lease("aa:bb:cc:dd:ee:02", "192.168.1.51", "lan", None, None, 3600)
    return store


def test_names_come_from_dhcp_leases_and_reservations(tmp_path):
    _store(tmp_path)
    config = _Config({"dhcp": {"scopes": [{"reservations": [{"ip": "192.168.1.9", "hostname": "nas"}]}]}})
    names = ClientNameResolver(config, leases_db=tmp_path / "dhcp_leases.db")
    assert names.get("192.168.1.50") == "laptop-jan"
    assert names.get("192.168.1.9") == "nas"
    assert names.get("192.168.1.51") is None
    assert names.snapshot() == {"192.168.1.50": "laptop-jan", "192.168.1.9": "nas"}


def test_dhcp_names_can_be_turned_off(tmp_path):
    _store(tmp_path)
    config = _Config({"dns": {"client_names_from_dhcp": False}})
    names = ClientNameResolver(config, leases_db=tmp_path / "dhcp_leases.db")
    assert names.get("192.168.1.50") is None
    assert names.snapshot() == {}


def test_dhcp_name_wins_over_ptr(tmp_path):
    _store(tmp_path)
    config = _Config({"dns": {"resolve_client_names": True, "client_name_resolver": "127.0.0.1:1"}})
    names = ClientNameResolver(config, leases_db=tmp_path / "dhcp_leases.db")
    names._cache["192.168.1.50"] = ("ptr-name.lan", time.time() + 60)
    names._cache["192.168.1.60"] = ("tv.lan", time.time() + 60)
    assert names.get("192.168.1.50") == "laptop-jan"
    assert names.get("192.168.1.60") == "tv.lan"
    assert names.snapshot()["192.168.1.50"] == "laptop-jan"


def test_missing_lease_db_is_fine(tmp_path):
    names = ClientNameResolver(_Config({}), leases_db=tmp_path / "nope.db")
    assert names.get("10.0.0.1") is None


def test_ipv6_reverse_pointer_and_mapped_ipv4():
    assert _normalize_ip("2001:db8::1").reverse_pointer.endswith(".8.b.d.0.1.0.0.2.ip6.arpa")
    assert _normalize_ip("::ffff:192.168.1.5").reverse_pointer == "5.1.168.192.in-addr.arpa"
    assert _normalize_ip("fe80::1%eth0") is not None
    assert _normalize_ip("not-an-ip") is None


def test_resolver_address_forms():
    assert _resolver_address("192.168.1.1") == ("192.168.1.1", 53)
    assert _resolver_address("192.168.1.1:5353") == ("192.168.1.1", 5353)
    assert _resolver_address("[fd00::1]:5300") == ("fd00::1", 5300)
    assert _resolver_address("[fd00::1]") == ("fd00::1", 53)
    assert _resolver_address("fd00::1") == ("fd00::1", 53)


def test_ipv6_ptr_lookup(monkeypatch):
    from dnslib import PTR, QTYPE, RR, DNSRecord

    asked = {}

    def fake_send(self, host, port, timeout=None, ipv6=False, **_):
        asked.update(qname=str(self.q.qname), host=host, port=port, ipv6=ipv6)
        reply = self.reply()
        reply.add_answer(RR(self.q.qname, QTYPE.PTR, rdata=PTR("phone.lan.")))
        return reply.pack()

    monkeypatch.setattr(DNSRecord, "send", fake_send)
    config = _Config({"dns": {"resolve_client_names": True, "client_name_resolver": "[fd00::1]:53"}})
    names = ClientNameResolver(config)
    assert names._resolve("2001:db8::1") == "phone.lan"
    assert asked["qname"].endswith("ip6.arpa.")
    assert asked == {**asked, "host": "fd00::1", "port": 53, "ipv6": True}
