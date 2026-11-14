# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""EDNS Client Subnet is stripped before queries go upstream, and messages on
encrypted transports are padded (RFC 7830 / 8467)."""

import ipaddress

from dnslib import EDNS0, QTYPE, RR, A, DNSRecord, EDNSOption

from app import dns_server
from app.dns_server import pad_message
from tests.test_dns_server import _resolver


def _ecs_option(subnet: str) -> EDNSOption:
    net = ipaddress.ip_network(subnet)
    prefix = net.prefixlen
    address = net.network_address.packed[: (prefix + 7) // 8]
    return EDNSOption(8, b"\x00\x01" + bytes([prefix, 0]) + address)


def _query(*options, do=False):
    request = DNSRecord.question("example.com", qtype="A")
    request.add_ar(EDNS0(flags="do" if do else "", udp_len=4096, opts=list(options)))
    return request


def _options(record):
    opt = next(rr for rr in record.ar if rr.rtype == QTYPE.OPT)
    return {o.code: o.data for o in opt.rdata}


def test_ecs_and_cookies_are_stripped_by_default(config_store, tmp_path):
    resolver = _resolver(config_store, tmp_path)
    request = _query(_ecs_option("192.168.1.0/24"), EDNSOption(10, b"12345678"), EDNSOption(3, b""), do=True)
    outgoing = resolver._prepare_upstream_query(request)
    assert set(_options(outgoing)) == {3}
    opt = next(rr for rr in outgoing.ar if rr.rtype == QTYPE.OPT)
    assert opt.ttl & (1 << 15)  # the client's DO bit survives
    assert opt.rclass == 4096


def test_ecs_can_be_passed_on(config_store, tmp_path):
    config_store.mutate(lambda d: d.setdefault("dns", {}).update(strip_ecs=False))
    resolver = _resolver(config_store, tmp_path)
    outgoing = resolver._prepare_upstream_query(_query(_ecs_option("10.1.0.0/16")))
    assert 8 in _options(outgoing)


def test_query_without_edns_stays_without_edns(config_store, tmp_path):
    resolver = _resolver(config_store, tmp_path)
    outgoing = resolver._prepare_upstream_query(DNSRecord.question("example.com"))
    assert not any(rr.rtype == QTYPE.OPT for rr in outgoing.ar)


def test_pad_message_block_sizes():
    for name in ("a.example", "a-much-longer-name.subdomain.example.org"):
        padded = pad_message(DNSRecord.question(name), 128)
        assert len(padded) % 128 == 0
        assert 12 in _options(DNSRecord.parse(padded))
    reply = DNSRecord.question("x.example").reply()
    reply.add_answer(RR("x.example", QTYPE.A, rdata=A("1.2.3.4"), ttl=60))
    assert len(pad_message(reply, 468)) % 468 == 0


def test_only_encrypted_upstreams_get_padding(config_store, tmp_path, monkeypatch):
    sent = {}

    def fake_forward(data, upstream, timeout):
        sent[upstream] = data
        reply = DNSRecord.parse(data).reply()
        reply.add_answer(RR("example.com", QTYPE.A, rdata=A("1.2.3.4"), ttl=60))
        if upstream == "1.1.1.1:53":
            raise OSError("down")
        return reply.pack()

    monkeypatch.setattr(dns_server.upstream_transport, "forward", fake_forward)
    config_store.mutate(lambda d: d.setdefault("dns", {}).update(upstreams=["1.1.1.1:53", "dot://9.9.9.9"]))
    resolver = _resolver(config_store, tmp_path)
    resolver.resolve(DNSRecord.question("example.com"), None)
    assert len(sent["dot://9.9.9.9"]) % 128 == 0
    assert 12 in _options(DNSRecord.parse(sent["dot://9.9.9.9"]))
    assert not any(rr.rtype == QTYPE.OPT for rr in DNSRecord.parse(sent["1.1.1.1:53"]).ar)

    sent.clear()
    config_store.mutate(lambda d: d["dns"].update(edns_padding=False))
    resolver.resolve(DNSRecord.question("example.org"), None)
    assert not any(rr.rtype == QTYPE.OPT for rr in DNSRecord.parse(sent["dot://9.9.9.9"]).ar)


def test_encrypted_clients_that_pad_get_padded_answers(config_store, tmp_path, monkeypatch):
    def fake_forward(data, upstream, timeout):
        reply = DNSRecord.parse(data).reply()
        reply.add_answer(RR("example.com", QTYPE.A, rdata=A("1.2.3.4"), ttl=60))
        return reply.pack()

    monkeypatch.setattr(dns_server.upstream_transport, "forward", fake_forward)
    resolver = _resolver(config_store, tmp_path)

    class _Plain:
        client_address = ("192.168.1.5", 5000)

    class _Encrypted(_Plain):
        encrypted_transport = True

    padded_query = _query(EDNSOption(12, b"\x00" * 10))
    answer = resolver.resolve(padded_query, _Encrypted())
    assert len(answer.pack()) % 468 == 0
    assert str(answer.rr[0].rdata) == "1.2.3.4"
    # Plain transport, or a client that didn't pad: no padding.
    assert len(resolver.resolve(padded_query, _Plain()).pack()) % 468 != 0
    assert len(resolver.resolve(_query(), _Encrypted()).pack()) % 468 != 0
