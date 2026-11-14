# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""DNS-over-QUIC (RFC 9250): DNS-shield as a DoQ client and as a DoQ server."""

import socket

import pytest
from dnslib import QTYPE, RR, A, DNSRecord

from app import doq, upstream
from app.tls import ensure_self_signed_cert


class _Resolver:
    def __init__(self):
        self.seen = []

    def resolve(self, request, handler):
        self.seen.append((request.header.id, str(request.q.qname), handler.client_address[0]))
        reply = request.reply()
        reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("192.0.2.7"), ttl=60))
        return reply


def _free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def doq_server(tmp_path, monkeypatch):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    ensure_self_signed_cert(cert, key)
    resolver = _Resolver()
    port = _free_udp_port()
    server = doq.start_server(resolver, cert, key, address="127.0.0.1", port=port, threads=2)

    def trust_test_cert(configuration):
        configuration.load_verify_locations(cafile=str(cert))
        configuration.server_name = "dns-shield.local"

    monkeypatch.setattr(doq, "configure_client", trust_test_cert)
    doq.reset_connections()
    yield port, resolver
    doq.reset_connections()
    server.stop()


def test_query_round_trip_keeps_the_callers_id(doq_server):
    port, resolver = doq_server
    query = DNSRecord.question("example.com")
    answer = DNSRecord.parse(upstream.forward(query.pack(), f"quic://127.0.0.1:{port}", 5.0))
    assert answer.header.id == query.header.id
    assert str(answer.rr[0].rdata) == "192.0.2.7"
    # on the wire the ID was 0, as RFC 9250 requires
    assert resolver.seen == [(0, "example.com.", "127.0.0.1")]


def test_queries_share_one_connection(doq_server):
    port, _resolver = doq_server
    for name in ("a.example", "b.example", "c.example"):
        answer = DNSRecord.parse(upstream.forward(DNSRecord.question(name).pack(), f"doq://127.0.0.1:{port}", 5.0))
        assert str(answer.q.qname) == name + "."
    assert len(doq._upstreams) == 1
    connection = doq._upstreams[("127.0.0.1", port)]._protocol
    assert connection is not None and not connection.terminated


def test_untrusted_certificate_is_refused(doq_server, monkeypatch):
    port, _resolver = doq_server
    monkeypatch.setattr(doq, "configure_client", None)
    doq.reset_connections()
    with pytest.raises((ConnectionError, TimeoutError)):
        upstream.forward(DNSRecord.question("example.com").pack(), f"quic://127.0.0.1:{port}", 2.0)


def test_doq_upstream_hostnames_are_protected():
    assert upstream.hostname_of("quic://dns.adguard-dns.com") == "dns.adguard-dns.com"
    assert upstream.hostname_of("doq://dns.example.net:8853") == "dns.example.net"


def test_doq_clients_get_the_same_filtering(config_store, tmp_path, monkeypatch):
    from app.blocklist import BlocklistManager
    from app.dns_server import FilteringResolver

    class _Stats:
        def __init__(self):
            self.rows = []

        def record(self, qname, blocked, client_ip, *args, **kwargs):
            self.rows.append((qname, blocked, client_ip))

    config_store.mutate(lambda d: d.update({"denylist": ["ads.example"], "dns": {"block_mode": "nxdomain"}}))
    stats = _Stats()
    resolver = FilteringResolver(BlocklistManager(config_store, tmp_path / "bl"), stats, config_store)
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    ensure_self_signed_cert(cert, key)
    port = _free_udp_port()
    server = doq.start_server(resolver, cert, key, address="127.0.0.1", port=port, threads=2)

    def trust_test_cert(configuration):
        configuration.load_verify_locations(cafile=str(cert))
        configuration.server_name = "dns-shield.local"

    monkeypatch.setattr(doq, "configure_client", trust_test_cert)
    doq.reset_connections()
    try:
        query = DNSRecord.question("x.ads.example")
        answer = DNSRecord.parse(upstream.forward(query.pack(), f"quic://127.0.0.1:{port}", 5.0))
        assert answer.header.rcode == 3 and answer.header.id == query.header.id
        assert stats.rows == [("x.ads.example", True, "127.0.0.1")]
    finally:
        doq.reset_connections()
        server.stop()
