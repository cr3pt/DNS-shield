# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Local DNSSEC validation against a small signed test hierarchy:
. -> example. (signed) and plain. (unsigned delegation)."""

import dns.dnssec
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import ec
from dnslib import QTYPE, RCODE, DNSRecord

from app import dns_server
from app.dnssec_validate import BOGUS, INDETERMINATE, INSECURE, SECURE, LocalValidator
from tests.test_dns_server import _resolver

ALG = dns.dnssec.Algorithm.ECDSAP256SHA256
N = dns.name.from_text


class Zone:
    def __init__(self, name):
        self.name = N(name)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.dnskey = dns.dnssec.make_dnskey(self.key.public_key(), ALG, flags=257)
        self.keys = self.rrset(name, "DNSKEY", self.dnskey.to_text())

    def rrset(self, owner, rdtype, *values, ttl=300):
        return dns.rrset.from_text(owner, ttl, "IN", rdtype, *values)

    def sign(self, rrset):
        sig = dns.dnssec.sign(rrset, self.key, self.name, self.dnskey, lifetime=3600)
        sigs = dns.rrset.RRset(rrset.name, dns.rdataclass.IN, dns.rdatatype.RRSIG, rrset.rdtype)
        sigs.add(sig, rrset.ttl)
        return sigs

    def ds(self):
        return dns.dnssec.make_ds(self.name, self.dnskey, "SHA256")


class World:
    def __init__(self):
        self.root = Zone(".")
        self.example = Zone("example.")
        self.anchor = f". IN DS {self.root.ds().to_text()}"
        self.answers = {}
        self.authority = {}
        root, example = self.root, self.example
        self.add(".", "DNSKEY", root.keys, root.sign(root.keys))
        ds = dns.rrset.from_rdata("example.", 300, example.ds())
        self.add("example.", "DS", ds, root.sign(ds))
        self.add("example.", "DNSKEY", example.keys, example.sign(example.keys))
        soa = example.rrset("example.", "SOA", "ns.example. admin.example. 1 3600 600 86400 300")
        self.add("example.", "SOA", soa, example.sign(soa))
        self.add("www.example.", "SOA", authority=[soa, example.sign(soa)])
        # plain. is delegated without a DS (root says NODATA).
        root_soa = root.rrset(".", "SOA", "a.root. nstld. 1 1800 900 604800 86400")
        self.add("plain.", "DS", authority=[root_soa, root.sign(root_soa)])
        plain_soa = root.rrset("plain.", "SOA", "ns.plain. admin.plain. 1 3600 600 86400 300")
        self.add("plain.", "SOA", plain_soa)
        self.add("www.plain.", "SOA", authority=[plain_soa])
        self.add("plain.", "DNSKEY")
        self.queries = []

    def add(self, name, rdtype, *answer, authority=()):
        self.answers[(N(name), dns.rdatatype.from_text(rdtype))] = list(answer)
        self.authority[(N(name), dns.rdatatype.from_text(rdtype))] = list(authority)

    def query(self, name, rdtype):
        self.queries.append((str(name), dns.rdatatype.to_text(rdtype)))
        request = dns.message.make_query(name, rdtype, want_dnssec=True)
        response = dns.message.make_response(request)
        for rrset in self.answers.get((name, rdtype), []):
            response.answer.append(rrset)
        for rrset in self.authority.get((name, rdtype), []):
            response.authority.append(rrset)
        return response

    def response(self, qname, rdtype, *rrsets):
        request = dns.message.make_query(qname, rdtype, want_dnssec=True)
        response = dns.message.make_response(request)
        response.answer.extend(rrsets)
        return response.to_wire()


def _validator(world):
    return LocalValidator(world.query, anchors=[world.anchor])


def test_signed_answer_is_secure():
    world = World()
    a = world.example.rrset("www.example.", "A", "93.184.216.34")
    assert _validator(world).validate(world.response("www.example.", "A", a, world.example.sign(a))) == SECURE


def test_tampered_or_stripped_signed_answer_is_bogus():
    world = World()
    a = world.example.rrset("www.example.", "A", "93.184.216.34")
    sig = world.example.sign(a)
    forged = world.example.rrset("www.example.", "A", "8.8.4.4")
    validator = _validator(world)
    assert validator.validate(world.response("www.example.", "A", forged, sig)) == BOGUS
    # Signatures removed: the zone is signed, so this is bogus too.
    assert validator.validate(world.response("www.example.", "A", forged)) == BOGUS


def test_signature_from_wrong_key_is_bogus():
    world = World()
    impostor = Zone("example.")
    a = world.example.rrset("www.example.", "A", "93.184.216.34")
    assert _validator(world).validate(world.response("www.example.", "A", a, impostor.sign(a))) == BOGUS


def test_unsigned_zone_is_insecure_and_cached():
    world = World()
    a = world.root.rrset("www.plain.", "A", "1.0.0.1")
    validator = _validator(world)
    assert validator.validate(world.response("www.plain.", "A", a)) == INSECURE
    asked = len(world.queries)
    assert validator.validate(world.response("www.plain.", "A", a)) == INSECURE
    assert len(world.queries) == asked


def test_wrong_trust_anchor_is_indeterminate_not_bogus():
    world = World()
    other = Zone(".")
    validator = LocalValidator(world.query, anchors=[f". IN DS {other.ds().to_text()}"])
    a = world.example.rrset("www.example.", "A", "93.184.216.34")
    assert validator.validate(world.response("www.example.", "A", a, world.example.sign(a))) == INDETERMINATE


def test_resolver_answers_servfail_for_bogus(config_store, tmp_path, monkeypatch):
    world = World()
    a = world.example.rrset("www.example.", "A", "93.184.216.34")
    sig = world.example.sign(a)
    forged = world.example.rrset("www.example.", "A", "8.8.4.4")
    good = {"value": True}

    def fake_forward(data, upstream, timeout):
        query = dns.message.from_wire(bytes(data))
        question = query.question[0]
        if question.rdtype == dns.rdatatype.A:
            response = dns.message.make_response(query)
            response.answer.extend([a if good["value"] else forged, sig])
            return response.to_wire()
        answer = world.query(question.name, question.rdtype)
        answer.id = query.id
        return answer.to_wire()

    monkeypatch.setattr(dns_server.upstream_transport, "forward", fake_forward)
    config_store.mutate(
        lambda d: d.setdefault("dns", {}).update(
            dnssec_enabled=True, dnssec_validation="local", dnssec_trust_anchors=[world.anchor], cache_enabled=False
        )
    )
    from app.dnssec import DnssecCache

    resolver = _resolver(config_store, tmp_path, dnssec_cache=DnssecCache())
    request = DNSRecord.question("www.example", qtype="A")
    reply = resolver.resolve(request, None)
    assert reply.header.rcode == RCODE.NOERROR
    assert [str(rr.rdata) for rr in reply.rr if rr.rtype == QTYPE.A] == ["93.184.216.34"]

    good["value"] = False
    reply = resolver.resolve(DNSRecord.question("www.example", qtype="A"), None)
    assert reply.header.rcode == RCODE.SERVFAIL
    opt = next(rr for rr in reply.ar if rr.rtype == QTYPE.OPT)
    assert any(o.code == 15 and o.data == b"\x00\x06" for o in opt.rdata)


def test_settings_validate_anchors(config_store, tmp_path):
    from tests.test_client_groups_api import _admin_client

    client = _admin_client(config_store, tmp_path)
    assert client.patch("/api/settings/dns", json={"dnssec_validation": "maybe"}).status_code == 422
    assert client.patch("/api/settings/dns", json={"dnssec_trust_anchors": ["nonsense"]}).status_code == 422
    assert client.patch("/api/settings/dns", json={"dnssec_validation": "local"}).status_code == 200
