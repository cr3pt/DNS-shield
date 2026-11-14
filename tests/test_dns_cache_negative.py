# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""NXDOMAIN / NODATA answers are cached for as long as the SOA allows (RFC 2308)."""

from dnslib import QTYPE, RCODE, RR, SOA, DNSRecord

from app.dns_cache import DNSCache


def _negative(qname, qtype="AAAA", rcode=RCODE.NOERROR, soa_ttl=900, minimum=60, with_soa=True):
    request = DNSRecord.question(qname, qtype=qtype)
    reply = request.reply()
    reply.header.rcode = rcode
    if with_soa:
        soa = SOA("ns1.example.com", "hostmaster.example.com", (1, 7200, 900, 1209600, minimum))
        reply.add_auth(RR("example.com", QTYPE.SOA, rdata=soa, ttl=soa_ttl))
    return request, reply


def test_nxdomain_is_cached_with_its_soa(config_store):
    cache = DNSCache(config_store)
    request, reply = _negative("nope.example.com", qtype="A", rcode=RCODE.NXDOMAIN)
    cache.put(request, reply)
    hit = cache.get(DNSRecord.question("NOPE.example.com", qtype="A"))
    assert hit is not None
    assert hit.header.rcode == RCODE.NXDOMAIN and not hit.rr
    assert hit.auth[0].rtype == QTYPE.SOA and 0 < hit.auth[0].ttl <= 60


def test_nodata_is_cached_per_type(config_store):
    cache = DNSCache(config_store)
    request, reply = _negative("v4only.example.com")
    cache.put(request, reply)
    hit = cache.get(request)
    assert hit is not None and hit.header.rcode == RCODE.NOERROR and not hit.rr
    assert cache.get(DNSRecord.question("v4only.example.com", qtype="A")) is None


def test_negative_ttl_is_the_smallest_of_soa_ttl_minimum_and_cap(config_store):
    cache = DNSCache(config_store)
    _request, reply = _negative("x.example.com", soa_ttl=30, minimum=600)
    assert cache._negative_ttl(reply) == 30
    _request, reply = _negative("x.example.com", soa_ttl=86400, minimum=86400)
    assert cache._negative_ttl(reply) == 300
    config_store.mutate(lambda d: d.setdefault("dns", {}).update({"cache_negative_max_ttl_seconds": 0}))
    assert cache._negative_ttl(reply) is None


def test_negative_answers_without_soa_or_servfail_are_not_cached(config_store):
    cache = DNSCache(config_store)
    request, reply = _negative("nosoa.example.com", rcode=RCODE.NXDOMAIN, with_soa=False)
    cache.put(request, reply)
    assert cache.get(request) is None
    request, reply = _negative("broken.example.com", rcode=RCODE.SERVFAIL)
    cache.put(request, reply)
    assert cache.get(request) is None


def test_negative_entries_survive_a_restart(config_store, tmp_path):
    path = tmp_path / "cache.json"
    cache = DNSCache(config_store, persist_path=path)
    request, reply = _negative("gone.example.com", qtype="A", rcode=RCODE.NXDOMAIN)
    cache.put(request, reply)
    cache.save()
    hit = DNSCache(config_store, persist_path=path).get(request)
    assert hit is not None and hit.header.rcode == RCODE.NXDOMAIN and hit.auth
