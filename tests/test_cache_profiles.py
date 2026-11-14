# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""The answer cache must never hand one client's answer to a client whose
policy differs (SafeSearch on/off, client-group upstreams)."""

from dnslib import QTYPE, RR, A, DNSRecord

from app import dns_server
from app.blocklist import BlocklistManager
from app.dns_cache import DNSCache
from app.dns_server import FilteringResolver


class _NullStats:
    def record(self, *args, **kwargs):
        pass


class _Handler:
    def __init__(self, ip):
        self.client_address = (ip, 53535)


_SAFE_IP = "216.239.38.120"
_REAL_IP = "142.250.1.1"


def _fake_forward(calls):
    def forward(data, upstream, timeout):
        request = DNSRecord.parse(data)
        qname = str(request.q.qname).rstrip(".").lower()
        calls.append((qname, upstream))
        if qname == "forcesafesearch.google.com":
            ip = _SAFE_IP
        elif upstream == "1.1.1.3:53":
            ip = "146.112.61.106"
        else:
            ip = _REAL_IP
        reply = request.reply()
        reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(ip), ttl=300))
        return reply.pack()

    return forward


def _setup(config_store, tmp_path, monkeypatch, groups):
    config_store.mutate(
        lambda d: d.update({"dns": {"cache_enabled": True, "upstreams": ["9.9.9.9:53"]}, "client_groups": groups})
    )
    calls = []
    monkeypatch.setattr(dns_server.upstream_transport, "forward", _fake_forward(calls))
    blocklist = BlocklistManager(config_store, tmp_path / "bl")
    cache = DNSCache(config_store)
    return FilteringResolver(blocklist, _NullStats(), config_store, cache=cache), cache, calls


def _ip(resolver, client):
    response = resolver.resolve(DNSRecord.question("www.google.com", qtype="A"), _Handler(client))
    return str(response.rr[0].rdata)


_KIDS = {"name": "kids", "match": ["192.168.1.50"], "safe_search": True}


def test_safe_search_answer_is_not_served_to_other_clients(config_store, tmp_path, monkeypatch):
    resolver, _cache, _calls = _setup(config_store, tmp_path, monkeypatch, [_KIDS])
    assert _ip(resolver, "192.168.1.50") == _SAFE_IP
    assert _ip(resolver, "192.168.1.10") == _REAL_IP


def test_unfiltered_answer_is_not_served_to_safe_search_clients(config_store, tmp_path, monkeypatch):
    resolver, _cache, _calls = _setup(config_store, tmp_path, monkeypatch, [_KIDS])
    assert _ip(resolver, "192.168.1.10") == _REAL_IP
    assert _ip(resolver, "192.168.1.50") == _SAFE_IP


def test_group_upstream_answers_are_cached_separately(config_store, tmp_path, monkeypatch):
    family = {"name": "family", "match": ["192.168.1.60"], "upstreams": ["1.1.1.3:53"]}
    resolver, _cache, calls = _setup(config_store, tmp_path, monkeypatch, [family])
    assert _ip(resolver, "192.168.1.10") == _REAL_IP
    assert _ip(resolver, "192.168.1.60") == "146.112.61.106"
    assert _ip(resolver, "192.168.1.60") == "146.112.61.106"
    assert _ip(resolver, "192.168.1.11") == _REAL_IP
    # one upstream call per profile, the repeats come from the cache
    assert len(calls) == 2


def test_prefetch_keeps_the_profile_of_the_entry(config_store, tmp_path, monkeypatch):
    resolver, cache, calls = _setup(config_store, tmp_path, monkeypatch, [_KIDS])
    _ip(resolver, "192.168.1.50")
    keys = list(cache._store)
    assert len(keys) == 1 and keys[0][3] == "ss"
    resolver._prefetch_one(keys[0])
    assert _ip(resolver, "192.168.1.50") == _SAFE_IP


def test_variant_round_trip():
    variant = FilteringResolver._cache_variant(True, ["1.1.1.3:53", "dot://x:853"])
    assert FilteringResolver._parse_cache_variant(variant) == (True, ["1.1.1.3:53", "dot://x:853"])
    assert FilteringResolver._cache_variant(False, None) == ""
    assert FilteringResolver._parse_cache_variant("") == (False, None)
