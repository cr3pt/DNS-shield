import random

from dnslib import CNAME, QTYPE, RCODE, RR, A, DNSRecord

from app import dns_server
from app.blocklist import BlocklistManager
from app.dns_cache import DNSCache
from app.dns_server import FilteringResolver


class _NullStats:
    def record(self, *args, **kwargs):
        pass


class _FakeHandler:
    def __init__(self, client_ip: str):
        self.client_address = (client_ip, 53535)


def _resolver(config_store, tmp_path, cache=None):
    blocklist = BlocklistManager(config_store, tmp_path / "cache")
    return FilteringResolver(blocklist, _NullStats(), config_store, cache=cache)


def _cname_response(qname: str, cname_target: str, final_ip: str = "1.2.3.4") -> bytes:
    request = DNSRecord.question(qname, qtype="A")
    reply = request.reply()
    reply.add_answer(RR(qname, QTYPE.CNAME, rdata=CNAME(cname_target), ttl=60))
    reply.add_answer(RR(cname_target, QTYPE.A, rdata=A(final_ip), ttl=60))
    return reply.pack()


def test_cname_cloaking_blocks_when_target_is_denylisted(config_store, tmp_path, monkeypatch):
    config_store.mutate(lambda d: d.update({"denylist": ["adnetwork.example"]}))
    resolver = _resolver(config_store, tmp_path)

    packed = _cname_response("innocent.example.com", "tracker.adnetwork.example")
    monkeypatch.setattr(dns_server.upstream_transport, "forward", lambda data, upstream, timeout: packed)

    request = DNSRecord.question("innocent.example.com", qtype="A")
    response = resolver.resolve(request, None)

    assert response.header.rcode == RCODE.NXDOMAIN


def test_cname_cloaking_leaves_unlisted_targets_alone(config_store, tmp_path, monkeypatch):
    resolver = _resolver(config_store, tmp_path)

    packed = _cname_response("shop.example.com", "cdn.example.net")
    monkeypatch.setattr(dns_server.upstream_transport, "forward", lambda data, upstream, timeout: packed)

    request = DNSRecord.question("shop.example.com", qtype="A")
    response = resolver.resolve(request, None)

    assert response.header.rcode == RCODE.NOERROR
    assert any(rr.rtype == QTYPE.A for rr in response.rr)


def _plain_response(qname: str, ip: str = "5.6.7.8", ttl: int = 60) -> bytes:
    request = DNSRecord.question(qname, qtype="A")
    reply = request.reply()
    reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=ttl))
    return reply.pack()


def test_serve_stale_on_upstream_failure(config_store, tmp_path, monkeypatch):
    cache = DNSCache(config_store)
    resolver = _resolver(config_store, tmp_path, cache=cache)

    request = DNSRecord.question("stale.example.com", qtype="A")
    cache.put(request, DNSRecord.parse(_plain_response("stale.example.com", ttl=1)))

    import time as time_module

    real_time = time_module.time
    monkeypatch.setattr(dns_server.time, "time", lambda: real_time() + 5)

    def always_fails(data, upstream, timeout):
        raise ConnectionError("upstream unreachable")

    monkeypatch.setattr(dns_server.upstream_transport, "forward", always_fails)

    response = resolver.resolve(DNSRecord.question("stale.example.com", qtype="A"), None)

    assert response.header.rcode == RCODE.NOERROR
    assert any(str(rr.rdata) == "5.6.7.8" for rr in response.rr)


def test_serve_stale_disabled_returns_servfail(config_store, tmp_path, monkeypatch):
    config_store.mutate(lambda d: d.setdefault("dns", {}).update({"cache_serve_stale_enabled": False}))
    cache = DNSCache(config_store)
    resolver = _resolver(config_store, tmp_path, cache=cache)

    request = DNSRecord.question("stale2.example.com", qtype="A")
    cache.put(request, DNSRecord.parse(_plain_response("stale2.example.com", ttl=1)))

    import time as time_module

    real_time = time_module.time
    monkeypatch.setattr(dns_server.time, "time", lambda: real_time() + 5)

    def always_fails(data, upstream, timeout):
        raise ConnectionError("upstream unreachable")

    monkeypatch.setattr(dns_server.upstream_transport, "forward", always_fails)

    response = resolver.resolve(DNSRecord.question("stale2.example.com", qtype="A"), None)

    assert response.header.rcode == RCODE.SERVFAIL


def test_prefetch_refreshes_hot_near_expiry_entries(config_store, tmp_path, monkeypatch):
    config_store.mutate(
        lambda d: d.setdefault("dns", {}).update(
            {"cache_prefetch_enabled": True, "cache_prefetch_before_expiry_seconds": 3600, "cache_prefetch_min_hits": 1}
        )
    )
    cache = DNSCache(config_store)
    resolver = _resolver(config_store, tmp_path, cache=cache)

    request = DNSRecord.question("hot.example.com", qtype="A")
    cache.put(request, DNSRecord.parse(_plain_response("hot.example.com", ip="1.1.1.1", ttl=60)))
    cache.get(request)

    fresh = _plain_response("hot.example.com", ip="9.9.9.9", ttl=60)
    monkeypatch.setattr(dns_server.upstream_transport, "forward", lambda data, upstream, timeout: fresh)

    resolver.maintain_cache()

    import time as time_module

    for _ in range(50):
        if not cache.expiring_soon(3600, 1):
            break
        time_module.sleep(0.02)

    refreshed = cache.get(request)
    assert any(str(rr.rdata) == "9.9.9.9" for rr in refreshed.rr)


def test_random_strategy_shuffles_upstreams(config_store, tmp_path, monkeypatch):
    config_store.mutate(
        lambda d: d.setdefault("dns", {}).update(
            {"upstream_strategy": "random", "upstreams": ["1.1.1.1:53", "9.9.9.9:53", "8.8.8.8:53"]}
        )
    )
    resolver = _resolver(config_store, tmp_path)

    called_with = []
    real_shuffle = random.shuffle

    def spy_shuffle(seq):
        called_with.append(list(seq))
        real_shuffle(seq)

    monkeypatch.setattr(dns_server.random, "shuffle", spy_shuffle)
    monkeypatch.setattr(
        dns_server.upstream_transport, "forward", lambda data, upstream, timeout: _plain_response("x.example.com")
    )

    resolver.resolve(DNSRecord.question("x.example.com", qtype="A"), None)

    assert len(called_with) == 1
    assert sorted(called_with[0]) == ["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"]


def test_case_randomization_scrambles_outgoing_qname(config_store, tmp_path, monkeypatch):
    config_store.mutate(lambda d: d.setdefault("dns", {}).update({"query_case_randomization_enabled": True}))
    resolver = _resolver(config_store, tmp_path)

    request = DNSRecord.question("verification.example.com", qtype="A")
    seen_qnames = set()
    for _ in range(20):
        data = resolver._prepare_upstream_data(request)
        seen_qnames.add(str(DNSRecord.parse(data).q.qname))

    assert len(seen_qnames) > 1
    assert all(q.lower() == "verification.example.com." for q in seen_qnames)


def test_query_acl_refuses_public_client_by_default(config_store, tmp_path, monkeypatch):
    resolver = _resolver(config_store, tmp_path)
    monkeypatch.setattr(
        dns_server.upstream_transport, "forward", lambda data, upstream, timeout: _plain_response("public.example.com")
    )

    request = DNSRecord.question("public.example.com", qtype="A")
    response = resolver.resolve(request, _FakeHandler("203.0.113.7"))

    assert response.header.rcode == RCODE.REFUSED
    assert not response.rr


def test_query_acl_allows_private_client_by_default(config_store, tmp_path, monkeypatch):
    resolver = _resolver(config_store, tmp_path)
    monkeypatch.setattr(
        dns_server.upstream_transport, "forward", lambda data, upstream, timeout: _plain_response("lan.example.com")
    )

    request = DNSRecord.question("lan.example.com", qtype="A")
    response = resolver.resolve(request, _FakeHandler("192.168.1.50"))

    assert response.header.rcode == RCODE.NOERROR
    assert any(rr.rtype == QTYPE.A for rr in response.rr)


def test_query_acl_allows_extra_configured_network(config_store, tmp_path, monkeypatch):
    config_store.mutate(
        lambda d: d.setdefault("dns", {}).update({"query_acl_extra_networks": ["203.0.113.0/24"]})
    )
    resolver = _resolver(config_store, tmp_path)
    monkeypatch.setattr(
        dns_server.upstream_transport, "forward", lambda data, upstream, timeout: _plain_response("vpn.example.com")
    )

    request = DNSRecord.question("vpn.example.com", qtype="A")
    response = resolver.resolve(request, _FakeHandler("203.0.113.7"))

    assert response.header.rcode == RCODE.NOERROR


def test_query_acl_disabled_allows_any_client(config_store, tmp_path, monkeypatch):
    config_store.mutate(lambda d: d.setdefault("dns", {}).update({"query_acl_enabled": False}))
    resolver = _resolver(config_store, tmp_path)
    monkeypatch.setattr(
        dns_server.upstream_transport, "forward", lambda data, upstream, timeout: _plain_response("open.example.com")
    )

    request = DNSRecord.question("open.example.com", qtype="A")
    response = resolver.resolve(request, _FakeHandler("203.0.113.7"))

    assert response.header.rcode == RCODE.NOERROR


def test_query_acl_allows_when_handler_is_none(config_store, tmp_path, monkeypatch):
    resolver = _resolver(config_store, tmp_path)
    monkeypatch.setattr(
        dns_server.upstream_transport, "forward", lambda data, upstream, timeout: _plain_response("internal.example.com")
    )

    request = DNSRecord.question("internal.example.com", qtype="A")
    response = resolver.resolve(request, None)

    assert response.header.rcode == RCODE.NOERROR


def test_dns_rebinding_blocked_by_default(config_store, tmp_path, monkeypatch):
    resolver = _resolver(config_store, tmp_path)
    monkeypatch.setattr(
        dns_server.upstream_transport, "forward", lambda data, upstream, timeout: _plain_response("localtest.me", "127.0.0.1")
    )

    request = DNSRecord.question("localtest.me", qtype="A")
    response = resolver.resolve(request, _FakeHandler("10.0.0.5"))

    assert response.header.rcode == RCODE.NXDOMAIN
    assert not any(rr.rtype == QTYPE.A for rr in response.rr)
