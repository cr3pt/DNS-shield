# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from dnslib import RR, DNSRecord
from fastapi.testclient import TestClient

from app import upstream as upstream_transport
from app.blocklist import BlocklistManager
from app.dns_cache import DNSCache
from app.dns_server import FilteringResolver
from app.domain_suffix import rule_domains
from app.stats import Stats
from app.web.server import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, create_app


def _resolver(config_store, tmp_path, rules, default=("1.1.1.1:53",)):
    config_store.mutate(lambda d: d.update({"dns": {"upstreams": list(default)}, "domain_upstreams": rules}))
    return FilteringResolver(BlocklistManager(config_store, tmp_path / "cache"), None, config_store)


def test_rule_domains_typed_loosely_still_match_queries(config_store, tmp_path):
    resolver = _resolver(
        config_store,
        tmp_path,
        [
            {"name": "a", "domains": ["A.pl."], "upstreams": ["10.0.0.1:53"]},
            {"name": "b", "domains": [" *.b.pl "], "upstreams": ["10.0.0.2:53"]},
            {"name": "c", "domains": "c.pl, d.pl", "upstreams": ["10.0.0.3:53"]},
            {"name": "e", "domain": "e.pl", "upstreams": ["10.0.0.4:53"]},
        ],
    )

    assert resolver._select_upstreams("a.pl", "192.168.1.5") == ["10.0.0.1:53"]
    assert resolver._select_upstreams("www.a.pl", "192.168.1.5") == ["10.0.0.1:53"]
    assert resolver._select_upstreams("b.pl", "192.168.1.5") == ["10.0.0.2:53"]
    assert resolver._select_upstreams("x.d.pl", "192.168.1.5") == ["10.0.0.3:53"]
    assert resolver._select_upstreams("e.pl", "192.168.1.5") == ["10.0.0.4:53"]
    assert resolver._select_upstreams("aa.pl", "192.168.1.5") == ["1.1.1.1:53"]
    assert resolver._select_upstreams("example.com", "192.168.1.5") == ["1.1.1.1:53"]


def test_the_most_specific_domain_rule_wins_whatever_the_order(config_store, tmp_path):
    resolver = _resolver(
        config_store,
        tmp_path,
        [
            {"name": "pl", "domains": ["pl"], "upstreams": ["10.0.0.9:53"]},
            {"name": "a", "domains": ["a.pl"], "upstreams": ["10.0.0.1:53"]},
        ],
    )

    assert resolver._select_upstreams("host.a.pl", "192.168.1.5") == ["10.0.0.1:53"]
    assert resolver._select_upstreams("other.pl", "192.168.1.5") == ["10.0.0.9:53"]


def test_a_rule_whose_upstreams_are_all_disabled_is_skipped(config_store, tmp_path):
    resolver = _resolver(config_store, tmp_path, [{"name": "a", "domains": ["a.pl"], "upstreams": ["#10.0.0.1:53"]}])

    assert resolver._select_upstreams("a.pl", "192.168.1.5") == ["1.1.1.1:53"]


def test_dnssec_validation_lookups_for_the_domain_go_to_its_own_upstream(config_store, tmp_path, monkeypatch):
    resolver = _resolver(config_store, tmp_path, [{"name": "a", "domains": ["a.pl"], "upstreams": ["10.0.0.1:53"]}])
    sent = []

    def fake_forward(data, upstream, timeout):
        sent.append((str(DNSRecord.parse(data).q.qname), upstream))
        return DNSRecord.parse(data).reply().pack()

    monkeypatch.setattr(upstream_transport, "forward", fake_forward)

    resolver._validation_forward(DNSRecord.question("a.pl", "DNSKEY").pack())
    resolver._validation_forward(DNSRecord.question("www.a.pl", "DS").pack())
    resolver._validation_forward(DNSRecord.question("pl", "DNSKEY").pack())

    assert sent == [("a.pl.", "10.0.0.1:53"), ("www.a.pl.", "10.0.0.1:53"), ("pl.", "1.1.1.1:53")]


def _admin_client(config_store, tmp_path, cache):
    config_store.mutate(lambda d: d.setdefault("web", {}).update({"https_enabled": False}))
    blocklist = BlocklistManager(config_store, tmp_path / "cache")
    stats = Stats(tmp_path / "stats.db", config_store)
    app = create_app(config_store, blocklist, stats, started_at=0.0, cache=cache, data_dir=tmp_path)
    client = TestClient(app)
    response = client.post("/api/login", json={"username": "admin", "password": "changeme"})
    assert response.status_code == 200
    client.headers[CSRF_HEADER_NAME] = client.cookies[CSRF_COOKIE_NAME]
    return client


def test_adding_a_rule_normalizes_domains_and_drops_answers_cached_from_the_old_upstream(config_store, tmp_path):
    cache = DNSCache(config_store)
    client = _admin_client(config_store, tmp_path, cache)
    request = DNSRecord.question("www.a.pl", "A")
    reply = request.reply()
    reply.add_answer(*RR.fromZone("www.a.pl. 300 A 203.0.113.7"))
    cache.put(request, reply)
    assert cache.get(request) is not None

    response = client.post(
        "/api/domain-upstreams",
        json={"name": "a", "domains": ["*.A.pl.", "a.pl"], "upstreams": [" 10.0.0.1:53 "]},
    )

    assert response.status_code == 200
    rule = response.json()[-1]
    assert rule["domains"] == ["a.pl"]
    assert rule["upstreams"] == ["10.0.0.1:53"]
    assert cache.get(request) is None
    assert rule_domains(rule) == ["a.pl"]


def test_a_rule_with_an_invalid_domain_is_refused(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path, None)

    response = client.post(
        "/api/domain-upstreams", json={"name": "x", "domains": ["not a domain"], "upstreams": ["10.0.0.1:53"]}
    )

    assert response.status_code == 422
