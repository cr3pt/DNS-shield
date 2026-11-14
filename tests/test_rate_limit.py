# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from dnslib import RCODE, DNSRecord

from app.rate_limit import ClientRateLimiter


class _Config:
    def __init__(self, **dns):
        self.dns = dns

    def get(self, *keys, default=None):
        if keys[0] == "dns" and len(keys) == 2:
            return self.dns.get(keys[1], default)
        return default


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_off_by_default():
    limiter = ClientRateLimiter(_Config())
    assert all(limiter.allow("192.168.1.5") for _ in range(1000))


def test_bucket_refills_over_time():
    clock = _Clock()
    limiter = ClientRateLimiter(_Config(rate_limit_qps=5, rate_limit_burst=10), clock=clock)
    assert all(limiter.allow("192.168.1.5") for _ in range(10))
    assert not limiter.allow("192.168.1.5")
    # Another client has its own bucket.
    assert limiter.allow("192.168.1.6")
    clock.now += 1.0
    assert sum(limiter.allow("192.168.1.5") for _ in range(10)) == 5
    assert limiter.limited_counts()["192.168.1.5"] == 6


def test_default_burst_is_twice_rate_at_least_20():
    limiter = ClientRateLimiter(_Config(rate_limit_qps=1), clock=_Clock())
    assert sum(limiter.allow("10.0.0.1") for _ in range(50)) == 20


def test_loopback_and_exempt_are_never_limited():
    limiter = ClientRateLimiter(_Config(rate_limit_qps=1, rate_limit_burst=1, rate_limit_exempt=["10.0.5.0/24"]), clock=_Clock())
    assert all(limiter.allow("127.0.0.1") for _ in range(50))
    assert all(limiter.allow("::1") for _ in range(50))
    assert all(limiter.allow("10.0.5.7") for _ in range(50))
    assert limiter.allow("10.0.6.7")
    assert not limiter.allow("10.0.6.7")


def test_resolver_refuses_over_limit(config_store, tmp_path):
    from app.blocklist import BlocklistManager
    from app.dns_server import FilteringResolver

    config_store.mutate(lambda d: d.setdefault("dns", {}).update(rate_limit_qps=1, rate_limit_burst=2, upstreams=["127.0.0.1:1"]))
    resolver = FilteringResolver(BlocklistManager(config_store, tmp_path / "bl"), None, config_store)

    class _Handler:
        client_address = ("192.168.1.50", 5353)

    request = DNSRecord.question("example.com")
    resolver._rate_limiter.allow("192.168.1.50")
    resolver._rate_limiter.allow("192.168.1.50")
    reply = resolver.resolve(request, _Handler())
    assert reply.header.rcode == RCODE.REFUSED


def test_settings_reject_bad_exempt(config_store, tmp_path):
    from tests.test_client_groups_api import _admin_client

    client = _admin_client(config_store, tmp_path)
    assert client.patch("/api/settings/dns", json={"rate_limit_exempt": ["nope"]}).status_code == 422
    response = client.patch("/api/settings/dns", json={"rate_limit_qps": 20, "rate_limit_exempt": ["10.0.0.0/8 "]})
    assert response.status_code == 200
    assert config_store.get("dns", "rate_limit_exempt") == ["10.0.0.0/8"]
    assert client.patch("/api/settings/dns", json={"rate_limit_qps": -1}).status_code == 422
