# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""One client query spends a bounded time on upstreams, whatever the number
of dead upstreams, and still gets an answer (stale cache or SERVFAIL)."""

from dnslib import RCODE, DNSRecord

from app import dns_server
from app.blocklist import BlocklistManager
from app.dns_server import FilteringResolver


class _NullStats:
    def record(self, *args, **kwargs):
        pass


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now


def _resolver(config_store, tmp_path):
    return FilteringResolver(BlocklistManager(config_store, tmp_path / "bl"), _NullStats(), config_store)


def test_in_order_stops_when_total_budget_is_used_up(config_store, tmp_path, monkeypatch):
    config_store.mutate(
        lambda d: d.setdefault("dns", {}).update(
            {
                "upstreams": ["192.0.2.1:53", "192.0.2.2:53", "192.0.2.3:53", "192.0.2.4:53"],
                "upstream_timeout_seconds": 2.0,
                "upstream_total_timeout_seconds": 5.0,
                "upstream_strategy": "in_order",
            }
        )
    )
    clock = _Clock()
    monkeypatch.setattr(dns_server.time, "monotonic", clock.monotonic)
    tried = []

    def hangs_until_timeout(data, upstream, timeout):
        tried.append((upstream, timeout))
        clock.now += timeout
        raise TimeoutError("timed out")

    monkeypatch.setattr(dns_server.upstream_transport, "forward", hangs_until_timeout)
    response = _resolver(config_store, tmp_path).resolve(DNSRecord.question("example.com", "A"), None)

    assert response.header.rcode == RCODE.SERVFAIL
    # 2 s + 2 s + the 1 s left; the fourth upstream is never asked.
    assert tried == [("192.0.2.1:53", 2.0), ("192.0.2.2:53", 2.0), ("192.0.2.3:53", 1.0)]


def test_budget_is_never_shorter_than_one_attempt(config_store, tmp_path, monkeypatch):
    config_store.mutate(
        lambda d: d.setdefault("dns", {}).update(
            {"upstreams": ["192.0.2.1:53"], "upstream_timeout_seconds": 8.0, "upstream_total_timeout_seconds": 5.0}
        )
    )
    monkeypatch.setattr(dns_server.time, "monotonic", _Clock().monotonic)
    seen = []

    def fails(data, upstream, timeout):
        seen.append(timeout)
        raise TimeoutError("timed out")

    monkeypatch.setattr(dns_server.upstream_transport, "forward", fails)
    _resolver(config_store, tmp_path).resolve(DNSRecord.question("example.com", "A"), None)
    assert seen == [8.0]


def test_race_does_not_wait_past_the_deadline_for_a_stuck_worker(config_store, tmp_path, monkeypatch):
    import threading
    import time

    config_store.mutate(
        lambda d: d.setdefault("dns", {}).update(
            {
                "upstreams": ["192.0.2.1:53", "192.0.2.2:53"],
                "upstream_timeout_seconds": 0.2,
                "upstream_total_timeout_seconds": 0.2,
                "upstream_strategy": "race",
            }
        )
    )
    release = threading.Event()

    def ignores_its_timeout(data, upstream, timeout):
        release.wait(10)
        raise TimeoutError("released")

    monkeypatch.setattr(dns_server.upstream_transport, "forward", ignores_its_timeout)
    start = time.monotonic()
    try:
        response = _resolver(config_store, tmp_path).resolve(DNSRecord.question("example.com", "A"), None)
    finally:
        release.set()
    assert response.header.rcode == RCODE.SERVFAIL
    assert time.monotonic() - start < 3.0
