# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Blocklist hosts are resolved through the upstreams, not the system
resolver: on a box that uses DNS-shield as its own DNS, the system answer for
a list host can be DNS-shield's own block address (e.g. a block page on
203.0.113.250), which the SSRF check then rightly refuses."""

import socket

import pytest
from dnslib import AAAA, QTYPE, RR, A, DNSRecord

import app.url_safety as url_safety
from app import upstream as upstream_mod
from app.blocklist import BlocklistManager
from app.upstream import protected_hostnames, resolve_direct
from app.url_safety import check_public_url, public_dns_guard

SINKHOLE_V4 = "203.0.113.250"
SINKHOLE_V6 = "2001:db8:1000::fa"
REAL_V4 = "57.128.255.167"
REAL_V6 = "2001:41d0:601:1100::8a86"


def _fake_upstream(answers: dict[str, list[str]], asked: list | None = None):
    def forward(data, upstream, timeout):
        query = DNSRecord.parse(data)
        if asked is not None:
            asked.append((upstream, QTYPE[query.q.qtype]))
        reply = query.reply()
        for value in answers.get(QTYPE[query.q.qtype], []):
            rdata = A(value) if query.q.qtype == QTYPE.A else AAAA(value)
            reply.add_answer(RR(query.q.qname, query.q.qtype, rdata=rdata, ttl=60))
        return reply.pack()

    return forward


def _system_resolves_to_sinkhole(monkeypatch):
    real = url_safety._real_getaddrinfo

    def fake(host, *args, **kwargs):
        if host == "nsfw.oisd.nl":
            return real(SINKHOLE_V4, *args, **kwargs) + real(SINKHOLE_V6, *args, **kwargs)
        return real(host, *args, **kwargs)

    monkeypatch.setattr(url_safety, "_real_getaddrinfo", fake)
    monkeypatch.setattr(socket, "getaddrinfo", url_safety._guarded_getaddrinfo)


def test_resolve_direct_asks_configured_upstreams(config_store, monkeypatch):
    config_store.mutate(lambda d: d.setdefault("dns", {}).update({"upstreams": ["# 8.8.8.8:53", "9.9.9.9:53"]}))
    asked: list = []
    monkeypatch.setattr(upstream_mod, "forward", _fake_upstream({"A": [REAL_V4], "AAAA": [REAL_V6]}, asked))

    assert resolve_direct("nsfw.oisd.nl", config_store) == [REAL_V4, REAL_V6]
    assert asked == [("9.9.9.9:53", "A"), ("9.9.9.9:53", "AAAA")]


def test_resolve_direct_uses_matching_domain_upstream(config_store, monkeypatch):
    config_store.mutate(lambda d: d.update({"domain_upstreams": [{"domains": ["oisd.nl"], "upstreams": ["5.5.5.5"]}]}))
    asked: list = []
    monkeypatch.setattr(upstream_mod, "forward", _fake_upstream({"A": [REAL_V4]}, asked))

    assert resolve_direct("nsfw.oisd.nl", config_store) == [REAL_V4]
    assert {u for u, _ in asked} == {"5.5.5.5"}


def test_resolve_direct_tries_next_upstream_and_returns_none_when_all_fail(config_store, monkeypatch):
    config_store.mutate(lambda d: d.setdefault("dns", {}).update({"upstreams": ["1.0.0.1", "8.8.8.8"]}))
    calls: list = []

    def failing(data, upstream, timeout):
        calls.append(upstream)
        raise OSError("timed out")

    monkeypatch.setattr(upstream_mod, "forward", failing)
    assert resolve_direct("nsfw.oisd.nl", config_store) is None
    assert calls == ["1.0.0.1", "8.8.8.8"]


def test_check_public_url_prefers_resolver_over_system_lookup(monkeypatch):
    _system_resolves_to_sinkhole(monkeypatch)
    with pytest.raises(ValueError, match="system resolver"):
        check_public_url("https://nsfw.oisd.nl")

    assert check_public_url("https://nsfw.oisd.nl", resolver=lambda h: [REAL_V4, REAL_V6]) == [REAL_V4, REAL_V6]


def test_check_public_url_still_refuses_private_answer_from_upstream():
    with pytest.raises(ValueError, match="upstream DNS servers"):
        check_public_url("https://list.example", resolver=lambda h: ["192.168.1.10"])


def test_check_public_url_falls_back_to_system_when_resolver_has_no_answer():
    with pytest.raises(ValueError, match="system resolver"):
        check_public_url("http://localhost/list.txt", resolver=lambda h: None)


def test_public_dns_guard_pins_vetted_addresses(monkeypatch):
    _system_resolves_to_sinkhole(monkeypatch)
    with public_dns_guard("https://nsfw.oisd.nl", addresses=[REAL_V4]):
        infos = socket.getaddrinfo("nsfw.oisd.nl", 443)
    assert {info[4][0] for info in infos} == {REAL_V4}

    # Outside the block the host is no longer pinned.
    assert REAL_V4 not in {info[4][0] for info in socket.getaddrinfo("nsfw.oisd.nl", 443)}


def test_public_dns_guard_never_pins_private_addresses(monkeypatch):
    with public_dns_guard("http://evil.example/", addresses=["127.0.0.1"]):
        with pytest.raises(socket.gaierror):
            socket.getaddrinfo("evil.example", 80)


def test_blocklist_download_uses_upstream_answer_not_own_block_address(config_store, monkeypatch, tmp_path):
    """The reported bug: the box resolves nsfw.oisd.nl through DNS-shield,
    gets the block address back and the download was refused as SSRF."""
    _system_resolves_to_sinkhole(monkeypatch)
    monkeypatch.setattr(upstream_mod, "forward", _fake_upstream({"A": [REAL_V4], "AAAA": [REAL_V6]}))
    connected_to: list = []

    class FakeResponse:
        status_code = 200
        headers: dict = {}

        def raise_for_status(self):
            pass

        def iter_content(self, chunk_size):
            yield b"0.0.0.0 porn.example\n"

        def close(self):
            pass

    def fake_get(url, **kwargs):
        connected_to.extend(info[4][0] for info in socket.getaddrinfo("nsfw.oisd.nl", 443))
        return FakeResponse()

    monkeypatch.setattr("app.blocklist.requests.get", fake_get)
    manager = BlocklistManager(config_store, tmp_path / "cache")
    assert "porn.example" in manager._download("https://nsfw.oisd.nl")
    assert set(connected_to) == {REAL_V4, REAL_V6}


def test_group_alert_and_answer_ip_source_hosts_are_protected(config_store):
    config_store.mutate(
        lambda d: d.update(
            {
                "client_groups": [{"name": "kids", "blocklist_sources": [{"name": "nsfw", "url": "https://nsfw.oisd.nl"}]}],
                "alert_rules": {"sources": [{"name": "a", "url": "https://alerts.example/list.txt"}]},
                "blocked_answer_ip_sources": [{"name": "ips", "url": "https://ips.example/ips.txt"}],
            }
        )
    )
    protected = protected_hostnames(config_store)
    assert {"nsfw.oisd.nl", "alerts.example", "ips.example"} <= protected
