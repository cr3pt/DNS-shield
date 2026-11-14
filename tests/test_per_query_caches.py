# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Values every DNS query asks for are worked out once per config version."""

from app import blocklist as blocklist_module
from app.blocklist import BlocklistManager
from app.upstream import matches_domain_or_parent, protected_hostnames


def test_matches_domain_or_parent():
    names = frozenset({"example.com", "dns.quad9.net"})
    assert matches_domain_or_parent("example.com", names)
    assert matches_domain_or_parent("a.b.example.com", names)
    assert not matches_domain_or_parent("badexample.com", names)
    assert not matches_domain_or_parent("com", names)
    assert not matches_domain_or_parent("quad9.net", names)


def test_protected_hostnames_follow_config_changes(config_store):
    config_store.mutate(lambda d: d.setdefault("dns", {}).update({"upstreams": ["dot://dns.quad9.net"]}))
    first = protected_hostnames(config_store)
    assert "dns.quad9.net" in first
    assert protected_hostnames(config_store) is first  # cached for this version
    config_store.mutate(lambda d: d["dns"].update({"upstreams": ["dot://one.one.one.one"]}))
    second = protected_hostnames(config_store)
    assert "one.one.one.one" in second and "dns.quad9.net" not in second


def test_client_group_is_looked_up_once_per_config_version(config_store, tmp_path, monkeypatch):
    config_store.mutate(lambda d: d.update({"client_groups": [{"name": "kids", "match": ["10.0.0.5"]}]}))
    manager = BlocklistManager(config_store, tmp_path / "bl")
    calls = []
    real = blocklist_module.best_matching_group

    def counting(*args, **kwargs):
        calls.append(args[1])
        return real(*args, **kwargs)

    monkeypatch.setattr(blocklist_module, "best_matching_group", counting)
    for _ in range(3):
        manager.block_reason("example.com", "10.0.0.5")
        manager.safe_search_enabled_for("10.0.0.5")
        assert manager.group_for("10.0.0.5")["name"] == "kids"
    assert calls == ["10.0.0.5"]

    config_store.mutate(lambda d: d.update({"client_groups": [{"name": "guests", "match": ["10.0.0.5"]}]}))
    assert manager.group_for("10.0.0.5")["name"] == "guests"
    assert len(calls) == 2
