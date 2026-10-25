# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

import pytest

from app.blocklist import BlocklistManager
from app.dns_server import FilteringResolver
from app.netmatch import best_matching_group, pattern_specificity


def _group(name, *match, **extra):
    return {"name": name, "match": list(match), "enabled": True, **extra}


def _winner(groups, ip, mac=None, hostname=None):
    group = best_matching_group(groups, ip, mac=mac, hostname=hostname)
    return group["name"] if group else None


def test_specificity_ranks_single_hosts_above_ranges_and_longer_prefixes_above_shorter():
    order = [
        "10.0.0.0/8",
        "10.1.0.0/16",
        "10.1.2.0/24",
        "10.1.2.0/28",
        "host:*.lan",
        "host:*.kids.lan",
        "host:tablet.kids.lan",
        "mac:AA:BB:CC:DD:EE:FF",
        "10.1.2.3/32",
        "10.1.2.3",
    ]
    ranks = [pattern_specificity(p) for p in order]

    assert ranks == sorted(ranks)
    assert len(set(ranks)) == len(ranks) - 1
    assert ranks[-1] == ranks[-2]
    assert pattern_specificity("2001:db8::/32") < pattern_specificity("2001:db8::/64") < pattern_specificity("2001:db8::1")
    assert pattern_specificity("2001:db8::1/128") == pattern_specificity("2001:db8::1")


def test_a_smaller_range_beats_a_larger_one_whatever_the_list_order():
    groups = [_group("Wide", "192.168.0.0/16"), _group("Mid", "192.168.1.0/24"), _group("Narrow", "192.168.1.0/28")]

    assert _winner(groups, "192.168.1.5") == "Narrow"
    assert _winner(groups, "192.168.1.200") == "Mid"
    assert _winner(groups, "192.168.7.7") == "Wide"
    assert _winner(list(reversed(groups)), "192.168.1.5") == "Narrow"


def test_an_individual_host_beats_the_pool_it_sits_in_even_when_listed_after_it():
    groups = [_group("Pool", "192.168.1.0/24"), _group("Laptop", "192.168.1.50")]

    assert _winner(groups, "192.168.1.50") == "Laptop"
    assert _winner(groups, "192.168.1.51") == "Pool"


def test_a_slash_32_counts_as_an_individual_host():
    groups = [_group("Pool", "10.0.0.0/8"), _group("One", "10.9.9.9/32")]

    assert _winner(groups, "10.9.9.9") == "One"


def test_mac_and_hostname_patterns_are_individual_settings_too():
    groups = [
        _group("Pool", "192.168.1.0/24"),
        _group("Suffix", "host:*.lan"),
        _group("ByName", "host:tablet.lan"),
        _group("ByMac", "mac:aa:bb:cc:dd:ee:ff"),
    ]

    assert _winner(groups, "192.168.1.9") == "Pool"
    assert _winner(groups, "192.168.1.9", hostname="phone.lan") == "Suffix"
    assert _winner(groups, "192.168.1.9", hostname="tablet.lan") == "ByName"
    assert _winner(groups, "192.168.1.9", mac="AA:BB:CC:DD:EE:FF") == "ByMac"
    assert _winner(groups, "172.16.0.1", hostname="phone.lan") == "Suffix"
    assert _winner(groups, "172.16.0.1") is None


def test_longer_hostname_suffix_beats_shorter():
    groups = [_group("Lan", "host:*.lan"), _group("Kids", "host:*.kids.lan")]

    assert _winner(groups, "10.0.0.1", hostname="x.kids.lan") == "Kids"
    assert _winner(groups, "10.0.0.1", hostname="x.lan") == "Lan"


def test_a_group_matching_through_several_patterns_competes_with_its_best_one():
    groups = [_group("Pool", "192.168.1.0/24"), _group("Mixed", "192.168.0.0/16", "192.168.1.50")]

    assert _winner(groups, "192.168.1.50") == "Mixed"
    assert _winner(groups, "192.168.1.51") == "Pool"
    assert _winner(groups, "192.168.9.9") == "Mixed"


def test_equally_specific_groups_fall_back_to_list_order_and_no_match_gives_none():
    groups = [_group("First", "10.0.0.0/24"), _group("Second", "10.0.0.0/24")]

    assert _winner(groups, "10.0.0.5") == "First"
    assert _winner(groups, "11.0.0.5") is None
    assert _winner([], "10.0.0.5") is None


def test_ipv6_ranges_follow_the_same_rule():
    groups = [_group("Site", "2001:db8::/32"), _group("Subnet", "2001:db8:1::/48"), _group("Host", "2001:db8:1::5")]

    assert _winner(groups, "2001:db8:1::5") == "Host"
    assert _winner(groups, "2001:db8:1::6") == "Subnet"
    assert _winner(groups, "2001:db8:2::1") == "Site"


@pytest.fixture
def manager(config_store, tmp_path):
    config_store.mutate(
        lambda d: d.update(
            {
                "denylist": ["global-blocked.example"],
                "client_groups": [
                    _group("Pool", "192.168.1.0/24", denylist=["pool-blocked.example"], upstreams=["9.9.9.9:53"]),
                    _group("Laptop", "192.168.1.50", denylist=["laptop-blocked.example"]),
                    _group("Open", "192.168.1.60", enabled=False),
                    _group("Strict", "192.168.1.64/28", denylist=["strict-blocked.example"]),
                ],
            }
        )
    )
    return BlocklistManager(config_store, tmp_path / "cache")


def test_default_group_and_individual_settings_apply_in_that_order_of_importance(manager):
    assert manager.block_reason("global-blocked.example", "10.9.9.9") is not None
    assert manager.block_reason("pool-blocked.example", "10.9.9.9") is None

    assert manager.block_reason("pool-blocked.example", "192.168.1.7") is not None
    assert manager.block_reason("global-blocked.example", "192.168.1.7") is not None

    assert manager.block_reason("laptop-blocked.example", "192.168.1.50") is not None
    assert manager.block_reason("pool-blocked.example", "192.168.1.50") is None
    assert manager.block_reason("laptop-blocked.example", "192.168.1.7") is None


def test_an_individual_host_inherits_nothing_from_the_pool(manager):
    assert manager.group_name_for("192.168.1.50") == "Laptop"
    assert manager.group_name_for("192.168.1.7") == "Pool"
    assert manager.group_name_for("10.9.9.9") is None
    assert manager.group_name_for("192.168.1.66") == "Strict"


def test_a_host_can_be_filtered_while_its_pool_is_not_and_the_reverse(config_store, manager):
    config_store.mutate(
        lambda d: d.update(
            {
                "client_groups": [
                    _group("Pool", "192.168.1.0/24", enabled=False),
                    _group("Strict", "192.168.1.50", enabled=True, denylist=["bad.example"]),
                ]
            }
        )
    )

    assert manager.block_reason("bad.example", "192.168.1.50") is not None
    assert manager.block_reason("bad.example", "192.168.1.51") is None


def test_the_individual_hosts_safe_search_setting_overrides_the_pools(config_store, manager):
    config_store.mutate(
        lambda d: d.update(
            {
                "client_groups": [
                    _group("Pool", "192.168.1.0/24", safe_search=True),
                    _group("Host", "192.168.1.50", safe_search=False),
                ]
            }
        )
    )

    assert manager.safe_search_enabled_for("192.168.1.7") is True
    assert manager.safe_search_enabled_for("192.168.1.50") is False
    assert manager.safe_search_enabled_for("10.0.0.1") is False


def test_upstream_override_follows_the_most_specific_group(config_store, manager):
    config_store.mutate(
        lambda d: d.update(
            {
                "dns": {"upstreams": ["1.1.1.1:53"]},
                "client_groups": [
                    _group("Pool", "192.168.1.0/24", upstreams=["9.9.9.9:53"]),
                    _group("Host", "192.168.1.50", upstreams=["8.8.8.8:53"]),
                    _group("Plain", "192.168.1.60"),
                ],
            }
        )
    )
    resolver = FilteringResolver(manager, None, config_store)

    assert resolver._select_upstreams("example.com", "192.168.1.7") == ["9.9.9.9:53"]
    assert resolver._select_upstreams("example.com", "192.168.1.50") == ["8.8.8.8:53"]
    assert resolver._select_upstreams("example.com", "192.168.1.60") == ["1.1.1.1:53"]
    assert resolver._select_upstreams("example.com", "10.0.0.1") == ["1.1.1.1:53"]
