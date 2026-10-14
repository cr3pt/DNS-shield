# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from app.blocklist import BlocklistManager, describe_format, describe_ip_format, parse_ip_list, parse_list


def test_plain_domain_list():
    domains, formats, exceptions = parse_list("ads.example.com\ntrack.example.org\n")
    assert domains == {"ads.example.com", "track.example.org"}
    assert formats == {"plain": 2}
    assert exceptions == set()


def test_hosts_file_format():
    text = "0.0.0.0 ads.example.com\n127.0.0.1 track.example.org\n"
    domains, formats, exceptions = parse_list(text)
    assert domains == {"ads.example.com", "track.example.org"}
    assert formats == {"hosts": 2}


def test_adblock_and_exception_format():
    text = "||ads.example.com^\n@@||safe.example.com^\n"
    domains, formats, exceptions = parse_list(text)
    assert domains == {"ads.example.com"}
    assert exceptions == {"safe.example.com"}
    assert formats == {"adblock": 1, "adblock_exception": 1}


def test_comments_and_blank_lines_are_skipped():
    text = "# comment\n! also a comment\n; also a comment\n\nads.example.com\n"
    domains, formats, _ = parse_list(text)
    assert domains == {"ads.example.com"}
    assert formats == {"plain": 1}


def test_localhost_variants_are_filtered_out():
    text = "0.0.0.0 localhost\n0.0.0.0 local\n0.0.0.0 broadcasthost\n0.0.0.0 real.example.com\n"
    domains, _, _ = parse_list(text)
    assert domains == {"real.example.com"}


def test_malformed_lines_are_ignored():
    text = "not a valid domain!!\n||\nads.example.com\n"
    domains, _, _ = parse_list(text)
    assert domains == {"ads.example.com"}


def test_describe_format_single_and_mixed():
    assert describe_format({}) == "unknown"
    assert describe_format({"plain": 10}) == "plain domain list"
    assert "mixed formats" in describe_format({"plain": 5, "hosts": 5})


def test_parse_ip_list_ip_and_cidr():
    text = "1.2.3.4\n10.0.0.0/8\n# comment\nnot-an-ip\n"
    entries, formats, exceptions = parse_ip_list(text)
    assert entries == {"1.2.3.4", "10.0.0.0/8"}
    assert formats == {"ip": 1, "cidr": 1}
    assert exceptions == set()


def test_parse_ip_list_ipv6():
    entries, formats, _ = parse_ip_list("2001:db8::1\n2001:db8::/32\n")
    assert entries == {"2001:db8::1", "2001:db8::/32"}
    assert formats == {"ip": 1, "cidr": 1}


def test_describe_ip_format():
    assert describe_ip_format({}) == "unknown"
    assert describe_ip_format({"ip": 3}) == "IP list"
    assert describe_ip_format({"ip": 1, "cidr": 1}) == "mixed (IP list + CIDR list)"


def test_exception_only_cancels_the_block_from_its_own_source(config_store, tmp_path):
    cache_dir = tmp_path / "blocklist_cache"
    cache_dir.mkdir()
    (cache_dir / "ListA.cache").write_text("ads.example.com\n", encoding="utf-8")
    (cache_dir / "ListB.cache").write_text("@@||ads.example.com^\n", encoding="utf-8")

    config_store.mutate(
        lambda d: d.setdefault("blocklists", {}).update(
            {
                "sources": [
                    {"name": "ListA", "url": "https://a.example/list.txt", "enabled": True},
                    {"name": "ListB", "url": "https://b.example/list.txt", "enabled": True},
                ]
            }
        )
    )

    blocklist = BlocklistManager(config_store, cache_dir)
    blocklist.refresh(network=False)

    assert blocklist.is_blocked("ads.example.com")


def test_exception_cancels_a_block_from_the_same_source(config_store, tmp_path):
    cache_dir = tmp_path / "blocklist_cache"
    cache_dir.mkdir()
    (cache_dir / "ListA.cache").write_text("||ads.example.com^\n@@||ads.example.com^\n", encoding="utf-8")

    config_store.mutate(
        lambda d: d.setdefault("blocklists", {}).update(
            {"sources": [{"name": "ListA", "url": "https://a.example/list.txt", "enabled": True}]}
        )
    )

    blocklist = BlocklistManager(config_store, cache_dir)
    blocklist.refresh(network=False)

    assert not blocklist.is_blocked("ads.example.com")
