# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Blocklist lookups: the right entries match, and the cost doesn't grow with the list.

A name is looked up together with its parent domains in a frozenset (one hash
lookup per label), not scanned against every entry, and not searched for as a
substring (which would make "ads.com" block "roads.com"). See
scripts/bench_blocklist.py for numbers.
"""

import random
import string
import time

from app.blocklist import BlocklistManager

find = BlocklistManager._find_match
find_block = BlocklistManager._find_block_match


def test_exact_name_and_parent_domains_match():
    blocked = frozenset({"example.com", "tracker.example.net"})
    assert find("example.com", blocked) == "example.com"
    assert find("www.example.com", blocked) == "example.com"
    assert find("a.b.c.example.com", blocked) == "example.com"
    assert find("cdn.tracker.example.net", blocked) == "tracker.example.net"


def test_more_specific_entry_wins_over_a_parent():
    blocked = frozenset({"example.com", "ads.example.com"})
    assert find("x.ads.example.com", blocked) == "ads.example.com"


def test_a_domain_is_not_matched_as_a_substring_or_suffix_of_a_label():
    blocked = frozenset({"ads.com", "example.com"})
    assert find("roads.com", blocked) is None
    assert find("notexample.com", blocked) is None
    assert find("example.com.evil.org", blocked) is None
    assert find("ads.com.au", blocked) is None


def test_a_parent_is_not_blocked_by_a_subdomain_entry():
    blocked = frozenset({"ads.example.com"})
    assert find("example.com", blocked) is None
    assert find("www.example.com", blocked) is None


def test_carve_out_skips_an_entry_but_keeps_looking_at_less_specific_ones():
    blocked = frozenset({"example.com", "ads.example.com"})
    carve_outs = {"ads.example.com": frozenset({"ok.ads.example.com"})}
    assert find_block("x.ads.example.com", blocked, carve_outs) == "ads.example.com"
    assert find_block("ok.ads.example.com", blocked, carve_outs) == "example.com"
    assert find_block("www.ok.ads.example.com", blocked, carve_outs) == "example.com"


def _random_domains(count: int, seed: int) -> set[str]:
    rng = random.Random(seed)
    alphabet = string.ascii_lowercase + string.digits
    return {
        f"{''.join(rng.choices(alphabet, k=8))}.{''.join(rng.choices(alphabet, k=6))}.com" for _ in range(count)
    }


def _seconds_per_lookup(domains: frozenset[str], names: list[str]) -> float:
    started = time.perf_counter()
    for name in names:
        find(name, domains)
    return (time.perf_counter() - started) / len(names)


def test_lookup_cost_does_not_grow_with_the_size_of_the_list():
    names = [f"www.{d}" for d in sorted(_random_domains(2_000, seed=1))]
    small = frozenset(_random_domains(2_000, seed=2))
    large = frozenset(_random_domains(200_000, seed=3))

    small_cost = min(_seconds_per_lookup(small, names) for _ in range(3))
    large_cost = min(_seconds_per_lookup(large, names) for _ in range(3))

    # A linear scan would be ~100x slower on the list that is 100x bigger.
    assert large_cost < small_cost * 6
