# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""How fast is a blocklist lookup, and does it depend on the size of the list?

    python scripts/bench_blocklist.py

BlocklistManager checks a query name by looking up the name and each of its
parent domains in a frozenset: a handful of hash lookups per query (one per
label), however many domains are on the lists. A linear scan - `any(name == d
or name.endswith("." + d) for d in domains)` - is shown next to it for
comparison; it grows with the list.
"""

import random
import string
import time

from app.blocklist import BlocklistManager

LIST_SIZES = (1_000, 10_000, 100_000, 1_000_000)
LINEAR_MAX = 100_000
QUERIES = 2_000


def _label(rng: random.Random, length: int) -> str:
    return "".join(rng.choices(string.ascii_lowercase + string.digits, k=length))


def _domain(rng: random.Random) -> str:
    tld = rng.choice(("com", "net", "org", "io"))
    return f"{_label(rng, rng.randint(3, 10))}.{_label(rng, rng.randint(3, 8))}.{tld}"


def _linear(name: str, domains: list[str]) -> bool:
    return any(name == d or name.endswith("." + d) for d in domains)


def main() -> None:
    rng = random.Random(7)
    print(f"{'list size':>10}  {'hash walk':>14}  {'linear scan':>14}")
    for size in LIST_SIZES:
        domains = {_domain(rng) for _ in range(size)}
        frozen = frozenset(domains)
        ordered = list(domains)
        queries = [f"www.{_domain(rng)}" for _ in range(QUERIES)]

        started = time.perf_counter()
        for name in queries:
            BlocklistManager._find_match(name, frozen)
        hash_rate = QUERIES / (time.perf_counter() - started)

        linear_text = "-"
        if size <= LINEAR_MAX:
            sample = queries[: max(20, QUERIES // max(1, size // 1_000))]
            started = time.perf_counter()
            for name in sample:
                _linear(name, ordered)
            linear_text = f"{len(sample) / (time.perf_counter() - started):,.0f}/s"
        print(f"{size:>10,}  {hash_rate:>12,.0f}/s  {linear_text:>14}")


if __name__ == "__main__":
    main()
