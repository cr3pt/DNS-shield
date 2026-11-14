# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Dashboard totals, top lists and charts come from the hourly aggregate and
must match what the raw query log says."""

import sqlite3
import time

from app.stats import Stats
from tests.test_stats import _wait_for


def _stats(tmp_path, config_store):
    return Stats(tmp_path / "stats.db", config_store, flush_interval=0.05)


def _log(stats, rows):
    for domain, blocked, client, reason in rows:
        stats.record(domain, blocked, client, "A", reason=reason)
    assert _wait_for(lambda: stats.max_query_id() >= len(rows))


_ROWS = [
    ("a.com", False, "10.0.0.1", None),
    ("a.com", False, "10.0.0.1", None),
    ("a.com", False, "10.0.0.2", None),
    ("ads.com", True, "10.0.0.1", "blocklist"),
    ("ads.com", True, "10.0.0.2", "blocklist"),
    ("evil.com", True, "10.0.0.2", "regex"),
]


def test_snapshot_counts_come_from_the_aggregate(tmp_path, config_store):
    stats = _stats(tmp_path, config_store)
    _log(stats, _ROWS)
    snap = stats.snapshot(top_n=10, log_n=3)
    assert snap["total_queries"] == 6 and snap["blocked_queries"] == 3
    assert snap["top_domains"][0] == ["a.com", 3]
    assert snap["top_blocked_domains"][0] == ["ads.com", 2]
    assert dict(map(tuple, snap["top_clients"])) == {"10.0.0.1": 3, "10.0.0.2": 3}
    assert dict(map(tuple, snap["block_reasons"])) == {"blocklist": 2, "regex": 1}
    assert len(snap["recent_queries"]) == 3
    assert stats.total_count() == 6 and stats.blocked_count() == 3

    only_two = stats.snapshot(top_n=10, log_n=0, client_ips=["10.0.0.2"])
    assert only_two["total_queries"] == 3 and only_two["blocked_queries"] == 2
    assert stats.snapshot(client_ips=[])["total_queries"] == 0


def test_timeseries_puts_this_hour_in_the_last_bucket(tmp_path, config_store):
    stats = _stats(tmp_path, config_store)
    _log(stats, _ROWS)
    series = stats.timeseries("24h")
    assert len(series) == 24
    assert series[-1]["total"] == 6 and series[-1]["blocked"] == 3
    assert series[-1]["bucket_start"] == int(time.time() // 3600) * 3600
    assert sum(b["total"] for b in series[:-1]) == 0
    assert stats.timeseries("7d", client_ips=["10.0.0.1"])[-1]["total"] == 3


def test_clear_and_prune_keep_the_aggregate_in_step(tmp_path, config_store):
    stats = _stats(tmp_path, config_store)
    _log(stats, _ROWS)
    config_store.mutate(lambda d: d.setdefault("logging", {}).update({"retention_days": -1}))
    stats._prune()
    assert stats.snapshot()["total_queries"] == 0
    _log(stats, _ROWS[:1])
    stats.clear()
    assert stats.total_count() == 0


def test_existing_query_log_is_backfilled_once(tmp_path, config_store):
    db = tmp_path / "stats.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE queries (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, domain TEXT NOT NULL, "
        "qtype TEXT NOT NULL, client TEXT NOT NULL, blocked INTEGER NOT NULL)"
    )
    now = time.time()
    conn.executemany(
        "INSERT INTO queries (ts, domain, qtype, client, blocked) VALUES (?, ?, 'A', ?, ?)",
        [(now, "a.com", "10.0.0.1", 0), (now, "a.com", "10.0.0.1", 0), (now - 7200, "b.com", "10.0.0.1", 1)],
    )
    conn.commit()
    conn.close()

    stats = Stats(db, config_store, flush_interval=0.05)
    assert stats.total_count() == 3 and stats.blocked_count() == 1
    assert stats.snapshot()["top_domains"][0] == ["a.com", 2]
    # a second start (or another DNS worker process) doesn't count them again
    again = Stats(db, config_store, flush_interval=0.05)
    assert again.total_count() == 3
    assert again.distinct_clients() == ["10.0.0.1"]


def test_known_clients_come_from_their_own_table(tmp_path, config_store):
    stats = _stats(tmp_path, config_store)
    _log(stats, _ROWS)
    assert sorted(stats.distinct_clients()) == ["10.0.0.1", "10.0.0.2"]
    with sqlite3.connect(tmp_path / "stats.db") as conn:
        conn.execute("UPDATE query_clients SET last_seen = 0 WHERE client = '10.0.0.1'")
    stats._prune()  # 30-day retention: only the long-silent client goes
    assert stats.distinct_clients() == ["10.0.0.2"]
    stats.clear()
    assert stats.distinct_clients() == []


def test_query_log_has_a_client_time_index(tmp_path, config_store):
    _stats(tmp_path, config_store)
    with sqlite3.connect(tmp_path / "stats.db") as conn:
        plan = " ".join(
            row[3]
            for row in conn.execute(
                "EXPLAIN QUERY PLAN SELECT DISTINCT domain FROM queries WHERE client = ? AND ts >= ? AND ts < ?",
                ("10.0.0.1", 0, 1),
            )
        )
    assert "idx_queries_client_ts" in plan
