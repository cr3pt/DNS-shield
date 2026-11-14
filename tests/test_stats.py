# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

import time

from app.stats import Stats


def _wait_for(predicate, timeout=2.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def test_distinct_clients_returns_unique_client_ips(tmp_path, config_store):
    stats = Stats(tmp_path / "stats.db", config_store, flush_interval=0.05)
    stats.record("a.example.com", False, "10.0.0.1", "A")
    stats.record("b.example.com", False, "10.0.0.2", "A")
    stats.record("c.example.com", True, "10.0.0.1", "A")

    assert _wait_for(lambda: len(stats.distinct_clients()) >= 2)
    assert sorted(stats.distinct_clients()) == ["10.0.0.1", "10.0.0.2"]


def test_distinct_clients_empty_when_no_queries_logged(tmp_path, config_store):
    stats = Stats(tmp_path / "stats.db", config_store, flush_interval=0.05)
    assert stats.distinct_clients() == []


def test_recent_clients_for_domain_orders_by_most_recent_and_dedupes(tmp_path, config_store):
    stats = Stats(tmp_path / "stats.db", config_store, flush_interval=0.05)
    stats.record("bad.example.com", True, "10.0.0.1", "A")
    assert _wait_for(lambda: stats.distinct_clients() == ["10.0.0.1"])
    stats.record("bad.example.com", True, "10.0.0.2", "A")
    assert _wait_for(lambda: sorted(stats.distinct_clients()) == ["10.0.0.1", "10.0.0.2"])
    stats.record("other.example.com", False, "10.0.0.3", "A")
    stats.record("bad.example.com", True, "10.0.0.1", "A")

    def _ready():
        return stats.recent_clients_for_domain("bad.example.com") == ["10.0.0.1", "10.0.0.2"]

    assert _wait_for(_ready)


def test_recent_clients_for_domain_respects_limit(tmp_path, config_store):
    stats = Stats(tmp_path / "stats.db", config_store, flush_interval=0.05)
    for i in range(5):
        stats.record("bad.example.com", True, f"10.0.0.{i}", "A")

    assert _wait_for(lambda: len(stats.distinct_clients()) == 5)
    assert len(stats.recent_clients_for_domain("bad.example.com", limit=3)) == 3


def test_recent_clients_for_domain_respects_restrict_client_ips(tmp_path, config_store):
    stats = Stats(tmp_path / "stats.db", config_store, flush_interval=0.05)
    stats.record("bad.example.com", True, "10.0.0.1", "A")
    stats.record("bad.example.com", True, "10.0.0.2", "A")
    assert _wait_for(lambda: len(stats.distinct_clients()) == 2)

    assert stats.recent_clients_for_domain("bad.example.com", restrict_client_ips=["10.0.0.2"]) == ["10.0.0.2"]
    assert stats.recent_clients_for_domain("bad.example.com", restrict_client_ips=[]) == []


def test_recent_clients_for_domain_empty_for_unknown_domain(tmp_path, config_store):
    stats = Stats(tmp_path / "stats.db", config_store, flush_interval=0.05)
    assert stats.recent_clients_for_domain("never-queried.example.com") == []


def test_writer_survives_database_errors_and_retries(config_store, tmp_path, monkeypatch):
    import sqlite3 as sqlite3_module

    from app import stats as stats_module

    stats = stats_module.Stats(tmp_path / "stats_retry.db", config_store, flush_interval=0.05)
    real_connect = stats._connect
    failures = {"left": 2}

    def flaky_connect():
        conn = real_connect()
        if failures["left"] > 0:
            failures["left"] -= 1
            conn.close()
            raise sqlite3_module.OperationalError("database is locked")
        return conn

    monkeypatch.setattr(stats, "_connect", flaky_connect)
    stats.record("retry.example.com", False, "192.168.1.5", "A")

    import time as time_module

    def count():
        conn = real_connect()
        try:
            return conn.execute("SELECT COUNT(*) FROM queries").fetchone()[0]
        finally:
            conn.close()

    for _ in range(100):
        if count() == 1:
            break
        time_module.sleep(0.05)
    assert count() == 1
    assert failures["left"] == 0
    assert stats._writer_thread.is_alive()


def test_record_drops_when_queue_is_full(config_store, tmp_path, monkeypatch):
    from app import stats as stats_module

    monkeypatch.setattr(stats_module, "_MAX_QUEUE", 0)
    stats = stats_module.Stats(tmp_path / "stats_full.db", config_store)
    stats.record("full.example.com", False, "192.168.1.5", "A")
    assert stats._dropped == 1
