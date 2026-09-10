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
