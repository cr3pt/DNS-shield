import time

from app import new_client_detection as ncd
from app.anomaly import AnomalyDetector
from app.stats import Stats


def _wait_for(predicate, timeout=2.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def test_ensure_learning_started_sets_once(config_store):
    first = ncd.ensure_learning_started(config_store, "new_client_detection", "dns_learning_started_at")
    second = ncd.ensure_learning_started(config_store, "new_client_detection", "dns_learning_started_at")
    assert first == second


def test_learning_elapsed_false_before_period_ends(config_store):
    now = time.time()
    config_store.mutate(lambda d: d.setdefault("new_client_detection", {}).update({
        "dns_learning_days": 7, "dns_learning_started_at": now,
    }))
    assert ncd.learning_elapsed(config_store, "new_client_detection", "dns_learning_days", "dns_learning_started_at", now) is False


def test_learning_elapsed_true_after_period_ends(config_store):
    now = time.time()
    started = now - 8 * 86400
    config_store.mutate(lambda d: d.setdefault("new_client_detection", {}).update({
        "dns_learning_days": 7, "dns_learning_started_at": started,
    }))
    assert ncd.learning_elapsed(config_store, "new_client_detection", "dns_learning_days", "dns_learning_started_at", now) is True


def test_reset_learning_clears_started_at(config_store):
    config_store.mutate(lambda d: d.setdefault("new_client_detection", {}).update({
        "dns_learning_started_at": time.time(),
    }))
    ncd.reset_learning(config_store, "new_client_detection", "dns_learning_started_at")
    assert config_store.get("new_client_detection", "dns_learning_started_at") is None


def test_dns_and_dhcp_started_at_keys_are_independent(config_store):
    now = time.time()
    config_store.mutate(lambda d: d.setdefault("new_client_detection", {}).update({
        "dns_learning_started_at": now - 8 * 86400,
        "dns_learning_days": 7,
    }))
    assert ncd.learning_elapsed(config_store, "new_client_detection", "dns_learning_days", "dns_learning_started_at") is True
    assert ncd.learning_elapsed(config_store, "new_client_detection", "dhcp_learning_days", "dhcp_learning_started_at") is False


def test_check_new_dns_clients_alerts_only_after_learning_elapsed(config_store, tmp_path):
    started = time.time() - 8 * 86400
    config_store.mutate(lambda d: d.setdefault("new_client_detection", {}).update({
        "dns_enabled": True, "dns_learning_days": 7, "dns_learning_started_at": started,
    }))
    stats = Stats(tmp_path / "stats.db", config_store, flush_interval=0.05)
    detector = AnomalyDetector(config_store, stats, tmp_path / "anomaly.db")

    stats.record("example.com", False, "10.0.0.5", "A")
    assert _wait_for(lambda: stats.max_query_id() >= 1)
    assert detector.check_new_dns_clients() == []

    stats.record("example2.com", False, "10.0.0.6", "A")
    assert _wait_for(lambda: stats.max_query_id() >= 2)
    found = detector.check_new_dns_clients()
    assert len(found) == 1
    assert found[0]["client"] == "10.0.0.6"
    assert found[0]["kind"] == "new_dns_client"

    stats.record("example3.com", False, "10.0.0.6", "A")
    assert _wait_for(lambda: stats.max_query_id() >= 3)
    assert detector.check_new_dns_clients() == []


def test_check_new_dns_clients_disabled_returns_empty(config_store, tmp_path):
    stats = Stats(tmp_path / "stats.db", config_store, flush_interval=0.05)
    detector = AnomalyDetector(config_store, stats, tmp_path / "anomaly.db")
    stats.record("example.com", False, "10.0.0.5", "A")
    assert _wait_for(lambda: stats.max_query_id() >= 1)
    assert detector.check_new_dns_clients() == []


def test_reset_new_dns_clients_allows_realert(config_store, tmp_path):
    started = time.time() - 8 * 86400
    config_store.mutate(lambda d: d.setdefault("new_client_detection", {}).update({
        "dns_enabled": True, "dns_learning_days": 7, "dns_learning_started_at": started,
    }))
    stats = Stats(tmp_path / "stats.db", config_store, flush_interval=0.05)
    detector = AnomalyDetector(config_store, stats, tmp_path / "anomaly.db")

    stats.record("example.com", False, "10.0.0.5", "A")
    assert _wait_for(lambda: stats.max_query_id() >= 1)
    detector.check_new_dns_clients()

    stats.record("example2.com", False, "10.0.0.6", "A")
    assert _wait_for(lambda: stats.max_query_id() >= 2)
    assert len(detector.check_new_dns_clients()) == 1

    detector.reset_new_dns_clients()
    config_store.mutate(lambda d: d.setdefault("new_client_detection", {}).update({
        "dns_learning_started_at": started,
    }))

    stats.record("example4.com", False, "10.0.0.6", "A")
    assert _wait_for(lambda: stats.max_query_id() >= 3)
    assert len(detector.check_new_dns_clients()) == 1
