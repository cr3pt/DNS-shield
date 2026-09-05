import time

from app.anomaly import (
    AnomalyDetector,
    _base_domain,
    _is_private_client,
    _is_private_ptr_target,
    _looks_like_dga,
    _looks_like_tunnel_label,
    _ptr_name_to_ip,
    _shannon_entropy,
)
from tests.conftest import FakeStats


def test_shannon_entropy_of_repeated_char_is_zero():
    assert _shannon_entropy("aaaa") == 0.0
    assert _shannon_entropy("") == 0.0


def test_shannon_entropy_of_random_looking_string_is_higher():
    assert _shannon_entropy("x7q9z2w4") > _shannon_entropy("aaaaaaaa")


def test_looks_like_dga_respects_min_length():
    assert _looks_like_dga("ab", min_label_length=5, min_entropy=1.0) is False


def test_looks_like_dga_flags_high_entropy_registrable_label():
    assert _looks_like_dga("www.x7q9z2w4b1.com", min_label_length=5, min_entropy=3.0) is True
    assert _looks_like_dga("www.wwwwwwwwww.com", min_label_length=5, min_entropy=3.0) is False


def test_base_domain():
    assert _base_domain("a.b.example.com") == "example.com"
    assert _base_domain("example.com") == "example.com"
    assert _base_domain("com") == "com"


def test_looks_like_tunnel_label_uses_first_label_only():
    assert _looks_like_tunnel_label("x7q9z2w4b1.example.com", min_label_length=5, min_entropy=3.0) is True
    assert _looks_like_tunnel_label("short.example.com", min_label_length=10, min_entropy=1.0) is False


def test_ptr_name_to_ip_v4():
    assert _ptr_name_to_ip("5.1.168.192.in-addr.arpa") == "192.168.1.5"
    assert _ptr_name_to_ip("5.1.168.192.in-addr.arpa.") == "192.168.1.5"
    assert _ptr_name_to_ip("not.a.ptr.name") is None
    assert _ptr_name_to_ip("1.2.3.in-addr.arpa") is None


def test_ptr_name_to_ip_v6():
    nibbles = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    ip = _ptr_name_to_ip(nibbles)
    assert ip == "2001:0db8:0000:0000:0000:0000:0000:0001"


def test_is_private_ptr_target():
    assert _is_private_ptr_target("5.1.168.192.in-addr.arpa") is True
    assert _is_private_ptr_target("8.8.8.8.in-addr.arpa") is False
    assert _is_private_ptr_target("garbage") is False


def test_is_private_client():
    assert _is_private_client("192.168.1.5") is True
    assert _is_private_client("10.0.0.1") is True
    assert _is_private_client("172.16.0.1") is True
    assert _is_private_client("172.31.255.255") is True
    assert _is_private_client("172.32.0.1") is False
    assert _is_private_client("8.8.8.8") is False
    assert _is_private_client("not-an-ip") is False


def _make_detector(config_store, tmp_path, hits, name="anomaly.db"):
    return AnomalyDetector(config_store, FakeStats(hits), tmp_path / name)


def test_typosquat_alert_fires_for_new_hit(config_store, tmp_path):
    hits = [{"id": 1, "ts": time.time(), "domain": "paypa1.com", "client": "8.8.8.8", "typosquat_match": "paypal.com|typo|1"}]
    config_store.mutate(lambda d: d.setdefault("dns", {}).update({"typosquat_enabled": True}))
    det = _make_detector(config_store, tmp_path, hits)
    det._typosquat_watch_last_id = 0
    found = det.check_typosquat_hits()
    assert len(found) == 1
    assert found[0]["kind"] == "typosquat:paypal.com"


def test_typosquat_disabled_by_default_produces_no_alerts(config_store, tmp_path):
    hits = [{"id": 1, "ts": time.time(), "domain": "paypa1.com", "client": "8.8.8.8", "typosquat_match": "paypal.com|typo|1"}]
    det = _make_detector(config_store, tmp_path, hits)
    det._typosquat_watch_last_id = 0
    assert det.check_typosquat_hits() == []


def test_typosquat_fp_pair_suppresses_only_that_exact_pair(config_store, tmp_path):
    hits = [
        {"id": 1, "ts": time.time(), "domain": "paypa1.com", "client": "1.2.3.4", "typosquat_match": "paypal.com|typo|1"},
        {"id": 2, "ts": time.time(), "domain": "gooogle.com", "client": "1.2.3.5", "typosquat_match": "google.com|typo|1"},
    ]
    config_store.mutate(lambda d: d.setdefault("dns", {}).update({"typosquat_enabled": True}))
    config_store.mutate(lambda d: d.setdefault("anomaly", {}).update(
        {"typosquat_fp_pairs": [{"domain": "paypa1.com", "protected": "paypal.com"}]}
    ))
    det = _make_detector(config_store, tmp_path, hits)
    det._typosquat_watch_last_id = 0
    found = det.check_typosquat_hits()
    assert len(found) == 1
    assert found[0]["client"] == "1.2.3.5"


def test_rebinding_fp_pair_suppresses_only_that_exact_pair(config_store, tmp_path):
    hits = [
        {"id": 1, "ts": time.time(), "domain": "printer.example.com", "client": "1.2.3.4", "rebinding_ip": "192.168.1.77"},
        {"id": 2, "ts": time.time(), "domain": "evil.example.com", "client": "1.2.3.5", "rebinding_ip": "10.0.0.99"},
    ]
    config_store.mutate(lambda d: d.setdefault("dns", {}).update({"rebinding_protection_enabled": True}))
    config_store.mutate(lambda d: d.setdefault("anomaly", {}).update(
        {"rebinding_fp_pairs": [{"domain": "printer.example.com", "ip": "192.168.1.77"}]}
    ))
    det = _make_detector(config_store, tmp_path, hits)
    det._rebinding_watch_last_id = 0
    found = det.check_rebinding_hits()
    assert len(found) == 1
    assert found[0]["client"] == "1.2.3.5"


def test_rebinding_fp_pair_does_not_suppress_same_domain_different_ip(config_store, tmp_path):
    hits = [{"id": 1, "ts": time.time(), "domain": "printer.example.com", "client": "1.2.3.4", "rebinding_ip": "192.168.1.99"}]
    config_store.mutate(lambda d: d.setdefault("dns", {}).update({"rebinding_protection_enabled": True}))
    config_store.mutate(lambda d: d.setdefault("anomaly", {}).update(
        {"rebinding_fp_pairs": [{"domain": "printer.example.com", "ip": "192.168.1.77"}]}
    ))
    det = _make_detector(config_store, tmp_path, hits)
    det._rebinding_watch_last_id = 0
    found = det.check_rebinding_hits()
    assert len(found) == 1


def test_threat_intel_fp_target_suppresses_at_or_below_marked_verdict(config_store, tmp_path):
    config_store.mutate(lambda d: d.setdefault("anomaly", {}).update(
        {"threat_intel_fp_targets": [{"target": "youtube.com", "verdict": "high"}]}
    ))
    det = _make_detector(config_store, tmp_path, [])
    assert det.record_threat_intel_alert("youtube.com", "domain", "high", "youtube.com flagged high", {}) is None
    found = det.record_threat_intel_alert("evil.example", "domain", "high", "evil.example flagged high", {})
    assert found is not None
    assert found["kind"] == "threat_intel:evil.example"


def test_threat_intel_fp_target_still_alerts_on_escalation(config_store, tmp_path):
    config_store.mutate(lambda d: d.setdefault("anomaly", {}).update(
        {"threat_intel_fp_targets": [{"target": "youtube.com", "verdict": "medium"}]}
    ))
    det = _make_detector(config_store, tmp_path, [])
    assert det.record_threat_intel_alert("youtube.com", "domain", "low", "youtube.com flagged low", {}) is None
    assert det.record_threat_intel_alert("youtube.com", "domain", "medium", "youtube.com flagged medium", {}) is None
    escalated = det.record_threat_intel_alert("youtube.com", "domain", "high", "youtube.com flagged high", {})
    assert escalated is not None
    assert "medium" in escalated["summary"] and "high" in escalated["summary"]
    assert "false positive" in escalated["summary"]


def test_local_tld_alert_suppressed_for_private_client(config_store, tmp_path):
    hits = [
        {"id": 1, "ts": time.time(), "domain": "printer.local", "client": "192.168.1.50", "local_tld_match": "local"},
        {"id": 2, "ts": time.time(), "domain": "evil.lan", "client": "8.8.8.8", "local_tld_match": "lan"},
    ]
    config_store.mutate(lambda d: d.setdefault("dns", {}).update({"local_tld_alert_enabled": True}))
    det = _make_detector(config_store, tmp_path, hits)
    det._local_tld_watch_last_id = 0
    found = det.check_local_tld_hits()
    assert len(found) == 1
    assert found[0]["client"] == "8.8.8.8"


def test_excluded_domain_suppresses_typosquat_alert(config_store, tmp_path):
    hits = [{"id": 1, "ts": time.time(), "domain": "sub.paypa1.com", "client": "8.8.8.8", "typosquat_match": "paypal.com|typo|1"}]
    config_store.mutate(lambda d: d.setdefault("dns", {}).update({"typosquat_enabled": True}))
    config_store.mutate(lambda d: d.setdefault("anomaly", {}).update({"excluded_domains": ["paypa1.com"]}))
    det = _make_detector(config_store, tmp_path, hits)
    det._typosquat_watch_last_id = 0
    assert det.check_typosquat_hits() == []
