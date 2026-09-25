from app.dhcp.rogue_detector import RogueDhcpDetector, find_rogue_servers


def test_find_rogue_servers_excludes_allowed_ips():
    assert find_rogue_servers({"192.168.1.1", "10.0.0.5"}, {"192.168.1.1"}) == {"10.0.0.5"}


def test_find_rogue_servers_empty_when_all_allowed():
    assert find_rogue_servers({"192.168.1.1"}, {"192.168.1.1"}) == set()


def test_find_rogue_servers_empty_when_no_responders():
    assert find_rogue_servers(set(), {"192.168.1.1"}) == set()


class FakeAnomalyDetector:
    def __init__(self):
        self.alerts = []

    def record_external_alert(self, client, kind, severity, summary, details=None):
        entry = {"client": client, "kind": kind, "severity": severity, "summary": summary, "details": details}
        self.alerts.append(entry)
        return entry


def test_check_once_alerts_only_for_unrecognized_servers(config_store, monkeypatch):
    config_store.mutate(lambda d: d.setdefault("rogue_dhcp_detection", {}).update({
        "enabled": True, "allowed_server_ips": ["192.168.1.1"],
    }))
    config_store.mutate(lambda d: d.setdefault("dhcp", {}).update({"scopes": []}))

    monkeypatch.setattr(
        "app.dhcp.rogue_detector.discover_dhcp_servers",
        lambda interface, listen_seconds=4.0: {"192.168.1.1", "10.0.0.66"},
    )

    anomaly = FakeAnomalyDetector()
    detector = RogueDhcpDetector(config_store, anomaly_detector=anomaly)
    found = detector.check_once()

    assert len(found) == 1
    assert anomaly.alerts[0]["client"] == "10.0.0.66"
    assert anomaly.alerts[0]["kind"] == "rogue_dhcp_server"


def test_check_once_respects_cooldown(config_store, monkeypatch):
    config_store.mutate(lambda d: d.setdefault("rogue_dhcp_detection", {}).update({
        "enabled": True, "allowed_server_ips": [], "cooldown_minutes": 60,
    }))
    config_store.mutate(lambda d: d.setdefault("dhcp", {}).update({"scopes": []}))

    monkeypatch.setattr(
        "app.dhcp.rogue_detector.discover_dhcp_servers",
        lambda interface, listen_seconds=4.0: {"10.0.0.66"},
    )

    anomaly = FakeAnomalyDetector()
    detector = RogueDhcpDetector(config_store, anomaly_detector=anomaly)
    first = detector.check_once()
    second = detector.check_once()

    assert len(first) == 1
    assert len(second) == 0


def test_allowed_ips_includes_own_scope_server_ips(config_store):
    config_store.mutate(lambda d: d.setdefault("dhcp", {}).update({
        "scopes": [{"name": "lan", "server_ip": "192.168.1.1"}],
    }))
    detector = RogueDhcpDetector(config_store)
    assert "192.168.1.1" in detector._allowed_ips()
