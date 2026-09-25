import pytest

from app.dhcp.leases import LeaseStore, find_free_ip


@pytest.fixture
def lease_store(tmp_path):
    return LeaseStore(tmp_path / "leases.db")


def test_find_free_ip_returns_first_available():
    ip = find_free_ip("192.168.1.100", "192.168.1.102", taken=set(), excluded=set())
    assert ip == "192.168.1.100"


def test_find_free_ip_skips_taken_and_excluded():
    ip = find_free_ip(
        "192.168.1.100", "192.168.1.102",
        taken={"192.168.1.100"}, excluded={"192.168.1.101"},
    )
    assert ip == "192.168.1.102"


def test_find_free_ip_returns_none_when_pool_exhausted():
    ip = find_free_ip(
        "192.168.1.100", "192.168.1.101",
        taken={"192.168.1.100", "192.168.1.101"}, excluded=set(),
    )
    assert ip is None


def test_find_free_ip_prefers_preferred_when_available():
    ip = find_free_ip("192.168.1.100", "192.168.1.110", taken=set(), excluded=set(), preferred="192.168.1.105")
    assert ip == "192.168.1.105"


def test_find_free_ip_ignores_preferred_outside_pool():
    ip = find_free_ip("192.168.1.100", "192.168.1.110", taken=set(), excluded=set(), preferred="10.0.0.5")
    assert ip == "192.168.1.100"


def test_commit_and_get_lease(lease_store):
    lease_store.commit_lease("AA:BB:CC:DD:EE:01", "192.168.1.100", "lan", "host1", None, 3600)
    lease = lease_store.get_by_mac("AA:BB:CC:DD:EE:01")
    assert lease["ip"] == "192.168.1.100"
    assert lease["scope"] == "lan"
    assert lease["hostname"] == "host1"


def test_taken_ips_excludes_own_mac_for_renewal(lease_store):
    lease_store.commit_lease("AA:BB:CC:DD:EE:01", "192.168.1.100", "lan", None, None, 3600)
    assert lease_store.taken_ips("lan") == {"192.168.1.100"}
    assert lease_store.taken_ips("lan", exclude_mac="AA:BB:CC:DD:EE:01") == set()


def test_release_removes_lease(lease_store):
    lease_store.commit_lease("AA:BB:CC:DD:EE:01", "192.168.1.100", "lan", None, None, 3600)
    lease_store.release("AA:BB:CC:DD:EE:01")
    assert lease_store.get_by_mac("AA:BB:CC:DD:EE:01") is None


def test_decline_marks_ip_unavailable_until_cooldown_expires(lease_store):
    now = 1000.0
    lease_store.decline("192.168.1.100", "lan", cooldown_seconds=100, now=now)
    assert lease_store.declined_ips("lan", now=now + 50) == {"192.168.1.100"}
    assert lease_store.declined_ips("lan", now=now + 200) == set()


def test_expire_sweep_removes_only_expired_dynamic_leases(lease_store):
    now = 1000.0
    lease_store.commit_lease("AA:BB:CC:DD:EE:01", "192.168.1.100", "lan", None, None, -10, now=now)
    lease_store.commit_lease("AA:BB:CC:DD:EE:02", "192.168.1.101", "lan", None, None, 3600, now=now)
    lease_store.commit_lease("AA:BB:CC:DD:EE:03", "192.168.1.102", "lan", None, None, -10, static=True, now=now)

    removed = lease_store.expire_sweep(now=now)

    assert removed == 1
    assert lease_store.get_by_mac("AA:BB:CC:DD:EE:01") is None
    assert lease_store.get_by_mac("AA:BB:CC:DD:EE:02") is not None
    assert lease_store.get_by_mac("AA:BB:CC:DD:EE:03") is not None


def test_mark_known_returns_true_only_on_first_call(lease_store):
    assert lease_store.mark_known("AA:BB:CC:DD:EE:01") is True
    assert lease_store.mark_known("AA:BB:CC:DD:EE:01") is False


def test_reset_known_macs_clears_state(lease_store):
    lease_store.mark_known("AA:BB:CC:DD:EE:01")
    lease_store.reset_known_macs()
    assert lease_store.mark_known("AA:BB:CC:DD:EE:01") is True
