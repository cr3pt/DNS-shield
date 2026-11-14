# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

import pytest
from fastapi.testclient import TestClient

from app.blocklist import BlocklistManager, normalize_tld
from app.stats import Stats
from app.web.server import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, create_app


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("ru", "ru"), (".RU", "ru"), (" ua. ", "ua"), ("..com", "com"), ("рф", "xn--p1ai"), (".co.uk", "co.uk")],
)
def test_tlds_are_normalized(raw, expected):
    assert normalize_tld(raw) == expected


@pytest.mark.parametrize("raw", ["", " . ", "r u", "-ru", "ru-", "a/b", "x" * 64])
def test_invalid_tlds_are_rejected(raw):
    with pytest.raises(ValueError):
        normalize_tld(raw)


@pytest.fixture
def manager(config_store, tmp_path):
    config_store.mutate(lambda d: d.update({"blocked_tlds": ["ru", "ua"], "allowlist": ["allowed.ru"]}))
    return BlocklistManager(config_store, tmp_path / "cache")


def test_every_domain_under_a_blocked_tld_is_blocked(manager):
    assert manager.block_reason("example.ru") == "Blocked TLD: .ru"
    assert manager.block_reason("mail.example.ru.") == "Blocked TLD: .ru"
    assert manager.block_reason("ru") == "Blocked TLD: .ru"
    assert manager.block_reason("Shop.Example.UA") == "Blocked TLD: .ua"


def test_other_tlds_and_lookalikes_are_not_blocked(manager):
    assert manager.block_reason("example.com") is None
    assert manager.block_reason("example.rus") is None
    assert manager.block_reason("ru.example.com") is None


def test_allowlist_overrides_a_blocked_tld(manager):
    assert manager.block_reason("allowed.ru") is None
    assert manager.block_reason("www.allowed.ru") is None
    assert manager.block_reason("other.ru") is not None


def test_pause_disables_tld_blocking(manager, config_store):
    config_store.mutate(lambda d: d.update({"pause": {"active": True, "until": None}}))
    assert manager.block_reason("example.ru") is None


def _admin_client(config_store, tmp_path) -> TestClient:
    config_store.mutate(lambda d: d.setdefault("web", {}).update({"https_enabled": False}))
    stats = Stats(tmp_path / "stats.db", config_store)
    blocklist = BlocklistManager(config_store, tmp_path / "cache")
    app = create_app(config_store, blocklist, stats, started_at=0.0, data_dir=tmp_path)
    client = TestClient(app)
    assert client.post("/api/login", json={"username": "admin", "password": "changeme"}).status_code == 200
    client.headers[CSRF_HEADER_NAME] = client.cookies[CSRF_COOKIE_NAME]
    return client, blocklist


def test_blocked_tlds_api_round_trip(config_store, tmp_path):
    client, blocklist = _admin_client(config_store, tmp_path)

    assert client.get("/api/blocked-tlds").json() == []
    assert client.post("/api/blocked-tlds", json={"value": ".RU"}).json() == ["ru"]
    assert client.post("/api/blocked-tlds", json={"value": "ru"}).json() == ["ru"]
    assert client.post("/api/blocked-tlds", json={"value": "ua"}).json() == ["ru", "ua"]
    assert client.post("/api/blocked-tlds", json={"value": "not valid"}).status_code == 400
    assert config_store.get("blocked_tlds") == ["ru", "ua"]
    assert blocklist.is_blocked("example.ru")

    assert client.delete("/api/blocked-tlds/.ru").json() == ["ua"]
    assert not blocklist.is_blocked("example.ru")
    assert client.get("/api/blocked-tlds").json() == ["ua"]
