# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

import pytest
from fastapi.testclient import TestClient

from app.blocklist import BlocklistManager
from app.netmatch import normalize_client_pattern
from app.stats import Stats
from app.web.server import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, create_app


def _admin_client(config_store, tmp_path) -> TestClient:
    config_store.mutate(lambda d: d.setdefault("web", {}).update({"https_enabled": False}))
    stats = Stats(tmp_path / "stats.db", config_store)
    app = create_app(
        config_store, BlocklistManager(config_store, tmp_path / "cache"), stats, started_at=0.0, data_dir=tmp_path
    )
    client = TestClient(app)
    assert client.post("/api/login", json={"username": "admin", "password": "changeme"}).status_code == 200
    client.headers[CSRF_HEADER_NAME] = client.cookies[CSRF_COOKIE_NAME]
    return client


def _create(client, name="Kids", match=("192.168.1.50",), enabled=True):
    response = client.post("/api/client-groups", json={"name": name, "match": list(match), "enabled": enabled})
    assert response.status_code == 200
    return response.json()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("192.168.1.5", "192.168.1.5"),
        ("  10.0.0.0/8 ", "10.0.0.0/8"),
        ("192.168.1.5/24", "192.168.1.5/24"),
        ("fe80:0:0:0:0:0:0:1", "fe80::1"),
        ("2001:db8::/32", "2001:db8::/32"),
        ("mac:aa-bb-cc-dd-ee-ff", "mac:AA:BB:CC:DD:EE:FF"),
        ("MAC:aa:bb:cc:dd:ee:ff", "mac:AA:BB:CC:DD:EE:FF"),
        ("host:Kids-Tablet.", "host:kids-tablet"),
        ("host:*.Kids.lan", "host:*.kids.lan"),
    ],
)
def test_valid_client_patterns_are_normalized(raw, expected):
    assert normalize_client_pattern(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "999.1.1.1", "10.0.0.0/33", "not an ip", "mac:zz:bb:cc:dd:ee:ff", "mac:aa:bb:cc", "host:", "host:bad name", "host:a/b", "x" * 300],
)
def test_invalid_client_patterns_are_rejected(raw):
    with pytest.raises(ValueError):
        normalize_client_pattern(raw)


def test_more_addresses_can_be_added_to_an_existing_group(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    _create(client)

    response = client.post("/api/client-groups/0/match", json={"patterns": ["192.168.1.51", "10.0.0.0/24", "mac:aa-bb-cc-dd-ee-ff"]})

    assert response.status_code == 200
    assert response.json()["match"] == ["192.168.1.50", "192.168.1.51", "10.0.0.0/24", "mac:AA:BB:CC:DD:EE:FF"]
    assert config_store.get("client_groups")[0]["match"] == response.json()["match"]


def test_adding_an_existing_pattern_does_not_duplicate_it(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    _create(client)

    response = client.post("/api/client-groups/0/match", json={"patterns": ["192.168.1.50", "192.168.1.50", "192.168.1.52"]})

    assert response.json()["match"] == ["192.168.1.50", "192.168.1.52"]


def test_one_bad_pattern_rejects_the_whole_request(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    _create(client)

    response = client.post("/api/client-groups/0/match", json={"patterns": ["192.168.1.51", "nonsense"]})

    assert response.status_code == 400
    assert "nonsense" in response.json()["detail"]
    assert config_store.get("client_groups")[0]["match"] == ["192.168.1.50"]


def test_an_empty_or_missing_pattern_list_is_rejected(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    _create(client)

    assert client.post("/api/client-groups/0/match", json={"patterns": []}).status_code == 422
    assert client.post("/api/client-groups/0/match", json={}).status_code == 422


def test_adding_to_a_missing_group_is_a_404(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)

    assert client.post("/api/client-groups/3/match", json={"patterns": ["10.0.0.1"]}).status_code == 404


def test_a_pattern_can_be_removed_even_when_it_contains_a_slash(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    _create(client, match=("192.168.1.50", "192.168.2.0/24"))

    response = client.delete("/api/client-groups/0/match", params={"pattern": "192.168.2.0/24"})

    assert response.status_code == 200
    assert response.json()["match"] == ["192.168.1.50"]


def test_the_last_pattern_of_a_group_cannot_be_removed(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    _create(client)

    response = client.delete("/api/client-groups/0/match", params={"pattern": "192.168.1.50"})

    assert response.status_code == 400
    assert config_store.get("client_groups")[0]["match"] == ["192.168.1.50"]


def test_removing_an_unknown_pattern_is_a_404(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    _create(client, match=("192.168.1.50", "192.168.1.51"))

    assert client.delete("/api/client-groups/0/match", params={"pattern": "10.9.9.9"}).status_code == 404


def test_a_pattern_stored_before_normalization_can_still_be_removed(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    _create(client, match=("192.168.1.50", "mac:AA:BB:CC:DD:EE:FF"))

    response = client.delete("/api/client-groups/0/match", params={"pattern": "mac:aa-bb-cc-dd-ee-ff"})

    assert response.status_code == 200
    assert response.json()["match"] == ["192.168.1.50"]


def test_creating_a_group_validates_and_normalizes_its_patterns(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)

    assert client.post("/api/client-groups", json={"name": "Bad", "match": ["nonsense"]}).status_code == 422
    groups = _create(client, name="Mixed", match=("mac:aa-bb-cc-dd-ee-ff", "10.0.0.1", "10.0.0.1"))

    assert groups[0]["match"] == ["mac:AA:BB:CC:DD:EE:FF", "10.0.0.1"]


def test_group_match_endpoints_are_admin_only(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    _create(client)
    anonymous = TestClient(client.app)

    assert anonymous.post("/api/client-groups/0/match", json={"patterns": ["10.0.0.1"]}).status_code in (401, 403)
    assert anonymous.delete("/api/client-groups/0/match", params={"pattern": "192.168.1.50"}).status_code in (401, 403)


def test_filtering_can_be_set_explicitly_and_repeatedly(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    _create(client)

    for enabled in (False, False, True, True):
        response = client.put("/api/client-groups/0/enabled", json={"enabled": enabled})
        assert response.status_code == 200
        assert response.json()[0]["enabled"] is enabled

    assert client.put("/api/client-groups/5/enabled", json={"enabled": True}).status_code == 404
    assert client.put("/api/client-groups/0/enabled", json={}).status_code == 422
