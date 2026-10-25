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


def _users_with_group_access(config_store, *groups):
    config_store.mutate(
        lambda d: d.setdefault("users", []).append(
            {
                "username": "parent",
                "password_hash": "x",
                "role": "user",
                "permissions": {"allowed_groups": list(groups), "allowed_clients": ["10.0.0.9"]},
            }
        )
    )


def test_a_group_can_be_renamed(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    _create(client)

    response = client.put("/api/client-groups/0/name", json={"name": "  Kids   Tablets "})

    assert response.status_code == 200
    assert response.json()["name"] == "Kids Tablets"
    assert response.json()["match"] == ["192.168.1.50"]
    assert [g["name"] for g in client.get("/api/client-groups").json()] == ["Kids Tablets"]


def test_renaming_keeps_users_access_to_the_group(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    _create(client)
    _create(client, name="Guests", match=("10.1.0.0/24",))
    _users_with_group_access(config_store, "Kids", "Guests")

    client.put("/api/client-groups/0/name", json={"name": "Children"})

    user = next(u for u in config_store.get("users") if u["username"] == "parent")
    assert user["permissions"]["allowed_groups"] == ["Children", "Guests"]
    assert user["permissions"]["allowed_clients"] == ["10.0.0.9"]


def test_renaming_leaves_other_users_alone(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    _create(client)
    _users_with_group_access(config_store, "Guests")

    client.put("/api/client-groups/0/name", json={"name": "Children"})

    user = next(u for u in config_store.get("users") if u["username"] == "parent")
    assert user["permissions"]["allowed_groups"] == ["Guests"]


def test_renaming_to_the_same_name_is_a_noop(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    _create(client)

    response = client.put("/api/client-groups/0/name", json={"name": "Kids"})

    assert response.status_code == 200
    assert response.json()["name"] == "Kids"


def test_changing_only_the_letter_case_is_allowed(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    _create(client)

    assert client.put("/api/client-groups/0/name", json={"name": "KIDS"}).json()["name"] == "KIDS"


def test_a_name_used_by_another_group_is_refused_ignoring_case(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    _create(client)
    _create(client, name="Guests", match=("10.1.0.0/24",))

    response = client.put("/api/client-groups/1/name", json={"name": "kids"})

    assert response.status_code == 409
    assert [g["name"] for g in config_store.get("client_groups")] == ["Kids", "Guests"]


def test_creating_a_group_with_a_taken_name_is_refused(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    _create(client)

    response = client.post("/api/client-groups", json={"name": "KIDS", "match": ["10.0.0.1"]})

    assert response.status_code == 409
    assert len(config_store.get("client_groups")) == 1


@pytest.mark.parametrize("name", ["", "   ", "x" * 256, "bad\nname", "tab\tname"])
def test_unusable_group_names_are_rejected(config_store, tmp_path, name):
    client = _admin_client(config_store, tmp_path)
    _create(client)

    assert client.put("/api/client-groups/0/name", json={"name": name}).status_code == 422
    assert client.post("/api/client-groups", json={"name": name, "match": ["10.0.0.1"]}).status_code == 422
    assert config_store.get("client_groups")[0]["name"] == "Kids"


def test_renaming_a_missing_group_is_a_404(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)

    assert client.put("/api/client-groups/2/name", json={"name": "Anything"}).status_code == 404


def test_rename_is_admin_only(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    _create(client)

    assert TestClient(client.app).put("/api/client-groups/0/name", json={"name": "Hacked"}).status_code in (401, 403)
    assert config_store.get("client_groups")[0]["name"] == "Kids"


def test_extra_blocklist_data_follows_a_renamed_group(config_store, tmp_path):
    manager = BlocklistManager(config_store, tmp_path / "cache")
    manager._group_blocked["Kids"] = frozenset({"bad.example"})
    manager._group_domain_source["Kids"] = {"bad.example": "list"}
    manager._group_source_counts["Kids"] = {"list": 1}
    manager._group_source_formats["Kids"] = {"list": "hosts"}

    manager.rename_group("Kids", "Children")

    assert manager.group_source_counts("Children") == {"list": 1}
    assert manager.group_source_formats("Children") == {"list": "hosts"}
    assert manager.group_source_counts("Kids") == {}
    assert "Kids" not in manager._group_blocked
    assert manager._group_blocked["Children"] == frozenset({"bad.example"})
    manager.rename_group("Missing", "Whatever")


def test_long_descriptive_group_names_up_to_255_characters_are_accepted(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    _create(client)
    name = "n" * 255

    assert client.put("/api/client-groups/0/name", json={"name": name}).json()["name"] == name
    assert client.post("/api/client-groups", json={"name": "m" * 255, "match": ["10.0.0.1"]}).status_code == 200
