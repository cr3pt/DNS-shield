# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

import time

import pytest
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.blocklist import BlocklistManager
from app.stats import Stats
from app.web.server import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, create_app


def _wait_for(predicate, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


@pytest.fixture
def logged(config_store, tmp_path):
    config_store.mutate(
        lambda d: d.update(
            {
                "web": {"https_enabled": False},
                "client_groups": [
                    {"name": "Kids", "match": ["192.168.1.50", "192.168.1.60"], "enabled": True},
                    {"name": "Guests", "match": ["10.1.0.0/24"], "enabled": True},
                    {"name": "Empty", "match": ["172.16.0.1"], "enabled": True},
                ],
            }
        )
    )
    stats = Stats(tmp_path / "stats.db", config_store, flush_interval=0.05)
    for domain, client in (
        ("kids-a.example", "192.168.1.50"),
        ("kids-b.example", "192.168.1.60"),
        ("guest.example", "10.1.0.7"),
        ("other.example", "192.168.1.99"),
        ("other2.example", "192.168.1.98"),
    ):
        stats.record(domain, False, client, "A")
    assert _wait_for(lambda: len(stats.distinct_clients()) == 5)
    app = create_app(
        config_store, BlocklistManager(config_store, tmp_path / "cache"), stats, started_at=0.0, data_dir=tmp_path
    )
    client = TestClient(app)
    assert client.post("/api/login", json={"username": "admin", "password": "changeme"}).status_code == 200
    client.headers[CSRF_HEADER_NAME] = client.cookies[CSRF_COOKIE_NAME]
    return client


def _domains(response):
    return sorted(row["domain"] for row in response.json()["rows"])


def test_log_can_be_limited_to_one_client_group(logged):
    response = logged.get("/api/query-log", params={"group": "Kids"})

    assert response.status_code == 200
    assert _domains(response) == ["kids-a.example", "kids-b.example"]
    assert response.json()["total"] == 2


def test_log_can_show_only_clients_outside_every_group(logged):
    response = logged.get("/api/query-log", params={"no_group": "true"})

    assert _domains(response) == ["other.example", "other2.example"]


def test_a_group_with_no_logged_clients_gives_an_empty_log(logged):
    response = logged.get("/api/query-log", params={"group": "Empty"})

    assert response.status_code == 200
    assert response.json()["rows"] == []
    assert response.json()["total"] == 0


def test_group_filter_combines_with_the_other_filters(logged):
    response = logged.get("/api/query-log", params={"group": "Kids", "domain": "kids-b"})

    assert _domains(response) == ["kids-b.example"]


def test_unknown_group_is_a_404_and_conflicting_options_a_400(logged):
    assert logged.get("/api/query-log", params={"group": "Nope"}).status_code == 404
    assert logged.get("/api/query-log", params={"group": "Kids", "no_group": "true"}).status_code == 400


def test_rows_report_which_group_each_client_belongs_to(logged):
    body = logged.get("/api/query-log").json()

    assert body["client_groups"] == {
        "192.168.1.50": "Kids",
        "192.168.1.60": "Kids",
        "10.1.0.7": "Guests",
    }


def test_clients_endpoint_lists_every_configured_group_for_admins(logged):
    assert logged.get("/api/query-log/clients").json()["groups"] == ["Kids", "Guests", "Empty"]


def test_restricted_users_only_see_and_filter_within_their_own_clients(config_store, tmp_path, logged):
    config_store.mutate(
        lambda d: d.setdefault("users", []).append(
            {
                "username": "parent",
                "password_hash": hash_password("pw-parent-1"),
                "role": "user",
                "permissions": {"view_logs": True, "allowed_clients": ["192.168.1.50", "10.1.0.7"]},
            }
        )
    )
    other = TestClient(logged.app)
    assert other.post("/api/login", json={"username": "parent", "password": "pw-parent-1"}).status_code == 200

    kids = other.get("/api/query-log", params={"group": "Kids"})
    guests = other.get("/api/query-log", params={"group": "Guests"})
    outside = other.get("/api/query-log", params={"no_group": "true"})
    listing = other.get("/api/query-log/clients").json()

    assert _domains(kids) == ["kids-a.example"]
    assert _domains(guests) == ["guest.example"]
    assert outside.json()["rows"] == []
    assert listing["groups"] == ["Guests", "Kids"]
    assert set(kids.json()["client_groups"]) == {"192.168.1.50"}


def test_client_list_can_be_limited_to_one_group(logged):
    body = logged.get("/api/query-log/clients", params={"group": "Kids"}).json()

    assert body["clients"] == ["192.168.1.50", "192.168.1.60"]
    assert body["groups"] == ["Kids", "Guests", "Empty"]


def test_client_list_can_be_limited_to_clients_outside_every_group(logged):
    body = logged.get("/api/query-log/clients", params={"no_group": "true"}).json()

    assert body["clients"] == ["192.168.1.98", "192.168.1.99"]


def test_client_list_of_a_group_without_logged_clients_is_empty(logged):
    assert logged.get("/api/query-log/clients", params={"group": "Empty"}).json()["clients"] == []


def test_client_list_without_a_group_still_returns_everyone(logged):
    assert len(logged.get("/api/query-log/clients").json()["clients"]) == 5


def test_client_list_rejects_an_unknown_group_and_conflicting_options(logged):
    assert logged.get("/api/query-log/clients", params={"group": "Nope"}).status_code == 404
    assert logged.get("/api/query-log/clients", params={"group": "Kids", "no_group": "true"}).status_code == 400


def test_a_restricted_users_group_scoped_client_list_stays_within_their_clients(config_store, logged):
    config_store.mutate(
        lambda d: d.setdefault("users", []).append(
            {
                "username": "parent",
                "password_hash": hash_password("pw-parent-1"),
                "role": "user",
                "permissions": {"view_logs": True, "allowed_clients": ["192.168.1.50", "10.1.0.7"]},
            }
        )
    )
    other = TestClient(logged.app)
    assert other.post("/api/login", json={"username": "parent", "password": "pw-parent-1"}).status_code == 200

    scoped = other.get("/api/query-log/clients", params={"group": "Kids"}).json()
    outside = other.get("/api/query-log/clients", params={"no_group": "true"}).json()

    assert scoped["clients"] == ["192.168.1.50"]
    assert outside["clients"] == []
    assert scoped["groups"] == ["Guests", "Kids"]
