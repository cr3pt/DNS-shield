# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

import pytest
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.blocklist import BlocklistManager
from app.stats import Stats
from app.users import UserStore
from app.web.server import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, create_app


def _client(config_store, tmp_path) -> TestClient:
    config_store.mutate(lambda d: d.setdefault("web", {}).update({"https_enabled": False}))
    blocklist = BlocklistManager(config_store, tmp_path / "cache")
    stats = Stats(tmp_path / "stats.db", config_store)
    return TestClient(create_app(config_store, blocklist, stats, started_at=0.0, data_dir=tmp_path))


def _login(client, username="admin", password="changeme"):
    response = client.post("/api/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    client.headers[CSRF_HEADER_NAME] = client.cookies[CSRF_COOKIE_NAME]
    return response.json()


@pytest.mark.force_password_change
def test_default_admin_must_change_password_before_using_the_api(config_store, tmp_path):
    client = _client(config_store, tmp_path)
    body = _login(client)
    assert body["user"]["must_change_password"] is True

    blocked = client.get("/api/status")
    assert blocked.status_code == 403
    assert "password_change_required" in blocked.json()["detail"]
    assert client.get("/api/whoami").json()["user"]["must_change_password"] is True

    weak = client.post("/api/account/password", json={"current_password": "changeme", "new_password": "short"})
    assert weak.status_code == 400
    same = client.post("/api/account/password", json={"current_password": "changeme", "new_password": "changeme"})
    assert same.status_code == 400

    ok = client.post(
        "/api/account/password", json={"current_password": "changeme", "new_password": "a-much-better-one"}
    )
    assert ok.status_code == 200
    client.headers[CSRF_HEADER_NAME] = client.cookies[CSRF_COOKIE_NAME]
    assert client.get("/api/status").status_code == 200
    assert client.get("/api/whoami").json()["user"]["must_change_password"] is False


@pytest.mark.force_password_change
def test_existing_install_on_default_password_gets_flagged(config_store):
    config_store.mutate(
        lambda d: d.update(
            {"users": [{"username": "root", "password_hash": hash_password("changeme"), "role": "admin"},
                       {"username": "bob", "password_hash": hash_password("bobs-own-pass"), "role": "user"}]}
        )
    )
    store = UserStore(config_store)
    assert store.get("root")["must_change_password"] is True
    assert not store.get("bob").get("must_change_password")


def test_changing_own_password_logs_out_other_sessions(config_store, tmp_path):
    first = _client(config_store, tmp_path)
    _login(first)
    second = TestClient(first.app)
    _login(second)

    response = first.post(
        "/api/account/password", json={"current_password": "changeme", "new_password": "new-password-1"}
    )
    assert response.status_code == 200
    first.headers[CSRF_HEADER_NAME] = first.cookies[CSRF_COOKIE_NAME]

    assert second.get("/api/status").status_code == 401
    assert first.get("/api/status").status_code == 200


def test_admin_cannot_set_a_too_short_password(config_store, tmp_path):
    client = _client(config_store, tmp_path)
    _login(client)
    assert client.post("/api/users", json={"username": "kid", "password": "123", "role": "user"}).status_code == 400
    assert client.post("/api/users", json={"username": "kid", "password": "12345678", "role": "user"}).status_code == 200
    assert client.patch("/api/users/kid", json={"password": "123"}).status_code == 400


def test_public_summary_is_off_by_default_and_can_be_enabled(config_store, tmp_path):
    client = _client(config_store, tmp_path)
    assert client.get("/api/public/summary").status_code == 404

    _login(client)
    assert client.get("/api/settings").json()["web"]["public_view_enabled"] is False
    assert client.patch("/api/settings/web", json={"public_view_enabled": True}).status_code == 200

    anonymous = TestClient(client.app)
    response = anonymous.get("/api/public/summary")
    assert response.status_code == 200
    assert "top_blocked_domains" in response.json()


def test_webauthn_origin_ignores_the_request_origin_header(config_store, tmp_path):
    client = _client(config_store, tmp_path)
    _login(client)
    assert client.patch("/api/settings/web", json={"public_url": "not a url"}).status_code == 422
    assert client.patch("/api/settings/web", json={"public_url": "https://dns.home.lan:3000/x"}).status_code == 200
    assert client.get("/api/settings").json()["web"]["public_url"] == "https://dns.home.lan:3000"
    options = client.post("/api/account/passkeys/register/options", json={}, headers={"Origin": "https://evil.example"})
    assert options.status_code == 200, options.text
    assert "dns.home.lan" in str(options.json())
