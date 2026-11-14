# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""A secondary copies the filtering config from a primary."""

from fastapi.testclient import TestClient

from app.blocklist import BlocklistManager
from app.config import ConfigStore
from app.stats import Stats
from app.sync import SyncClient, apply_view, syncable_view
from app.web.server import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, create_app


def _instance(tmp_path, name):
    directory = tmp_path / name
    directory.mkdir()
    store = ConfigStore(db_path=directory / "config.db", backup_path=directory / "config.backup.yaml")
    store.mutate(lambda d: d.setdefault("web", {}).update({"https_enabled": False}))
    blocklist = BlocklistManager(store, directory / "cache")
    app = create_app(store, blocklist, Stats(directory / "stats.db", store), started_at=0.0, data_dir=directory)
    client = TestClient(app)
    assert client.post("/api/login", json={"username": "admin", "password": "changeme"}).status_code == 200
    client.headers[CSRF_HEADER_NAME] = client.cookies[CSRF_COOKIE_NAME]
    return store, client, blocklist


class _Session:
    """Sends the secondary's requests to the primary's TestClient."""

    def __init__(self, client):
        self.client = client
        self.urls = []

    def get(self, url, headers=None, **_kwargs):
        self.urls.append(url)
        path = url.split("://", 1)[1].split("/", 1)[1]
        return _Response(TestClient(self.client.app).get("/" + path, headers=headers))


class _Response:
    def __init__(self, response):
        self.status_code = response.status_code
        self._response = response

    def json(self):
        return self._response.json()


def test_view_keeps_local_settings():
    primary = {
        "denylist": ["a.example"],
        "users": [{"username": "x"}],
        "dhcp": {"enabled": True},
        "dns": {"listen_port": 5353, "upstreams": ["9.9.9.9"], "doq_enabled": True},
    }
    view = syncable_view(primary, list(primary))
    assert set(view) == {"denylist", "dns"}
    assert view["dns"] == {"upstreams": ["9.9.9.9"]}

    secondary = {"dns": {"listen_port": 53, "upstreams": ["1.1.1.1"]}, "denylist": []}
    changed = apply_view(secondary, view, ["denylist", "dns", "users"])
    assert changed == ["denylist", "dns"]
    assert secondary["dns"] == {"upstreams": ["9.9.9.9"], "listen_port": 53}
    assert "users" not in secondary
    assert apply_view(secondary, view, ["denylist", "dns"]) == []


def test_secondary_pulls_from_primary(tmp_path):
    primary_store, primary, _ = _instance(tmp_path, "primary")
    secondary_store, secondary, secondary_blocklist = _instance(tmp_path, "secondary")
    token = primary.post("/api/account/tokens", json={"name": "secondary"}).json()["token"]
    assert primary.post("/api/rules/deny", json={"domain": "ads.example"}).status_code == 200
    group = primary.post("/api/client-groups", json={"name": "Kids", "match": ["10.0.0.5"]})
    assert group.status_code == 200
    primary_store.mutate(lambda d: d["dns"].update(listen_port=5353))

    # Without a token the primary refuses.
    assert TestClient(primary.app).get("/api/sync/config").status_code == 401

    response = secondary.patch(
        "/api/settings/sync",
        json={"enabled": True, "primary_url": "http://primary.lan:3000/", "token": token, "interval_seconds": 60},
    )
    assert response.status_code == 200
    assert response.json()["token_set"] is True and "token" not in response.json()

    sync = SyncClient(secondary_store, secondary_blocklist, session=_Session(primary))
    changed = sync.sync_once()
    assert "denylist" in changed and "client_groups" in changed
    assert secondary_store.get("denylist") == ["ads.example"]
    assert secondary_store.get("client_groups")[0]["name"] == "Kids"
    assert secondary_store.get("dns", "listen_port") != 5353
    assert sync.status()["last_error"] is None
    assert sync.sync_once() == []
    assert secondary_store.get("users")[0]["username"] == "admin"
    assert secondary_store.history()[0]["actor"].startswith("sync from http://primary.lan:3000")


def test_sync_reports_errors(tmp_path):
    _primary_store, primary, _ = _instance(tmp_path, "primary")
    secondary_store, _secondary, _ = _instance(tmp_path, "secondary")
    secondary_store.mutate(
        lambda d: d.update(sync={"enabled": True, "primary_url": "http://primary.lan", "token": "wrong"})
    )
    sync = SyncClient(secondary_store, session=_Session(primary))
    assert sync.sync_once() == []
    assert "HTTP 401" in sync.status()["last_error"]


def test_sync_settings_validation(tmp_path):
    _store, client, _ = _instance(tmp_path, "one")
    assert client.patch("/api/settings/sync", json={"primary_url": "ftp://x"}).status_code == 422
    assert client.patch("/api/settings/sync", json={"sections": ["users"]}).status_code == 422
    assert client.patch("/api/settings/sync", json={"interval_seconds": 5}).status_code == 422
    assert client.post("/api/sync/now").status_code == 400
    status = client.get("/api/sync/status").json()
    assert status["status"]["enabled"] is False
    assert "denylist" in status["default_sections"]
