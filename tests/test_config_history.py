# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Every config change is kept as a version that can be rolled back."""

from app.config import HISTORY_MAX_VERSIONS, ConfigStore, config_actor
from tests.test_client_groups_api import _admin_client


def _store(tmp_path):
    return ConfigStore(db_path=tmp_path / "config.db", backup_path=tmp_path / "config.backup.yaml")


def test_changes_are_versioned_with_sections_and_actor(tmp_path):
    store = _store(tmp_path)
    assert [v["actor"] for v in store.history()] == ["startup"]
    token = config_actor.set("alice: POST /api/rules/deny")
    try:
        store.mutate(lambda d: d.update(denylist=["ads.example"]))
    finally:
        config_actor.reset(token)
    # Same content again: no new version.
    store.mutate(lambda d: d.update(denylist=["ads.example"]))
    newest = store.history()[0]
    assert newest["actor"] == "alice: POST /api/rules/deny"
    assert newest["changed"] == ["denylist"]
    assert len(store.history()) == 2


def test_account_changes_are_not_versioned_nor_restored(tmp_path):
    store = _store(tmp_path)
    store.mutate(lambda d: d.update(users=[{"username": "admin", "password_hash": "old"}]))
    assert len(store.history()) == 1
    first = store.history()[0]["id"]
    store.mutate(lambda d: d.update(denylist=["x.example"], users=[{"username": "admin", "password_hash": "new"}]))
    changed = store.restore_version(first)
    assert changed == ["denylist"]
    assert store.get("denylist") in (None, [])
    assert store.get("users")[0]["password_hash"] == "new"
    assert "restore of version" in store.history()[0]["actor"]


def test_restore_unknown_version(tmp_path):
    assert _store(tmp_path).restore_version(999999) is None


def test_history_is_capped(tmp_path):
    store = _store(tmp_path)
    for i in range(HISTORY_MAX_VERSIONS + 5):
        store.mutate(lambda d, i=i: d.update(denylist=[f"d{i}.example"]))
    assert len(store.history(limit=1000)) == HISTORY_MAX_VERSIONS


def test_history_api_diff_and_restore(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    assert client.post("/api/rules/deny", json={"domain": "ads.example"}).status_code == 200
    versions = client.get("/api/config-history").json()
    assert versions[0]["current"] is True
    assert versions[0]["actor"] == "admin: POST /api/rules/deny"
    assert "denylist" in versions[0]["changed"]

    diff = client.get(f"/api/config-history/{versions[0]['id']}").json()["diff"]
    assert "+- ads.example" in diff

    response = client.post(f"/api/config-history/{versions[1]['id']}/restore")
    assert response.status_code == 200
    assert "denylist" in response.json()["changed"]
    assert "ads.example" not in (config_store.get("denylist") or [])
    # Still signed in: accounts weren't touched.
    assert client.get("/api/config-history").status_code == 200
    assert client.post("/api/config-history/999999/restore").status_code == 404
