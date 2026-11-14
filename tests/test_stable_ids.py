# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""List entries are addressed by a stable id, so an action aimed at one entry
can't land on another after the list shifted underneath."""

from app.config import ConfigStore, ensure_item_ids
from tests.test_client_groups_api import _admin_client, _create


def test_ids_are_assigned_and_kept(tmp_path):
    data = {"client_groups": [{"name": "a"}, {"name": "b", "id": "keepme", "blocklist_sources": [{"url": "u"}]}]}
    assert ensure_item_ids(data) is True
    first, second = data["client_groups"]
    assert first["id"] and second["id"] == "keepme" and second["blocklist_sources"][0]["id"]
    assert ensure_item_ids(data) is False


def test_duplicate_ids_are_replaced():
    data = {"dns_rewrites": [{"name": "a", "id": "x"}, {"name": "b", "id": "x"}]}
    ensure_item_ids(data)
    assert data["dns_rewrites"][0]["id"] == "x" and data["dns_rewrites"][1]["id"] != "x"


def test_existing_config_gets_ids_on_load(tmp_path):
    store = ConfigStore(db_path=tmp_path / "c.db", backup_path=tmp_path / "b.yaml")
    store._save_to_db({"domain_upstreams": [{"domain": "lan", "upstreams": ["10.0.0.1:53"]}]})
    reopened = ConfigStore(db_path=tmp_path / "c.db", backup_path=tmp_path / "b.yaml")
    rule_id = reopened.get("domain_upstreams")[0]["id"]
    again = ConfigStore(db_path=tmp_path / "c.db", backup_path=tmp_path / "b.yaml")
    assert again.get("domain_upstreams")[0]["id"] == rule_id


def test_delete_by_id_survives_a_shifted_list(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    _create(client, name="Kids", match=("192.168.1.50",))
    groups = _create(client, name="Guests", match=("192.168.1.60",))
    guests_id = next(g["id"] for g in groups if g["name"] == "Guests")
    # someone else removes the first group: "Guests" moves from index 1 to 0
    assert client.delete("/api/client-groups/0").status_code == 200
    assert client.delete(f"/api/client-groups/{guests_id}").status_code == 200
    assert client.get("/api/client-groups").json() == []
    assert client.delete(f"/api/client-groups/{guests_id}").status_code == 404


def test_group_routes_accept_ids(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    group_id = _create(client)[0]["id"]
    response = client.put(f"/api/client-groups/{group_id}/name", json={"name": "Children"})
    assert response.status_code == 200 and response.json()["id"] == group_id
    assert client.put("/api/client-groups/nosuchid/name", json={"name": "X"}).status_code == 404
