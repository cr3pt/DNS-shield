# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""A parent can cut a group's internet now, or allow it for a while despite
its bedtime schedule."""

import time

from app.blocklist import BlocklistManager
from app.schedule import group_access_override
from tests.test_client_groups_api import _admin_client, _create

_ALWAYS_BEDTIME = {
    "enabled": True,
    "timezone": "UTC",
    "windows": [{"days": [0, 1, 2, 3, 4, 5, 6], "start": "00:00", "end": "23:59"}],
}


def test_override_states():
    now = 1_000_000.0
    assert group_access_override(None, now) is None
    assert group_access_override({"internet_off": {"active": True, "until": None}}, now) == "off"
    assert group_access_override({"internet_off": {"active": True, "until": now + 60}}, now) == "off"
    assert group_access_override({"internet_off": {"active": True, "until": now - 1}}, now) is None
    assert group_access_override({"allow_until": now + 60}, now) == "on"
    assert group_access_override({"allow_until": now - 1}, now) is None


def _setup(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    group_id = _create(client, name="Kids", match=("10.0.0.5",))[0]["id"]
    manager = BlocklistManager(config_store, tmp_path / "bl2")
    return client, group_id, manager


def test_internet_off_blocks_everything_even_while_paused(config_store, tmp_path):
    client, group_id, manager = _setup(config_store, tmp_path)
    assert manager.block_reason("example.com", "10.0.0.5") is None
    response = client.put(f"/api/client-groups/{group_id}/internet-off", json={"minutes": None})
    assert response.status_code == 200 and response.json()["internet_off"]["until"] is None
    assert manager.block_reason("example.com", "10.0.0.5") == 'Internet off (client group "Kids")'
    assert manager.block_reason("example.com", "10.0.0.9") is None  # not in the group
    config_store.mutate(lambda d: d.update({"pause": {"active": True, "until": None}}))
    assert manager.block_reason("example.com", "10.0.0.5") is not None
    assert client.delete(f"/api/client-groups/{group_id}/internet-off").status_code == 200
    assert manager.block_reason("example.com", "10.0.0.5") is None


def test_timed_internet_off_ends_by_itself(config_store, tmp_path):
    client, group_id, manager = _setup(config_store, tmp_path)
    until = client.put(f"/api/client-groups/{group_id}/internet-off", json={"minutes": 30}).json()["internet_off"]["until"]
    assert 29 * 60 < until - time.time() <= 30 * 60
    config_store.mutate(lambda d: d["client_groups"][0]["internet_off"].update({"until": time.time() - 1}))
    assert manager.block_reason("example.com", "10.0.0.5") is None


def test_allow_now_lifts_the_bedtime_schedule(config_store, tmp_path):
    client, group_id, manager = _setup(config_store, tmp_path)
    config_store.mutate(lambda d: d["client_groups"][0].update({"schedule": _ALWAYS_BEDTIME}))
    assert manager.block_reason("example.com", "10.0.0.5").startswith("Scheduled block")
    client.put(f"/api/client-groups/{group_id}/internet-off", json={"minutes": 60})
    group = client.put(f"/api/client-groups/{group_id}/allow-now", json={"minutes": 30}).json()
    assert "internet_off" not in group and group["allow_until"] > time.time()
    assert manager.block_reason("example.com", "10.0.0.5") is None
    client.delete(f"/api/client-groups/{group_id}/allow-now")
    assert manager.block_reason("example.com", "10.0.0.5").startswith("Scheduled block")


def test_bounds(config_store, tmp_path):
    client, group_id, _manager = _setup(config_store, tmp_path)
    assert client.put(f"/api/client-groups/{group_id}/allow-now", json={"minutes": 0}).status_code == 422
    assert client.put(f"/api/client-groups/{group_id}/allow-now", json={}).status_code == 422
    assert client.put(f"/api/client-groups/{group_id}/internet-off", json={"minutes": 99999}).status_code == 422
    assert client.put("/api/client-groups/nope/internet-off", json={}).status_code == 404
