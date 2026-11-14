# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Blocking whole services (YouTube, TikTok, ...) globally and per group."""

from app import services
from app.blocklist import BlocklistManager
from app.import_adguard import import_config
from tests.test_client_groups_api import _admin_client, _create


def test_catalog_domains_are_unique_and_lowercase():
    seen = {}
    for service_id, service in services.SERVICES.items():
        assert service_id == service_id.lower()
        for domain in service["domains"]:
            assert domain == domain.lower().strip(".")
            assert domain not in seen, f"{domain} in {seen.get(domain)} and {service_id}"
            seen[domain] = service_id


def test_service_for_matches_subdomains_only():
    assert services.service_for("www.youtube.com") == "youtube"
    assert services.service_for("r3---sn-abc.googlevideo.com.") == "youtube"
    assert services.service_for("youtube.com") == "youtube"
    assert services.service_for("notyoutube.com") is None
    assert services.service_for("google.com") is None
    assert services.blocked_service("v16.tiktokcdn.com", ["tiktok"]) == "tiktok"
    assert services.blocked_service("v16.tiktokcdn.com", ["youtube"]) is None
    assert services.blocked_service("v16.tiktokcdn.com", None) is None


def test_global_and_group_services_block(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    group_id = _create(client, name="Kids", match=("10.0.0.5",))[0]["id"]
    manager = BlocklistManager(config_store, tmp_path / "bl")

    catalog = client.get("/api/services").json()
    assert any(s["id"] == "youtube" for s in catalog["services"])
    assert catalog["blocked"] == []

    assert client.put("/api/blocked-services", json={"services": ["tiktok"]}).status_code == 200
    assert client.put(f"/api/client-groups/{group_id}/blocked-services", json={"services": ["youtube", "roblox"]}).status_code == 200

    assert manager.block_reason("www.tiktok.com", "10.0.0.9") == "Blocked service: TikTok"
    assert manager.block_reason("www.youtube.com", "10.0.0.9") is None
    assert manager.block_reason("www.youtube.com", "10.0.0.5") == 'Blocked service: YouTube (client group "Kids")'
    assert manager.block_reason("www.tiktok.com", "10.0.0.5") == "Blocked service: TikTok"

    assert client.put("/api/blocked-services", json={"services": ["nope"]}).status_code == 422
    assert client.get("/api/services").json()["blocked"] == ["tiktok"]


def test_adguard_blocked_services_are_imported():
    adguard = {
        "filtering": {"blocked_services": {"ids": ["youtube", "amazon_video", "something_else"]}},
        "clients": {
            "persistent": [
                {
                    "name": "Kid",
                    "ids": ["10.0.0.5"],
                    "use_global_blocked_services": False,
                    "blocked_services": {"ids": ["tiktok", "epic_games"]},
                }
            ]
        },
    }
    result, warnings = import_config(adguard, {})
    assert result["blocked_services"] == ["primevideo", "youtube"]
    assert result["client_groups"][0]["blocked_services"] == ["tiktok", "fortnite"]
    assert any("something_else" in w for w in warnings)
