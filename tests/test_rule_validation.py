# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from app.blocklist import BlocklistManager
from app.domain_suffix import normalize_domain
from app.stats import Stats
from app.web.server import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, create_app


@pytest.fixture
def client(config_store, tmp_path):
    config_store.mutate(lambda d: d.setdefault("web", {}).update({"https_enabled": False}))
    blocklist = BlocklistManager(config_store, tmp_path / "cache")
    stats = Stats(tmp_path / "stats.db", config_store)
    c = TestClient(create_app(config_store, blocklist, stats, started_at=0.0, data_dir=tmp_path))
    assert c.post("/api/login", json={"username": "admin", "password": "changeme"}).status_code == 200
    c.headers[CSRF_HEADER_NAME] = c.cookies[CSRF_COOKIE_NAME]
    return c


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("Example.COM.", "example.com"),
        ("*.ads.example.com", "ads.example.com"),
        ("https://ads.example.com/path?x=1", "ads.example.com"),
        ("żółw.pl", "xn--w-uga1v8h.pl"),
        ("wpad", "wpad"),
    ],
)
def test_normalize_domain_accepts(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["edge0/audio8-tts-preview-0.6b", "a b.com", "1.2.3.4:53", "-x.com", "", "x..com"])
def test_normalize_domain_rejects(raw):
    with pytest.raises(ValueError):
        normalize_domain(raw)


@pytest.mark.parametrize(
    "path",
    [
        "/api/rules/allow",
        "/api/rules/deny",
        "/api/log-ignore/domains",
        "/api/typosquat-domains",
        "/api/alert-rules/domains",
        "/api/anomaly-exclusions",
        "/api/anomaly-subdomain-exclusions",
    ],
)
def test_domain_lists_refuse_paths_and_urls_without_a_host(client, path):
    response = client.post(path, json={"domain": "edge0/audio8-tts-preview-0.6b"})
    assert response.status_code == 422
    assert "not a valid domain" in response.text


def test_domain_list_normalizes_pasted_url(client):
    assert client.post("/api/rules/deny", json={"domain": "https://Ads.Example.com/x"}).json() == ["ads.example.com"]


def test_bad_entries_saved_by_older_versions_can_be_removed(client, config_store):
    config_store.mutate(lambda d: d.update({"denylist": ["edge0/audio8-tts-preview-0.6b", "ok.example.com"]}))
    response = client.delete("/api/rules/deny/" + quote("edge0/audio8-tts-preview-0.6b", safe=""))
    assert response.status_code == 200, response.text
    assert response.json() == ["ok.example.com"]


def test_client_and_ip_lists_are_validated_and_cidrs_removable(client):
    assert client.post("/api/rules/deny-client", json={"value": "not a client"}).status_code == 400
    assert client.post("/api/rules/deny-client", json={"value": "10.0.0.0/8"}).status_code == 200
    assert client.delete("/api/rules/deny-client/" + quote("10.0.0.0/8", safe="")).json() == []

    assert client.post("/api/rules/deny-answer-ip", json={"value": "abc"}).status_code == 400
    assert client.post("/api/rules/deny-answer-ip", json={"value": "203.0.113.0/24"}).status_code == 200
    assert client.delete("/api/rules/deny-answer-ip/" + quote("203.0.113.0/24", safe="")).status_code == 200

    assert client.post("/api/log-ignore/clients", json={"value": "x"}).status_code == 400
    assert client.post("/api/log-ignore/clients", json={"value": "192.168.1.0/24"}).status_code == 200
    assert client.delete("/api/log-ignore/clients/192.168.1.0/24").json() == []


def test_mac_client_block_can_be_removed(client):
    assert client.post("/api/rules/deny-client", json={"value": "mac:aa-bb-cc-dd-ee-ff"}).status_code == 200
    assert client.delete("/api/rules/deny-client/mac:AA:BB:CC:DD:EE:FF").json() == []


def test_query_parameters_are_bounded(client):
    assert client.get("/api/stats?log_n=100000000").status_code == 422
    assert client.get("/api/stats?top_n=0").status_code == 422
    assert client.get("/api/stats?top_n=10&log_n=10").status_code == 200
    assert client.get("/api/query-log?limit=0").status_code == 422
    assert client.get("/api/query-log?offset=-1").status_code == 422
    assert client.post("/api/pause", json={"seconds": -5}).status_code == 422
    assert client.patch("/api/settings/anomaly", json={"check_interval_minutes": 0}).status_code == 422
