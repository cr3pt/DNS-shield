# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from fastapi.testclient import TestClient

from app.blocklist import BlocklistManager
from app.graph import ClientDomainGraph
from app.stats import Stats
from app.web.server import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, create_app


def _admin_client(config_store, tmp_path) -> TestClient:
    config_store.mutate(lambda d: d.setdefault("web", {}).update({"https_enabled": False}))
    stats = Stats(tmp_path / "stats.db", config_store)
    graph = ClientDomainGraph(config_store, stats, tmp_path / "graph.db")
    app = create_app(
        config_store,
        BlocklistManager(config_store, tmp_path / "cache"),
        stats,
        started_at=0.0,
        data_dir=tmp_path,
        client_domain_graph=graph,
    )
    client = TestClient(app)
    client.stats = stats
    assert client.post("/api/login", json={"username": "admin", "password": "changeme"}).status_code == 200
    client.headers[CSRF_HEADER_NAME] = client.cookies[CSRF_COOKIE_NAME]
    return client


def test_graph_endpoint_defaults_to_the_client_domain_view(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)

    body = client.get("/api/graph").json()

    assert body["view"] == "bipartite"
    assert body["links"] == []


def test_graph_endpoint_accepts_every_known_view(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)

    for view in ("bipartite", "domains", "clients"):
        response = client.get("/api/graph", params={"view": view})
        assert response.status_code == 200
        assert response.json()["view"] == view


def test_graph_endpoint_rejects_an_unknown_view(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)

    assert client.get("/api/graph", params={"view": "everything"}).status_code == 400


def _seeded_client(config_store, tmp_path):
    import sqlite3

    config_store.mutate(
        lambda d: d.update(
            {
                "web": {"https_enabled": False},
                "client_groups": [
                    {"name": "Kids", "match": ["192.168.1.0/28"], "enabled": True},
                    {"name": "Guests", "match": ["10.1.0.0/24"], "enabled": True},
                    {"name": "Empty", "match": ["172.16.0.1"], "enabled": True},
                ],
            }
        )
    )
    client = _admin_client(config_store, tmp_path)
    conn = sqlite3.connect(tmp_path / "graph.db")
    rows = [
        ("192.168.1.5", "kids-only.example", 4),
        ("192.168.1.6", "shared.example", 2),
        ("10.1.0.7", "shared.example", 3),
        ("10.1.0.7", "guest-only.example", 1),
        ("192.168.1.99", "plain.example", 5),
    ]
    for client_ip, domain, count in rows:
        conn.execute("INSERT INTO edges VALUES (?,?,?,?,?,?)", (client_ip, domain, count, 0, 1.0, 2.0))
    conn.commit()
    conn.close()
    return client


def _ids(body, key):
    return sorted(node["id"] for node in body[key])


def test_graph_can_be_limited_to_one_client_group(config_store, tmp_path):
    client = _seeded_client(config_store, tmp_path)

    body = client.get("/api/graph", params={"group": "Kids"}).json()

    assert _ids(body, "clients") == ["192.168.1.5", "192.168.1.6"]
    assert _ids(body, "domains") == ["kids-only.example", "shared.example"]
    assert {edge["client"] for edge in body["edges"]} == {"192.168.1.5", "192.168.1.6"}


def test_graph_can_show_only_clients_outside_every_group(config_store, tmp_path):
    client = _seeded_client(config_store, tmp_path)

    body = client.get("/api/graph", params={"no_group": "true"}).json()

    assert _ids(body, "clients") == ["192.168.1.99"]
    assert _ids(body, "domains") == ["plain.example"]


def test_group_filter_works_in_the_projection_views_too(config_store, tmp_path):
    client = _seeded_client(config_store, tmp_path)

    body = client.get("/api/graph", params={"group": "Guests", "view": "domains"}).json()

    assert _ids(body, "domains") == ["guest-only.example", "shared.example"]
    assert body["clients"] == []


def test_a_group_without_graph_history_gives_an_empty_graph(config_store, tmp_path):
    client = _seeded_client(config_store, tmp_path)

    body = client.get("/api/graph", params={"group": "Empty"}).json()

    assert body["clients"] == [] and body["domains"] == [] and body["edges"] == []


def test_graph_response_lists_every_group_whatever_the_filter(config_store, tmp_path):
    client = _seeded_client(config_store, tmp_path)

    assert client.get("/api/graph").json()["groups"] == ["Kids", "Guests", "Empty"]
    assert client.get("/api/graph", params={"group": "Kids"}).json()["groups"] == ["Kids", "Guests", "Empty"]


def test_graph_rejects_an_unknown_group_and_conflicting_options(config_store, tmp_path):
    client = _seeded_client(config_store, tmp_path)

    assert client.get("/api/graph", params={"group": "Nope"}).status_code == 404
    assert client.get("/api/graph", params={"group": "Kids", "no_group": "true"}).status_code == 400


def test_domain_detail_follows_the_selected_group(config_store, tmp_path):
    client = _seeded_client(config_store, tmp_path)

    everyone = client.get("/api/graph/domain/shared.example").json()
    kids = client.get("/api/graph/domain/shared.example", params={"group": "Kids"}).json()

    assert sorted(c["client"] for c in everyone["clients"]) == ["10.1.0.7", "192.168.1.6"]
    assert [c["client"] for c in kids["clients"]] == ["192.168.1.6"]
    assert kids["distinct_clients"] == 1


def test_restricted_users_group_filter_stays_within_their_own_clients(config_store, tmp_path):
    import time

    from app.auth import hash_password

    client = _seeded_client(config_store, tmp_path)
    for ip in ("192.168.1.5", "192.168.1.6", "10.1.0.7", "192.168.1.99"):
        client.stats.record("seen.example", False, ip, "A")
    deadline = time.time() + 5
    while len(client.stats.distinct_clients()) < 4 and time.time() < deadline:
        time.sleep(0.05)
    config_store.mutate(
        lambda d: d.setdefault("users", []).append(
            {
                "username": "parent",
                "password_hash": hash_password("pw-parent-1"),
                "role": "user",
                "permissions": {"view_graph": True, "allowed_clients": ["192.168.1.5", "10.1.0.7"]},
            }
        )
    )
    other = TestClient(client.app)
    assert other.post("/api/login", json={"username": "parent", "password": "pw-parent-1"}).status_code == 200

    kids = other.get("/api/graph", params={"group": "Kids"}).json()
    guests = other.get("/api/graph", params={"group": "Guests"}).json()
    outside = other.get("/api/graph", params={"no_group": "true"}).json()

    assert _ids(kids, "clients") == ["192.168.1.5"]
    assert _ids(guests, "clients") == ["10.1.0.7"]
    assert outside["clients"] == []
    assert kids["groups"] == ["Guests", "Kids"]
