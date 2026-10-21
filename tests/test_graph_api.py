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
