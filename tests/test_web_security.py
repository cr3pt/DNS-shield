from fastapi.testclient import TestClient

from app.blocklist import BlocklistManager
from app.stats import Stats
from app.web.server import create_app


def _client(config_store, tmp_path) -> TestClient:
    blocklist = BlocklistManager(config_store, tmp_path / "cache")
    stats = Stats(tmp_path / "stats.db", config_store)
    app = create_app(config_store, blocklist, stats, started_at=0.0)
    return TestClient(app)


def test_openapi_schema_is_disabled(config_store, tmp_path):
    client = _client(config_store, tmp_path)

    response = client.get("/openapi.json")

    assert response.status_code == 404


def test_docs_and_redoc_are_disabled(config_store, tmp_path):
    client = _client(config_store, tmp_path)

    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404


def test_security_headers_present_on_every_response(config_store, tmp_path):
    client = _client(config_store, tmp_path)

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "geolocation=()" in response.headers["Permissions-Policy"]
    assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert response.headers["Cross-Origin-Resource-Policy"] == "same-origin"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_hsts_absent_over_plain_http(config_store, tmp_path):
    client = _client(config_store, tmp_path)

    response = client.get("/healthz")

    assert "Strict-Transport-Security" not in response.headers
