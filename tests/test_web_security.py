from fastapi.testclient import TestClient

from app.blocklist import BlocklistManager
from app.stats import Stats
from app.web.server import create_app


def _client(config_store, tmp_path, data_dir=None) -> TestClient:
    blocklist = BlocklistManager(config_store, tmp_path / "cache")
    stats = Stats(tmp_path / "stats.db", config_store)
    app = create_app(config_store, blocklist, stats, started_at=0.0, data_dir=data_dir or tmp_path)
    return TestClient(app)


def _admin_client(config_store, tmp_path, data_dir=None) -> TestClient:
    client = _client(config_store, tmp_path, data_dir=data_dir)
    response = client.post("/api/login", json={"username": "admin", "password": "changeme"})
    assert response.status_code == 200
    return client


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


def test_https_migration_requires_admin(config_store, tmp_path):
    client = _client(config_store, tmp_path)

    response = client.post("/api/settings/web/migrate-https")

    assert response.status_code == 401


def test_https_migration_enables_https_and_generates_cert(config_store, tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config_store.mutate(lambda d: d.setdefault("web", {}).update({"https_enabled": False}))
    client = _admin_client(config_store, tmp_path, data_dir=data_dir)

    response = client.post("/api/settings/web/migrate-https")

    assert response.status_code == 200
    body = response.json()
    assert body["https_enabled"] is True
    assert body["restart_required"] is True
    assert config_store.get("web", "https_enabled", default=False) is True
    assert (data_dir / "tls" / "cert.pem").exists()
    assert (data_dir / "tls" / "key.pem").exists()


def test_https_migration_reuses_existing_cert(config_store, tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "tls").mkdir()
    cert_path = data_dir / "tls" / "cert.pem"
    key_path = data_dir / "tls" / "key.pem"
    cert_path.write_text("existing-cert")
    key_path.write_text("existing-key")
    config_store.mutate(lambda d: d.setdefault("web", {}).update({"https_enabled": False}))
    client = _admin_client(config_store, tmp_path, data_dir=data_dir)

    response = client.post("/api/settings/web/migrate-https")

    assert response.status_code == 200
    assert cert_path.read_text() == "existing-cert"
    assert key_path.read_text() == "existing-key"


def test_https_migration_skips_self_signed_cert_when_custom_paths_configured(config_store, tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config_store.mutate(
        lambda d: d.setdefault("web", {}).update(
            {"https_enabled": False, "https_cert_path": "/custom/cert.pem", "https_key_path": "/custom/key.pem"}
        )
    )
    client = _admin_client(config_store, tmp_path, data_dir=data_dir)

    response = client.post("/api/settings/web/migrate-https")

    assert response.status_code == 200
    assert config_store.get("web", "https_enabled", default=False) is True
    assert not (data_dir / "tls").exists()
