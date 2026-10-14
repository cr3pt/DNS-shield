# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from fastapi.testclient import TestClient

from app.blocklist import BlocklistManager
from app.stats import Stats
from app.web.server import CSRF_COOKIE_NAME, CSRF_HEADER_NAME
from app.web.server import create_app


def _client(config_store, tmp_path, data_dir=None) -> TestClient:
    blocklist = BlocklistManager(config_store, tmp_path / "cache")
    stats = Stats(tmp_path / "stats.db", config_store)
    app = create_app(config_store, blocklist, stats, started_at=0.0, data_dir=data_dir or tmp_path)
    return TestClient(app)


def _admin_client(config_store, tmp_path, data_dir=None) -> TestClient:
    config_store.mutate(lambda d: d.setdefault("web", {}).update({"https_enabled": False}))
    client = _client(config_store, tmp_path, data_dir=data_dir)
    response = client.post("/api/login", json={"username": "admin", "password": "changeme"})
    assert response.status_code == 200
    client.headers[CSRF_HEADER_NAME] = client.cookies[CSRF_COOKIE_NAME]
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


def test_deny_regex_rejects_catastrophic_backtracking_pattern(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)

    response = client.post("/api/rules/deny-regex", json={"pattern": "^(a|a)*$"})

    assert response.status_code == 400
    assert "backtracking" in response.json()["detail"]
    assert config_store.get("denylist_regex", default=[]) == []


def test_deny_regex_accepts_safe_pattern(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)

    response = client.post("/api/rules/deny-regex", json={"pattern": r"^ads\."})

    assert response.status_code == 200
    assert r"^ads\." in config_store.get("denylist_regex", default=[])


def test_add_blocklist_rejects_ssrf_target(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)

    response = client.post(
        "/api/blocklists", json={"name": "ssrf-test", "url": "http://127.0.0.1:8899/poc", "enabled": True}
    )

    assert response.status_code == 400
    assert "SSRF" in response.json()["detail"]
    names = [s["name"] for s in config_store.get("blocklists", "sources", default=[])]
    assert "ssrf-test" not in names


def test_add_blocklist_accepts_public_url(config_store, tmp_path, monkeypatch):
    from app.blocklist import BlocklistManager

    monkeypatch.setattr(BlocklistManager, "refresh", lambda self: None)
    client = _admin_client(config_store, tmp_path)

    response = client.post(
        "/api/blocklists", json={"name": "public-test", "url": "http://1.1.1.1/list.txt", "enabled": True}
    )

    assert response.status_code == 200
    names = [s["name"] for s in response.json()]
    assert "public-test" in names


def test_clear_secret_requires_admin(config_store, tmp_path):
    client = _client(config_store, tmp_path)

    response = client.post("/api/settings/clear-secret", json={"path": "enrichment.virustotal_api_key"})

    assert response.status_code == 401


def test_clear_secret_rejects_unknown_path(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)

    response = client.post("/api/settings/clear-secret", json={"path": "dns.listen_address"})

    assert response.status_code == 400


def test_clear_secret_clears_enrichment_key(config_store, tmp_path):
    config_store.mutate(lambda d: d.setdefault("enrichment", {}).update({"virustotal_api_key": "super-secret-key"}))
    client = _admin_client(config_store, tmp_path)

    response = client.post("/api/settings/clear-secret", json={"path": "enrichment.virustotal_api_key"})

    assert response.status_code == 200
    assert config_store.get("enrichment", "virustotal_api_key", default=None) == ""


def test_clear_secret_clears_nested_smtp_password(config_store, tmp_path):
    config_store.mutate(
        lambda d: d.setdefault("notifications", {}).setdefault("email", {}).update({"smtp_password": "hunter2"})
    )
    client = _admin_client(config_store, tmp_path)

    response = client.post("/api/settings/clear-secret", json={"path": "notifications.email.smtp_password"})

    assert response.status_code == 200
    assert config_store.get("notifications", "email", "smtp_password", default=None) == ""


def test_mutating_request_with_session_cookie_but_no_csrf_header_is_rejected(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    del client.headers[CSRF_HEADER_NAME]

    response = client.post("/api/rules/deny-regex", json={"pattern": r"^ads\."})

    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]


def test_mutating_request_with_wrong_csrf_header_is_rejected(config_store, tmp_path):
    client = _admin_client(config_store, tmp_path)
    client.headers[CSRF_HEADER_NAME] = "not-the-right-token"

    response = client.post("/api/rules/deny-regex", json={"pattern": r"^ads\."})

    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]


def test_login_itself_is_exempt_from_csrf_check(config_store, tmp_path):
    config_store.mutate(lambda d: d.setdefault("web", {}).update({"https_enabled": False}))
    client = _client(config_store, tmp_path)

    response = client.post("/api/login", json={"username": "admin", "password": "changeme"})

    assert response.status_code == 200
    assert CSRF_COOKIE_NAME in response.cookies


def test_bearer_token_request_is_not_subject_to_csrf_check(config_store, tmp_path):
    from app.users import UserStore

    client = _client(config_store, tmp_path)
    users = UserStore(config_store)
    token, _ = users.create_token("admin", "ci token")

    response = client.post(
        "/api/rules/deny-regex",
        json={"pattern": r"^ads\."},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200


def test_changing_typosquat_max_distance_clears_the_match_cache(config_store, tmp_path):
    blocklist = BlocklistManager(config_store, tmp_path / "cache")
    stats = Stats(tmp_path / "stats.db", config_store)
    config_store.mutate(lambda d: d.setdefault("web", {}).update({"https_enabled": False}))
    config_store.mutate(lambda d: d.setdefault("dns", {}).update({"typosquat_enabled": True}))
    app = create_app(config_store, blocklist, stats, started_at=0.0, data_dir=tmp_path)
    client = TestClient(app)
    response = client.post("/api/login", json={"username": "admin", "password": "changeme"})
    assert response.status_code == 200
    client.headers[CSRF_HEADER_NAME] = client.cookies[CSRF_COOKIE_NAME]

    blocklist.typosquat_match("gooogle.com")
    assert "gooogle.com" in blocklist._typosquat_cache

    response = client.patch("/api/settings/dns", json={"typosquat_max_distance": 3})

    assert response.status_code == 200
    assert blocklist._typosquat_cache == {}
