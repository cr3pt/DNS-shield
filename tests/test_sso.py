# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from fastapi.testclient import TestClient

import app.web.server as server_module
from app.blocklist import BlocklistManager
from app.stats import Stats
from app.web.server import PendingSSOStore, create_app


def _sso_client(config_store, tmp_path, monkeypatch, claims):
    config_store.mutate(
        lambda d: d.update(
            {
                "web": {"https_enabled": False},
                "sso": {
                    "enabled": True,
                    "issuer": "https://idp.example.com",
                    "client_id": "dns-shield",
                    "client_secret": "secret",
                    "auto_provision": True,
                    "default_role": "user",
                },
            }
        )
    )
    monkeypatch.setattr(PendingSSOStore, "consume", lambda self, state: {"nonce": "n", "next": "/"})
    monkeypatch.setattr(server_module, "exchange_code", lambda cfg, redirect_uri, code: ({"id_token": "fake"}, {}))
    monkeypatch.setattr(server_module, "verify_id_token", lambda id_token, metadata, cfg, nonce: claims)

    blocklist = BlocklistManager(config_store, tmp_path / "cache")
    stats = Stats(tmp_path / "stats.db", config_store)
    app_ = create_app(config_store, blocklist, stats, started_at=0.0, data_dir=tmp_path)
    return TestClient(app_, follow_redirects=False)


def test_sso_cannot_hijack_an_existing_local_password_account(config_store, tmp_path, monkeypatch):
    client = _sso_client(config_store, tmp_path, monkeypatch, claims={"preferred_username": "admin"})

    response = client.get("/api/sso/callback", params={"code": "fake-code", "state": "fake-state"})

    assert response.status_code in (302, 307)
    assert "sso_account_conflict" in response.headers["location"]
    assert "session" not in response.cookies


def test_sso_auto_provisions_a_new_account_for_an_unknown_identity(config_store, tmp_path, monkeypatch):
    client = _sso_client(config_store, tmp_path, monkeypatch, claims={"preferred_username": "newsso.user"})

    response = client.get("/api/sso/callback", params={"code": "fake-code", "state": "fake-state"})

    assert response.status_code in (302, 307)
    assert "error" not in response.headers["location"]


def test_sso_can_log_back_into_its_own_previously_provisioned_account(config_store, tmp_path, monkeypatch):
    client = _sso_client(config_store, tmp_path, monkeypatch, claims={"preferred_username": "repeat.sso.user"})
    first = client.get("/api/sso/callback", params={"code": "fake-code", "state": "fake-state"})
    assert "error" not in first.headers["location"]

    monkeypatch.setattr(PendingSSOStore, "consume", lambda self, state: {"nonce": "n", "next": "/"})
    second = client.get("/api/sso/callback", params={"code": "fake-code-2", "state": "fake-state-2"})

    assert "error" not in second.headers["location"]
