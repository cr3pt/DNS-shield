# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Web UI changes reload the lists in the background, coalescing bursts."""

import threading
import time

from app.blocklist import BlocklistManager
from tests.test_client_groups_api import _admin_client


def test_requests_during_a_refresh_fold_into_one_more(config_store, tmp_path, monkeypatch):
    manager = BlocklistManager(config_store, tmp_path / "bl")
    gate = threading.Event()
    calls = []

    def slow_refresh(network=True):
        calls.append(time.monotonic())
        gate.wait(5)

    monkeypatch.setattr(manager, "refresh", slow_refresh)
    manager.request_refresh()
    assert manager.refresh_pending()
    deadline = time.monotonic() + 5
    while not calls and time.monotonic() < deadline:
        time.sleep(0.01)
    for _ in range(5):
        manager.request_refresh()
    gate.set()
    assert manager.wait_for_refresh(5)
    assert len(calls) == 2  # the running one, plus one for everything asked meanwhile
    assert not manager.refresh_pending()


def test_a_failing_refresh_does_not_wedge_later_requests(config_store, tmp_path, monkeypatch):
    manager = BlocklistManager(config_store, tmp_path / "bl")
    outcomes = iter([RuntimeError("network down"), None])

    def flaky(network=True):
        outcome = next(outcomes)
        if outcome:
            raise outcome

    monkeypatch.setattr(manager, "refresh", flaky)
    manager.request_refresh()
    assert manager.wait_for_refresh(5)
    manager.request_refresh()
    assert manager.wait_for_refresh(5)


def test_adding_a_list_returns_before_it_downloads(config_store, tmp_path, monkeypatch):
    client = _admin_client(config_store, tmp_path)
    started = threading.Event()
    release = threading.Event()
    monkeypatch.setattr("app.web.routes.rules.check_public_url", lambda url: None)

    def slow_download(self, url):
        started.set()
        release.wait(5)
        return "||ads.example^\n"

    monkeypatch.setattr(BlocklistManager, "_download", slow_download)
    t0 = time.monotonic()
    response = client.post("/api/blocklists", json={"name": "ads", "url": "https://lists.example/ads.txt"})
    assert response.status_code == 200 and time.monotonic() - t0 < 2
    assert started.wait(5)
    assert client.get("/api/status").json()["blocklist_refreshing"] is True
    release.set()
    deadline = time.monotonic() + 5
    while client.get("/api/status").json()["blocklist_refreshing"] and time.monotonic() < deadline:
        time.sleep(0.05)
    status = client.get("/api/status").json()
    assert status["blocklist_refreshing"] is False and status["blocklist_domains"] == 1
