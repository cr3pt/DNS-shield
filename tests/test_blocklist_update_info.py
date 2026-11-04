import contextlib
import os

import app.blocklist as blocklist_mod
from app.blocklist import BlocklistManager


def _configure(config_store):
    config_store.mutate(
        lambda d: d.setdefault("blocklists", {}).update(
            {"sources": [{"name": "ListA", "url": "https://a.example/list.txt", "enabled": True}]}
        )
    )


class _Resp:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        return None


def _no_guard(monkeypatch):
    monkeypatch.setattr(blocklist_mod, "check_public_url", lambda url: None)
    monkeypatch.setattr(blocklist_mod, "public_dns_guard", lambda url: contextlib.nullcontext())


def test_warm_start_reports_cache_file_time(config_store, tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    cache_file = cache_dir / "ListA.cache"
    cache_file.write_text("ads.example.com\n", encoding="utf-8")
    os.utime(cache_file, (1_700_000_000, 1_700_000_000))
    _configure(config_store)

    blocklist = BlocklistManager(config_store, cache_dir)
    blocklist.refresh(network=False)

    info = blocklist.source_update_info()["ListA"]
    assert info == {"updated_at": 1_700_000_000, "checked_at": None, "error": None}


def test_never_downloaded_source_has_no_update_time(config_store, tmp_path):
    _configure(config_store)
    blocklist = BlocklistManager(config_store, tmp_path / "cache")
    blocklist.refresh(network=False)

    assert blocklist.source_update_info()["ListA"]["updated_at"] is None


def test_successful_download_sets_update_time(config_store, tmp_path, monkeypatch):
    _configure(config_store)
    _no_guard(monkeypatch)
    monkeypatch.setattr(blocklist_mod.requests, "get", lambda url, timeout: _Resp("ads.example.com\n"))

    blocklist = BlocklistManager(config_store, tmp_path / "cache")
    blocklist.refresh()

    info = blocklist.source_update_info()["ListA"]
    assert info["updated_at"] is not None
    assert info["checked_at"] is not None
    assert info["error"] is None
    assert blocklist.is_blocked("ads.example.com")


def test_failed_download_keeps_previous_update_time_and_reports_error(config_store, tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    cache_file = cache_dir / "ListA.cache"
    cache_file.write_text("ads.example.com\n", encoding="utf-8")
    os.utime(cache_file, (1_700_000_000, 1_700_000_000))
    _configure(config_store)
    _no_guard(monkeypatch)

    def boom(url, timeout):
        raise ConnectionError("network down")

    monkeypatch.setattr(blocklist_mod.requests, "get", boom)

    blocklist = BlocklistManager(config_store, cache_dir)
    blocklist.refresh()

    info = blocklist.source_update_info()["ListA"]
    assert info["updated_at"] == 1_700_000_000
    assert info["checked_at"] is not None
    assert info["error"] == "network down"
    assert blocklist.is_blocked("ads.example.com")
