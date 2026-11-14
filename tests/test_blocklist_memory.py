# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Labelling a block with its list doesn't need a domain -> list dict."""

import time

from app import blocklist as blocklist_module
from app.blocklist import BlocklistManager, _SourceIndex


def test_source_index_follows_list_order_and_exceptions():
    index = _SourceIndex([("first", {"a.com", "b.com"}, {"b.com"}), ("second", {"b.com", "c.com"}, set())])
    assert index.get("a.com") == "first"
    assert index.get("b.com") == "second"  # excepted in the first list
    assert index.get("x.com") is None and index.get("x.com", "-") == "-"
    assert index.setdefault("x.com", "manually added") == "manually added"
    assert index.setdefault("a.com", "manually added") == "first"
    assert index.get("x.com") == "manually added"


def _manager(config_store, tmp_path, lists):
    config_store.mutate(
        lambda d: d.setdefault("blocklists", {}).update(
            {"sources": [{"name": name, "url": f"https://lists.example/{name}"} for name in lists]}
        )
    )
    manager = BlocklistManager(config_store, tmp_path / "bl")
    manager._download = lambda url: lists[url.rsplit("/", 1)[1]]
    return manager


def test_block_reason_names_the_list(config_store, tmp_path):
    manager = _manager(config_store, tmp_path, {"ads": "||ads.example^\n", "trackers": "||t.example^\n"})
    manager.refresh()
    assert manager.block_reason("x.ads.example") == "Blocklist: ads"
    assert manager.block_reason("t.example") == "Blocklist: trackers"
    assert isinstance(manager._domain_source, _SourceIndex)


def test_removed_lists_leave_the_fetch_cache(config_store, tmp_path, monkeypatch):
    manager = _manager(config_store, tmp_path, {"ads": "||ads.example^\n", "old": "||old.example^\n"})
    manager.refresh()
    assert len(manager._fetch_cache) == 2
    config_store.mutate(lambda d: d["blocklists"]["sources"].pop())
    real_time = time.time
    monkeypatch.setattr(blocklist_module.time, "time", lambda: real_time() + 120)
    manager.refresh()
    assert [key[0] for key in manager._fetch_cache] == ["https://lists.example/ads"]
    assert manager.block_reason("old.example") is None
