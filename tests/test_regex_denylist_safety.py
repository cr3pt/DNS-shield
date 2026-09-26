import time

import pytest

from app.blocklist import BlocklistManager, check_regex_pattern_safety


def test_check_regex_pattern_safety_accepts_normal_patterns():
    check_regex_pattern_safety(r"^ads\.")
    check_regex_pattern_safety(r"track(er)?\.example\.(com|net)$")


def test_check_regex_pattern_safety_rejects_catastrophic_backtracking():
    with pytest.raises(ValueError, match="catastrophic backtracking"):
        check_regex_pattern_safety(r"^(a|a)*$")


def test_block_reason_with_regex_denylist_does_not_hang_on_catastrophic_pattern(config_store, tmp_path):
    manager = BlocklistManager(config_store, tmp_path / "cache")
    config_store.mutate(
        lambda d: d.update(
            {
                "dns": {**(d.get("dns") or {}), "regex_denylist_enabled": True},
                "denylist_regex": [r"^(a|a)*$"],
            }
        )
    )

    start = time.time()
    reason = manager.block_reason("a" * 40 + "evil.example.com", "10.0.0.5")
    elapsed = time.time() - start

    assert elapsed < 2.0
    assert reason is None


def test_block_reason_still_matches_safe_regex_pattern(config_store, tmp_path):
    manager = BlocklistManager(config_store, tmp_path / "cache")
    config_store.mutate(
        lambda d: d.update(
            {
                "dns": {**(d.get("dns") or {}), "regex_denylist_enabled": True},
                "denylist_regex": [r"^ads\."],
            }
        )
    )

    reason = manager.block_reason("ads.example.com", "10.0.0.5")

    assert reason is not None
    assert "regex" in reason.lower()
