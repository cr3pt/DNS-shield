

def test_mutate_is_copy_on_write(tmp_path):
    from app.config import ConfigStore

    store = ConfigStore(db_path=tmp_path / "cow.db", backup_path=tmp_path / "cow.yaml")
    store.mutate(lambda d: d.update({"denylist": ["a.example"]}))
    held = store.get("denylist")
    version = store.version

    store.mutate(lambda d: d["denylist"].append("b.example"))

    assert held == ["a.example"]  # a reader's reference never changes under it
    assert store.get("denylist") == ["a.example", "b.example"]
    assert store.version == version + 1


def test_failed_mutate_leaves_config_untouched(tmp_path):
    import pytest

    from app.config import ConfigStore

    store = ConfigStore(db_path=tmp_path / "cow2.db", backup_path=tmp_path / "cow2.yaml")
    store.mutate(lambda d: d.update({"denylist": ["a.example"]}))

    def broken(d):
        d["denylist"].append("half-done.example")
        raise ValueError("nope")

    with pytest.raises(ValueError):
        store.mutate(broken)
    assert store.get("denylist") == ["a.example"]
