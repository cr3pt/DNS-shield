import pytest

from app.config import ConfigStore


class FakeStats:
    def __init__(self, hits=None):
        self._hits = hits or []

    def max_query_id(self):
        return 0

    def _since(self, last_id):
        return [h for h in self._hits if h["id"] > last_id]

    def typosquat_hits_since(self, last_id, limit=500):
        return self._since(last_id)

    def local_tld_hits_since(self, last_id, limit=500):
        return self._since(last_id)

    def rebinding_hits_since(self, last_id, limit=500):
        return self._since(last_id)

    def alert_hits_since(self, last_id, limit=500):
        return self._since(last_id)


@pytest.fixture
def config_store(tmp_path):
    return ConfigStore(db_path=tmp_path / "config.db", backup_path=tmp_path / "config.backup.yaml")
