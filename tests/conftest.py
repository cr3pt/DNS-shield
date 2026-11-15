# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

import pytest

from app import upstream_guard
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


@pytest.fixture(autouse=True)
def _fresh_upstream_guard():
    """An upstream's failure history must not leak from one test into the next."""
    upstream_guard.reset()
    yield
    upstream_guard.reset()


@pytest.fixture(autouse=True)
def _no_forced_default_password_change(monkeypatch, request):
    """Most tests log in as admin/changeme and go straight to the feature they
    test; the forced first-login password change has its own tests, which
    opt back in with the `force_password_change` marker."""
    if request.node.get_closest_marker("force_password_change") is None:
        monkeypatch.setattr("app.users.FORCE_DEFAULT_PASSWORD_CHANGE", False)
