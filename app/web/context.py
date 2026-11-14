# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""What create_app() hands to each route module."""

from __future__ import annotations

from types import SimpleNamespace


class AppContext(SimpleNamespace):
    """The services create_app() received (config_store, blocklist, stats, ...)
    plus the auth helpers it built (require_auth, require_admin, ...). Each
    route module's register(app, ctx) takes what it needs from here."""
