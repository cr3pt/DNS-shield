# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""API route modules; each exposes register(app, ctx). create_app() registers
them in MODULES order."""

from app.web.routes import (
    account,
    anomalies,
    auth,
    backup,
    dhcp,
    dns_rules,
    enrichment,
    groups,
    notifications,
    proxy,
    rules,
    settings,
    stats,
    status,
    sync,
)

MODULES = (
    auth,
    status,
    stats,
    rules,
    groups,
    dhcp,
    proxy,
    dns_rules,
    backup,
    settings,
    notifications,
    anomalies,
    enrichment,
    account,
    sync,
)
