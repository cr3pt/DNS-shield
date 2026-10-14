# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from app.import_adguard import convert_dns_settings


def test_listen_address_and_port_are_never_imported():
    adguard = {"dns": {"bind_hosts": ["192.168.1.1"], "port": 5353}}

    out, warnings = convert_dns_settings(adguard)

    assert "listen_address" not in out
    assert "listen_port" not in out
    assert any("listen" in w for w in warnings)
