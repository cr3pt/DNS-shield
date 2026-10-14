# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from app.upstream_stats import UpstreamStats


def test_all_configured_upstreams_includes_domain_and_group_only_entries(config_store):
    config_store.mutate(
        lambda d: d.update(
            {
                "dns": {"upstreams": ["1.1.1.1:53"]},
                "domain_upstreams": [{"domains": ["work.example"], "upstreams": ["10.0.0.1:53"]}],
                "client_groups": [{"name": "kids", "match": [], "upstreams": ["9.9.9.9:53", "#10.0.0.2:53"]}],
            }
        )
    )
    stats = UpstreamStats(config_store)

    upstreams = set(stats._all_configured_upstreams())

    assert upstreams == {"1.1.1.1:53", "10.0.0.1:53", "9.9.9.9:53"}

    stats.stop()
