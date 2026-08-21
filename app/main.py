"""DNS-shield entrypoint.

Wires together: config store -> blocklist manager -> DNS resolver/server
-> stats -> web UI, then blocks running the web server in the foreground.

By design DNS-shield never makes any network call other than:
  1. fetching the blocklist URLs listed in your config,
  2. forwarding non-blocked queries to the upstream resolvers you configured, and
  3. a threat-intel lookup (VirusTotal/AbuseIPDB/AlienVault OTX) - but only
     for a service you've configured an API key for, and only when you
     click "Enrich" on a specific domain/IP in the dashboard. Never
     automatic, never on a schedule, never as a side effect of a query.
There is no telemetry, update-check, or "safe browsing" cloud service.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

import uvicorn

from app.blocklist import BlocklistManager
from app.client_names import ClientNameResolver
from app.config import ConfigStore
from app.dns_cache import DNSCache
from app.dns_server import start_dns_servers
from app.enrichment_store import EnrichmentStore
from app.stats import Stats
from app.upstream_stats import UpstreamStats
from app.web.server import create_app

DATA_DIR = Path(os.environ.get("DNSSHIELD_DATA_DIR", "/data"))


def main() -> None:
    started_at = time.time()

    level = os.environ.get("DNSSHIELD_LOG_LEVEL", "INFO")
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logger = logging.getLogger("dnsshield.main")

    config_store = ConfigStore(db_path=DATA_DIR / "config.db", backup_path=DATA_DIR / "config.backup.yaml")
    config_store.start_backup_thread(interval_hours=12)
    log_level = config_store.get("logging", "level", default=level)
    logging.getLogger().setLevel(log_level)

    blocklist = BlocklistManager(config_store, cache_dir=DATA_DIR / "blocklist_cache")
    blocklist.start()

    stats = Stats(DATA_DIR / "stats.db", config_store)

    # Settings for these (enabled/thresholds/resolver address) are all read
    # live from config_store on every use, so changes from the web UI take
    # effect immediately - these objects always exist, they just no-op
    # internally when their feature is turned off.
    cache = DNSCache(config_store)
    client_names = ClientNameResolver(config_store)
    upstream_stats = UpstreamStats(config_store)
    enrichment_store = EnrichmentStore(DATA_DIR / "enrichment.db")

    start_dns_servers(
        config_store, blocklist, stats, cache=cache, client_names=client_names, upstream_stats=upstream_stats
    )

    app = create_app(
        config_store,
        blocklist,
        stats,
        started_at,
        cache=cache,
        client_names=client_names,
        upstream_stats=upstream_stats,
        enrichment_store=enrichment_store,
    )
    web_host = config_store.get("web", "listen_address", default="0.0.0.0")
    web_port = int(config_store.get("web", "listen_port", default=3000))
    logger.info("web UI listening on %s:%d", web_host, web_port)

    uvicorn.run(app, host=web_host, port=web_port, log_level="warning")


if __name__ == "__main__":
    main()
