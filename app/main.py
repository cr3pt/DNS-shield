"""DNS-shield entrypoint.

Wires together: config store -> blocklist manager -> DNS resolver/server
-> stats -> web UI, then blocks running the web server in the foreground.

By design DNS-shield never makes any network call other than:
  1. fetching the blocklist URLs listed in your config, and
  2. forwarding non-blocked queries to the upstream resolvers you configured.
There is no telemetry, update-check, or "safe browsing" cloud service.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

import uvicorn

from app.blocklist import BlocklistManager
from app.config import ConfigStore
from app.dns_cache import DNSCache
from app.dns_server import start_dns_servers
from app.stats import Stats
from app.web.server import create_app

DATA_DIR = Path(os.environ.get("DNSSHIELD_DATA_DIR", "/data"))


def main() -> None:
    started_at = time.time()

    level = os.environ.get("DNSSHIELD_LOG_LEVEL", "INFO")
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logger = logging.getLogger("dnsshield.main")

    config_store = ConfigStore()
    log_level = config_store.get("logging", "level", default=level)
    logging.getLogger().setLevel(log_level)

    blocklist = BlocklistManager(config_store, cache_dir=DATA_DIR / "blocklist_cache")
    blocklist.start()

    retention_days = float(config_store.get("logging", "retention_days", default=30))
    stats = Stats(DATA_DIR / "stats.db", retention_days=retention_days)

    cache = None
    if config_store.get("dns", "cache_enabled", default=True):
        cache = DNSCache(
            max_entries=int(config_store.get("dns", "cache_max_entries", default=10000)),
            min_ttl=int(config_store.get("dns", "cache_min_ttl_seconds", default=0)),
            max_ttl=int(config_store.get("dns", "cache_max_ttl_seconds", default=3600)),
        )

    start_dns_servers(config_store, blocklist, stats, cache=cache)

    app = create_app(config_store, blocklist, stats, started_at, cache=cache)
    web_host = config_store.get("web", "listen_address", default="0.0.0.0")
    web_port = int(config_store.get("web", "listen_port", default=3000))
    logger.info("web UI listening on %s:%d", web_host, web_port)

    uvicorn.run(app, host=web_host, port=web_port, log_level="warning")


if __name__ == "__main__":
    main()
