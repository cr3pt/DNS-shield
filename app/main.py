from __future__ import annotations

import atexit
import logging
import multiprocessing
import os
import signal
import threading
import time
from pathlib import Path

import uvicorn

from app.anomaly import AnomalyDetector
from app.audit import AuditLog
from app.auto_enrich import AutoEnricher
from app.block_page import start_block_page_server
from app.blocklist import BlocklistManager
from app.client_names import ClientNameResolver
from app.config import ConfigStore
from app.dns_cache import DNSCache
from app.dns_server import build_resolver, reuse_port_supported, start_dns_servers, start_dot_server
from app.dnssec import DnssecCache
from app.enrichment_store import EnrichmentStore
from app.tls import ensure_self_signed_cert
from app.mac_resolve import MacResolver
from app.notifications import NotificationSender
from app.sessions import SessionStore
from app.stats import Stats
from app.upstream_stats import UpstreamStats
from app.users import UserStore
from app.web.server import create_app

DATA_DIR = Path(os.environ.get("DNSSHIELD_DATA_DIR", "/data"))


def _run_dns_worker(worker_id: int, num_workers: int, data_dir: Path, log_level: str) -> None:
    logging.basicConfig(level=log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger().setLevel(log_level)
    logger = logging.getLogger("dnsshield.main")

    config_store = ConfigStore(db_path=data_dir / "config.db", backup_path=data_dir / "config.backup.yaml")
    config_store.start_reload_thread(interval_seconds=5)

    client_names = ClientNameResolver(config_store)
    mac_resolver = MacResolver()
    mac_resolver.start()

    blocklist = BlocklistManager(
        config_store,
        cache_dir=data_dir / f"blocklist_cache_worker_{worker_id}",
        mac_resolver=mac_resolver,
        client_names=client_names,
    )
    blocklist.start()

    stats = Stats(data_dir / "stats.db", config_store)
    cache = DNSCache(config_store)
    upstream_stats = UpstreamStats(config_store)
    dnssec_cache = DnssecCache()

    start_dns_servers(
        config_store,
        blocklist,
        stats,
        cache=cache,
        client_names=client_names,
        upstream_stats=upstream_stats,
        reuse_port=True,
        dnssec_cache=dnssec_cache,
    )
    logger.info("DNS worker %d/%d ready", worker_id + 1, num_workers)
    threading.Event().wait()


def main() -> None:
    started_at = time.time()

    level = os.environ.get("DNSSHIELD_LOG_LEVEL", "INFO")
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logger = logging.getLogger("dnsshield.main")

    num_workers = max(1, int(os.environ.get("DNSSHIELD_DNS_WORKERS", "1") or "1"))
    if num_workers > 1 and not reuse_port_supported():
        logger.warning(
            "DNSSHIELD_DNS_WORKERS=%d requested but SO_REUSEPORT isn't available on this platform - "
            "running with 1 DNS worker instead",
            num_workers,
        )
        num_workers = 1

    config_store = ConfigStore(db_path=DATA_DIR / "config.db", backup_path=DATA_DIR / "config.backup.yaml")
    config_store.start_backup_thread(interval_hours=12)
    log_level = config_store.get("logging", "level", default=level)
    logging.getLogger().setLevel(log_level)

    stats = Stats(DATA_DIR / "stats.db", config_store)

    workers: list[multiprocessing.Process] = []
    if num_workers > 1:
        for worker_id in range(1, num_workers):
            p = multiprocessing.Process(
                target=_run_dns_worker,
                args=(worker_id, num_workers, DATA_DIR, level),
                name=f"dnsshield-dns-worker-{worker_id}",
                daemon=True,
            )
            p.start()
            workers.append(p)
        logger.info("started %d additional DNS worker process(es) with SO_REUSEPORT", num_workers - 1)

    def _stop_workers() -> None:
        for p in workers:
            if p.is_alive():
                p.terminate()
        for p in workers:
            p.join(timeout=5)

    def _handle_term(signum, frame) -> None:
        _stop_workers()
        raise SystemExit(0)

    atexit.register(_stop_workers)
    signal.signal(signal.SIGTERM, _handle_term)
    signal.signal(signal.SIGINT, _handle_term)

    client_names = ClientNameResolver(config_store)
    mac_resolver = MacResolver()
    mac_resolver.start()

    blocklist = BlocklistManager(
        config_store, cache_dir=DATA_DIR / "blocklist_cache", mac_resolver=mac_resolver, client_names=client_names
    )
    blocklist.start()

    cache = DNSCache(config_store)
    upstream_stats = UpstreamStats(config_store)
    dnssec_cache = DnssecCache()
    enrichment_store = EnrichmentStore(DATA_DIR / "enrichment.db")

    notifications = NotificationSender(config_store)

    anomaly = AnomalyDetector(
        config_store, stats, DATA_DIR / "anomalies.db", on_new_anomalies=notifications.notify_anomalies
    )
    anomaly.start()

    auto_enricher = AutoEnricher(config_store, stats, enrichment_store, anomaly=anomaly)
    auto_enricher.start()

    users = UserStore(config_store)
    sessions = SessionStore()
    audit_log = AuditLog(DATA_DIR / "audit.db", config_store)

    resolver = build_resolver(
        config_store,
        blocklist,
        stats,
        cache=cache,
        client_names=client_names,
        upstream_stats=upstream_stats,
        dnssec_cache=dnssec_cache,
    )
    start_dns_servers(
        config_store,
        blocklist,
        stats,
        cache=cache,
        client_names=client_names,
        upstream_stats=upstream_stats,
        reuse_port=num_workers > 1,
        dnssec_cache=dnssec_cache,
        resolver=resolver,
    )

    if config_store.get("dns", "block_page_enabled", default=False):
        bp_address = config_store.get("dns", "listen_address", default="0.0.0.0")
        bp_port = int(config_store.get("dns", "block_page_port", default=80))
        try:
            start_block_page_server(bp_address, bp_port, blocklist)
        except OSError as exc:
            logger.warning("could not start block page server on %s:%d: %s", bp_address, bp_port, exc)

    app = create_app(
        config_store,
        blocklist,
        stats,
        started_at,
        cache=cache,
        client_names=client_names,
        upstream_stats=upstream_stats,
        enrichment_store=enrichment_store,
        anomaly=anomaly,
        notifications=notifications,
        users=users,
        sessions=sessions,
        dnssec_cache=dnssec_cache,
        resolver=resolver,
        audit_log=audit_log,
    )
    web_host = config_store.get("web", "listen_address", default="0.0.0.0")
    web_port = int(config_store.get("web", "listen_port", default=3000))

    https_enabled = bool(config_store.get("web", "https_enabled", default=False))
    dot_enabled = bool(config_store.get("dns", "dot_enabled", default=False))

    cert_path = key_path = None
    if https_enabled or dot_enabled:
        cert_path_cfg = config_store.get("web", "https_cert_path", default="") or ""
        key_path_cfg = config_store.get("web", "https_key_path", default="") or ""
        if cert_path_cfg and key_path_cfg:
            cert_path, key_path = Path(cert_path_cfg), Path(key_path_cfg)
        else:
            cert_path, key_path = DATA_DIR / "tls" / "cert.pem", DATA_DIR / "tls" / "key.pem"
            ensure_self_signed_cert(cert_path, key_path)

    ssl_kwargs: dict[str, str] = {}
    if https_enabled:
        ssl_kwargs = {"ssl_certfile": str(cert_path), "ssl_keyfile": str(key_path)}
        logger.info("web UI listening on https://%s:%d", web_host, web_port)
    else:
        logger.info("web UI listening on http://%s:%d", web_host, web_port)

    if dot_enabled:
        dot_port = int(config_store.get("dns", "dot_port", default=853))
        dns_address = config_store.get("dns", "listen_address", default="0.0.0.0")
        try:
            start_dot_server(resolver, cert_path, key_path, address=dns_address, port=dot_port)
        except OSError as exc:
            logger.warning("could not start DoT server on %s:%d: %s", dns_address, dot_port, exc)

    uvicorn.run(app, host=web_host, port=web_port, log_level="warning", **ssl_kwargs)
    _stop_workers()


if __name__ == "__main__":
    main()
