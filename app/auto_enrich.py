from __future__ import annotations

import logging
import threading
from typing import Any, Callable

from app.enrichment import enrich as run_enrichment
from app.enrichment import maybe_alert_on_verdict

logger = logging.getLogger("dnsshield.auto_enrich")

_SKIP_QTYPES = {"PTR"}


class AutoEnricher:
    def __init__(self, config_store, stats, enrichment_store, anomaly=None, on_result: Callable[[dict[str, Any]], None] | None = None):
        self._config = config_store
        self._stats = stats
        self._enrichment_store = enrichment_store
        self._anomaly = anomaly
        self._on_result = on_result
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._watch_last_id: int | None = None
        self._known_domains: set[str] = set()
        self._known_domains_loaded = False

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="auto-enricher", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            interval = float(self._config.get("enrichment", "auto_enrich_interval_seconds", default=30) or 30)
            if self._stop_event.wait(max(interval, 5.0)):
                return
            if not self._config.get("enrichment", "auto_enrich_enabled", default=False):
                continue
            try:
                self.check_once()
            except Exception:
                logger.exception("auto-enrich check failed")

    def _ensure_known_domains_loaded(self) -> None:
        if self._known_domains_loaded:
            return
        try:
            self._known_domains = self._enrichment_store.known_targets(target_type="domain")
        except Exception:
            logger.exception("failed to seed auto-enrich known-domains set")
            self._known_domains = set()
        self._known_domains_loaded = True

    def check_once(self) -> list[dict[str, Any]]:
        if self._watch_last_id is None:
            self._watch_last_id = self._stats.max_query_id()
            return []

        hits = self._stats.queries_since(self._watch_last_id)
        if not hits:
            return []

        self._ensure_known_domains_loaded()

        max_per_check = int(self._config.get("enrichment", "auto_enrich_max_per_check", default=5) or 5)
        results: list[dict[str, Any]] = []
        checked_this_round = 0
        last_processed_id = self._watch_last_id

        for hit in hits:
            domain = hit["domain"]
            is_candidate = hit.get("qtype") not in _SKIP_QTYPES and domain not in self._known_domains
            if is_candidate and checked_this_round >= max_per_check:
                break
            last_processed_id = hit["id"]
            if not is_candidate:
                continue

            self._known_domains.add(domain)
            checked_this_round += 1

            try:
                result = run_enrichment(domain, "domain", self._config)
            except Exception:
                logger.exception("auto-enrich lookup failed for %s", domain)
                continue

            if self._enrichment_store is not None:
                self._enrichment_store.record(
                    result["target"], result["type"], result["overall_verdict"],
                    result.get("overall_score"), result["sources"], source="auto",
                )
            maybe_alert_on_verdict(result, self._config, self._anomaly)
            results.append(result)
            if self._on_result is not None:
                try:
                    self._on_result(result)
                except Exception:
                    logger.exception("auto-enrich on_result callback failed")

        self._watch_last_id = last_processed_id
        if results:
            logger.info("auto-enrich: checked %d newly-seen domain(s)", len(results))
        return results
