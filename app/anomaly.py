from __future__ import annotations

import ipaddress
import json
import logging
import math
import sqlite3
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any

logger = logging.getLogger("dnsshield.anomaly")


def _registrable_label(domain: str) -> str:
    labels = domain.rstrip(".").split(".")
    return labels[-2] if len(labels) >= 2 else labels[0]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _looks_like_dga(domain: str, min_label_length: int, min_entropy: float) -> bool:
    label = _registrable_label(domain)
    if len(label) < min_label_length:
        return False
    return _shannon_entropy(label) >= min_entropy


def _base_domain(domain: str) -> str:
    labels = domain.rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain


def _looks_like_tunnel_label(domain: str, min_label_length: int, min_entropy: float) -> bool:
    first_label = domain.rstrip(".").split(".")[0]
    if len(first_label) < min_label_length:
        return False
    return _shannon_entropy(first_label) >= min_entropy


def _ptr_name_to_ip(name: str) -> str | None:
    name = name.rstrip(".").lower()
    if name.endswith(".in-addr.arpa"):
        parts = name[: -len(".in-addr.arpa")].split(".")
        if len(parts) != 4:
            return None
        try:
            octets = [int(p) for p in reversed(parts)]
        except ValueError:
            return None
        if any(o < 0 or o > 255 for o in octets):
            return None
        return ".".join(str(o) for o in octets)
    if name.endswith(".ip6.arpa"):
        nibbles = name[: -len(".ip6.arpa")].split(".")
        if len(nibbles) != 32 or not all(len(n) == 1 and n in "0123456789abcdef" for n in nibbles):
            return None
        hex_str = "".join(reversed(nibbles))
        groups = [hex_str[i : i + 4] for i in range(0, 32, 4)]
        return ":".join(groups)
    return None


def _is_private_ptr_target(name: str) -> bool:
    ip = _ptr_name_to_ip(name)
    if ip is None:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _is_private_client(client: str) -> bool:
    try:
        return ipaddress.ip_address(client).is_private
    except ValueError:
        return False

SCHEMA = """
CREATE TABLE IF NOT EXISTS anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    client TEXT NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    details_json TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_anomalies_ts ON anomalies(ts);
CREATE INDEX IF NOT EXISTS idx_anomalies_client_kind ON anomalies(client, kind);
CREATE INDEX IF NOT EXISTS idx_anomalies_ack ON anomalies(acknowledged);
"""

KIND_LABELS = {
    "high_blocked_ratio": "High blocked-query ratio",
    "domain_burst": "Burst of random-looking domains (possible DGA)",
    "blocked_domain_burst": "Unusually many distinct blocked domains",
    "dns_tunneling": "Many distinct subdomains of one domain (possible DNS tunneling)",
    "ptr_scan": "Many reverse-DNS lookups of local/private IPs (possible internal network scan)",
}

_THREAT_INTEL_SEVERITY_MAP = {"critical": "high", "high": "high", "medium": "medium", "low": "low"}


class AnomalyDetector:
    def __init__(self, config_store, stats, db_path: Path, on_new_anomalies=None):
        self._config = config_store
        self._stats = stats
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._on_new_anomalies = on_new_anomalies
        self._init_schema()

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._watch_thread: threading.Thread | None = None
        self._watch_last_id: int | None = None
        self._typosquat_watch_last_id: int | None = None
        self._rebinding_watch_last_id: int | None = None
        self._local_tld_watch_last_id: int | None = None

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _excluded_domains(self) -> list[str]:
        return [d.lower().rstrip(".") for d in (self._config.get("anomaly", "excluded_domains", default=[]) or [])]

    @staticmethod
    def _is_excluded(domain: str, excluded: list[str]) -> bool:
        domain = (domain or "").lower().rstrip(".")
        return any(domain == d or domain.endswith("." + d) for d in excluded)

    def _typosquat_fp_pairs(self) -> set[tuple[str, str]]:
        pairs = self._config.get("anomaly", "typosquat_fp_pairs", default=[]) or []
        return {
            ((p.get("domain") or "").lower().rstrip("."), (p.get("protected") or "").lower().rstrip("."))
            for p in pairs
            if isinstance(p, dict)
        }

    def _rebinding_fp_pairs(self) -> set[tuple[str, str]]:
        pairs = self._config.get("anomaly", "rebinding_fp_pairs", default=[]) or []
        return {
            ((p.get("domain") or "").lower().rstrip("."), (p.get("ip") or "").strip())
            for p in pairs
            if isinstance(p, dict)
        }

    def _threat_intel_fp_targets(self) -> set[str]:
        targets = self._config.get("anomaly", "threat_intel_fp_targets", default=[]) or []
        return {(t or "").strip().lower() for t in targets if t}

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="anomaly-detector", daemon=True)
        self._thread.start()
        self._watch_thread = threading.Thread(target=self._watch_loop, name="alert-rule-watcher", daemon=True)
        self._watch_thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            interval_minutes = self._config.get("anomaly", "check_interval_minutes", default=5) or 5
            interval = max(float(interval_minutes), 1.0) * 60
            if self._stop_event.wait(interval):
                return
            if not self._config.get("anomaly", "enabled", default=False):
                continue
            try:
                self.check_once()
            except Exception:
                logger.exception("anomaly check failed")

    def _watch_loop(self) -> None:
        while not self._stop_event.is_set():
            interval_seconds = self._config.get("alert_rules", "check_interval_seconds", default=15) or 15
            interval = max(float(interval_seconds), 1.0)
            if self._stop_event.wait(interval):
                return
            try:
                self.check_watched_domains()
            except Exception:
                logger.exception("watched-domain check failed")
            try:
                self.check_typosquat_hits()
            except Exception:
                logger.exception("typosquat check failed")
            try:
                self.check_rebinding_hits()
            except Exception:
                logger.exception("rebinding check failed")
            try:
                self.check_local_tld_hits()
            except Exception:
                logger.exception("local-TLD check failed")

    def check_once(self) -> list[dict[str, Any]]:
        window_minutes = float(self._config.get("anomaly", "window_minutes", default=15) or 15)
        return self._evaluate_window(window_minutes, time.time(), notify=True)

    def reanalyze(self, hours: float) -> list[dict[str, Any]]:
        window_minutes = float(self._config.get("anomaly", "window_minutes", default=15) or 15)
        window_seconds = max(window_minutes, 1.0) * 60
        end_ts = time.time()
        cursor = end_ts - max(float(hours), 1.0) * 3600

        found: list[dict[str, Any]] = []
        while cursor < end_ts:
            slice_end = min(cursor + window_seconds, end_ts)
            found.extend(self._evaluate_window(window_minutes, slice_end, notify=False))
            cursor = slice_end
        return found

    def _evaluate_window(self, window_minutes: float, until_ts: float, notify: bool) -> list[dict[str, Any]]:
        min_queries = int(self._config.get("anomaly", "min_queries", default=20) or 20)
        blocked_ratio_threshold = float(self._config.get("anomaly", "blocked_ratio_threshold", default=0.5) or 0.5)
        domain_burst_threshold = int(self._config.get("anomaly", "domain_burst_threshold", default=50) or 50)
        domain_burst_min_entropy = float(self._config.get("anomaly", "domain_burst_min_entropy", default=3.3) or 3.3)
        domain_burst_min_label_length = int(
            self._config.get("anomaly", "domain_burst_min_label_length", default=10) or 10
        )
        domain_burst_entropy_fraction = float(
            self._config.get("anomaly", "domain_burst_entropy_fraction", default=0.5) or 0.5
        )
        blocked_domain_burst_threshold = int(
            self._config.get("anomaly", "blocked_domain_burst_threshold", default=15) or 15
        )
        dns_tunneling_threshold = int(self._config.get("anomaly", "dns_tunneling_threshold", default=30) or 30)
        dns_tunneling_min_label_length = int(
            self._config.get("anomaly", "dns_tunneling_min_label_length", default=20) or 20
        )
        dns_tunneling_min_entropy = float(
            self._config.get("anomaly", "dns_tunneling_min_entropy", default=3.0) or 3.0
        )
        ptr_scan_threshold = int(self._config.get("anomaly", "ptr_scan_threshold", default=15) or 15)
        cooldown_minutes = float(self._config.get("anomaly", "cooldown_minutes", default=60) or 60)
        cooldown_seconds = max(cooldown_minutes, 1.0) * 60

        activity = self._stats.client_activity(window_minutes * 60, until_ts=until_ts)
        now = until_ts
        found: list[dict[str, Any]] = []

        domain_list_threshold = min(domain_burst_threshold, dns_tunneling_threshold)
        needs_domains = any(row["distinct_domains"] >= domain_list_threshold for row in activity)
        domains_by_client = self._stats.client_domains(window_minutes * 60, until_ts=until_ts) if needs_domains else {}

        needs_ptr = any(row["total"] >= ptr_scan_threshold for row in activity)
        ptr_targets_by_client = self._stats.client_ptr_targets(window_minutes * 60, until_ts=until_ts) if needs_ptr else {}

        with self._lock:
            conn = self._connect()
            try:
                conn.row_factory = sqlite3.Row
                last_fired = {
                    (row["client"], row["kind"]): row["last_ts"]
                    for row in conn.execute(
                        "SELECT client, kind, MAX(ts) AS last_ts FROM anomalies GROUP BY client, kind"
                    ).fetchall()
                }

                for row in activity:
                    client = row["client"]
                    total = row["total"]
                    blocked = row["blocked"]
                    distinct_domains = row["distinct_domains"]
                    distinct_blocked_domains = row["distinct_blocked_domains"]

                    candidates: list[tuple[str, str, str]] = []
                    domain_burst_entropy_pct: int | None = None
                    domain_burst_random_count: int | None = None

                    if total >= min_queries and blocked / total >= blocked_ratio_threshold:
                        pct = round(100 * blocked / total)
                        severity = "high" if blocked / total >= 0.8 else "medium"
                        candidates.append((
                            "high_blocked_ratio", severity,
                            f"{pct}% of {total} queries blocked in the last {window_minutes:g} min",
                        ))

                    if distinct_domains >= domain_burst_threshold:
                        client_domains = domains_by_client.get(client, [])
                        random_looking = [
                            d for d in client_domains
                            if _looks_like_dga(d, domain_burst_min_label_length, domain_burst_min_entropy)
                        ]
                        entropy_fraction = len(random_looking) / len(client_domains) if client_domains else 0.0
                        if entropy_fraction >= domain_burst_entropy_fraction:
                            domain_burst_entropy_pct = round(100 * entropy_fraction)
                            domain_burst_random_count = len(random_looking)
                            severity = "high" if distinct_domains >= domain_burst_threshold * 2 else "medium"
                            candidates.append((
                                "domain_burst", severity,
                                f"{distinct_domains} distinct domains queried in the last {window_minutes:g} min, "
                                f"{domain_burst_random_count} ({domain_burst_entropy_pct}%) look randomly generated",
                            ))

                    if distinct_blocked_domains >= blocked_domain_burst_threshold:
                        severity = "high" if distinct_blocked_domains >= blocked_domain_burst_threshold * 2 else "medium"
                        candidates.append((
                            "blocked_domain_burst", severity,
                            f"{distinct_blocked_domains} distinct blocked domains hit in the last {window_minutes:g} min",
                        ))

                    dns_tunneling_base: str | None = None
                    dns_tunneling_subdomain_count: int | None = None
                    dns_tunneling_avg_length: float | None = None
                    if distinct_domains >= dns_tunneling_threshold:
                        client_domains = domains_by_client.get(client, [])
                        groups: dict[str, list[str]] = {}
                        for d in client_domains:
                            groups.setdefault(_base_domain(d), []).append(d)
                        for base, subdomains in sorted(groups.items(), key=lambda kv: -len(kv[1])):
                            if len(subdomains) < dns_tunneling_threshold:
                                break
                            avg_length = sum(len(d) for d in subdomains) / len(subdomains)
                            random_like = [
                                d for d in subdomains
                                if _looks_like_tunnel_label(d, dns_tunneling_min_label_length, dns_tunneling_min_entropy)
                            ]
                            if len(random_like) / len(subdomains) >= 0.5:
                                dns_tunneling_base = base
                                dns_tunneling_subdomain_count = len(subdomains)
                                dns_tunneling_avg_length = avg_length
                                severity = "high" if len(subdomains) >= dns_tunneling_threshold * 2 else "medium"
                                candidates.append((
                                    "dns_tunneling", severity,
                                    f"{len(subdomains)} distinct, long/random-looking subdomains of {base} queried "
                                    f"in the last {window_minutes:g} min (avg name length {avg_length:.0f} chars)",
                                ))
                                break

                    ptr_scan_count: int | None = None
                    ptr_targets = ptr_targets_by_client.get(client, [])
                    private_ptr_targets = [t for t in ptr_targets if _is_private_ptr_target(t)]
                    if len(private_ptr_targets) >= ptr_scan_threshold:
                        ptr_scan_count = len(private_ptr_targets)
                        severity = "high" if ptr_scan_count >= ptr_scan_threshold * 2 else "medium"
                        candidates.append((
                            "ptr_scan", severity,
                            f"{ptr_scan_count} distinct reverse-DNS lookups of local/private IPs in the last "
                            f"{window_minutes:g} min",
                        ))

                    for kind, severity, summary in candidates:
                        last = last_fired.get((client, kind))
                        if last is not None and now - last < cooldown_seconds:
                            continue
                        details = {
                            "total_queries": total,
                            "blocked_queries": blocked,
                            "distinct_domains": distinct_domains,
                            "distinct_blocked_domains": distinct_blocked_domains,
                            "window_minutes": window_minutes,
                        }
                        if kind == "domain_burst":
                            details["random_looking_domains"] = domain_burst_random_count
                            details["random_looking_percent"] = domain_burst_entropy_pct
                        if kind == "dns_tunneling":
                            details["base_domain"] = dns_tunneling_base
                            details["subdomain_count"] = dns_tunneling_subdomain_count
                            details["avg_name_length"] = dns_tunneling_avg_length
                        if kind == "ptr_scan":
                            details["ptr_scan_count"] = ptr_scan_count
                        conn.execute(
                            "INSERT INTO anomalies (ts, client, kind, severity, summary, details_json, acknowledged) "
                            "VALUES (?, ?, ?, ?, ?, ?, 0)",
                            (now, client, kind, severity, summary, json.dumps(details)),
                        )
                        last_fired[(client, kind)] = now
                        found.append({
                            "ts": now, "client": client, "kind": kind,
                            "severity": severity, "summary": summary,
                        })

                conn.commit()
            finally:
                conn.close()

        if found:
            logger.info("anomaly check: %d new anomal%s flagged", len(found), "y" if len(found) == 1 else "ies")
            if notify and self._on_new_anomalies is not None:
                try:
                    self._on_new_anomalies(found)
                except Exception:
                    logger.exception("on_new_anomalies callback failed")
        return found

    def check_watched_domains(self) -> list[dict[str, Any]]:
        if self._watch_last_id is None:
            self._watch_last_id = self._stats.max_query_id()
            return []

        hits = self._stats.alert_hits_since(self._watch_last_id)
        if not hits:
            return []

        cooldown_minutes = float(self._config.get("alert_rules", "cooldown_minutes", default=15) or 15)
        cooldown_seconds = max(cooldown_minutes, 1.0) * 60
        now = time.time()
        found: list[dict[str, Any]] = []

        excluded = self._excluded_domains()

        with self._lock:
            conn = self._connect()
            try:
                conn.row_factory = sqlite3.Row
                last_fired = {
                    (row["client"], row["kind"]): row["last_ts"]
                    for row in conn.execute(
                        "SELECT client, kind, MAX(ts) AS last_ts FROM anomalies GROUP BY client, kind"
                    ).fetchall()
                }

                for hit in hits:
                    client = hit["client"]
                    domain = hit["domain"]
                    if self._is_excluded(domain, excluded):
                        continue
                    kind = f"watched_domain:{domain}"
                    last = last_fired.get((client, kind))
                    if last is not None and now - last < cooldown_seconds:
                        continue
                    summary = f'Queried watched domain "{domain}" (rule: {hit["alert_rule"]})'
                    details = {"domain": domain, "alert_rule": hit["alert_rule"], "query_ts": hit["ts"]}
                    conn.execute(
                        "INSERT INTO anomalies (ts, client, kind, severity, summary, details_json, acknowledged) "
                        "VALUES (?, ?, ?, 'high', ?, ?, 0)",
                        (now, client, kind, summary, json.dumps(details)),
                    )
                    last_fired[(client, kind)] = now
                    found.append({"ts": now, "client": client, "kind": kind, "severity": "high", "summary": summary})

                conn.commit()
            finally:
                conn.close()

        self._watch_last_id = max(hit["id"] for hit in hits)

        if found:
            logger.info(
                "watched-domain check: %d new alert%s flagged", len(found), "" if len(found) == 1 else "s"
            )
            if self._on_new_anomalies is not None:
                try:
                    self._on_new_anomalies(found)
                except Exception:
                    logger.exception("on_new_anomalies callback failed")
        return found

    def record_threat_intel_alert(
        self, target: str, target_type: str, verdict: str, summary: str, details: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Called from the Enrich endpoint when a lookup comes back with a bad-enough
        verdict, so it shows up in the same Alerts list as anomaly/alert-rule hits
        instead of only ever being visible in the one-off popup that triggered it."""
        severity = _THREAT_INTEL_SEVERITY_MAP.get(verdict)
        if severity is None:
            return None
        if target.strip().lower() in self._threat_intel_fp_targets():
            return None
        cooldown_minutes = float(self._config.get("anomaly", "cooldown_minutes", default=60) or 60)
        cooldown_seconds = max(cooldown_minutes, 1.0) * 60
        kind = f"threat_intel:{target}"
        now = time.time()

        with self._lock:
            conn = self._connect()
            try:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT MAX(ts) AS last_ts FROM anomalies WHERE client = ? AND kind = ?", (target, kind)
                ).fetchone()
                if row is not None and row["last_ts"] is not None and now - row["last_ts"] < cooldown_seconds:
                    return None
                details = dict(details)
                details["target_type"] = target_type
                details["verdict"] = verdict
                conn.execute(
                    "INSERT INTO anomalies (ts, client, kind, severity, summary, details_json, acknowledged) "
                    "VALUES (?, ?, ?, ?, ?, ?, 0)",
                    (now, target, kind, severity, summary, json.dumps(details)),
                )
                conn.commit()
            finally:
                conn.close()

        result = {"ts": now, "client": target, "kind": kind, "severity": severity, "summary": summary}
        if self._on_new_anomalies is not None:
            try:
                self._on_new_anomalies([result])
            except Exception:
                logger.exception("on_new_anomalies callback failed")
        return result

    def check_typosquat_hits(self) -> list[dict[str, Any]]:
        if not self._config.get("dns", "typosquat_enabled", default=False):
            return []
        if self._typosquat_watch_last_id is None:
            self._typosquat_watch_last_id = self._stats.max_query_id()
            return []

        hits = self._stats.typosquat_hits_since(self._typosquat_watch_last_id)
        if not hits:
            return []

        cooldown_minutes = float(self._config.get("dns", "typosquat_cooldown_minutes", default=30) or 30)
        cooldown_seconds = max(cooldown_minutes, 1.0) * 60
        now = time.time()
        found: list[dict[str, Any]] = []
        excluded = self._excluded_domains()
        fp_pairs = self._typosquat_fp_pairs()

        with self._lock:
            conn = self._connect()
            try:
                conn.row_factory = sqlite3.Row
                last_fired = {
                    (row["client"], row["kind"]): row["last_ts"]
                    for row in conn.execute(
                        "SELECT client, kind, MAX(ts) AS last_ts FROM anomalies GROUP BY client, kind"
                    ).fetchall()
                }

                for hit in hits:
                    client = hit["client"]
                    domain = hit["domain"]
                    if self._is_excluded(domain, excluded):
                        continue
                    parts = (hit["typosquat_match"] or "").split("|")
                    protected = parts[0] if parts else "?"
                    match_type = parts[1] if len(parts) > 1 else "typo"
                    if (domain.lower().rstrip("."), protected.lower().rstrip(".")) in fp_pairs:
                        continue
                    kind = f"typosquat:{protected}"
                    last = last_fired.get((client, kind))
                    if last is not None and now - last < cooldown_seconds:
                        continue
                    verb = "impersonates" if match_type == "embedded" else "looks like a typo of"
                    summary = f'Domain "{domain}" {verb} "{protected}"'
                    details = {
                        "domain": domain, "protected_domain": protected,
                        "match_type": match_type, "query_ts": hit["ts"],
                    }
                    conn.execute(
                        "INSERT INTO anomalies (ts, client, kind, severity, summary, details_json, acknowledged) "
                        "VALUES (?, ?, ?, 'high', ?, ?, 0)",
                        (now, client, kind, summary, json.dumps(details)),
                    )
                    last_fired[(client, kind)] = now
                    found.append({"ts": now, "client": client, "kind": kind, "severity": "high", "summary": summary})

                conn.commit()
            finally:
                conn.close()

        self._typosquat_watch_last_id = max(hit["id"] for hit in hits)

        if found:
            logger.info(
                "typosquat check: %d new alert%s flagged", len(found), "" if len(found) == 1 else "s"
            )
            if self._on_new_anomalies is not None:
                try:
                    self._on_new_anomalies(found)
                except Exception:
                    logger.exception("on_new_anomalies callback failed")
        return found

    def check_rebinding_hits(self) -> list[dict[str, Any]]:
        if not self._config.get("dns", "rebinding_protection_enabled", default=False):
            return []
        if self._rebinding_watch_last_id is None:
            self._rebinding_watch_last_id = self._stats.max_query_id()
            return []

        hits = self._stats.rebinding_hits_since(self._rebinding_watch_last_id)
        if not hits:
            return []

        cooldown_minutes = float(self._config.get("anomaly", "cooldown_minutes", default=60) or 60)
        cooldown_seconds = max(cooldown_minutes, 1.0) * 60
        now = time.time()
        found: list[dict[str, Any]] = []
        excluded = self._excluded_domains()
        fp_pairs = self._rebinding_fp_pairs()

        with self._lock:
            conn = self._connect()
            try:
                conn.row_factory = sqlite3.Row
                last_fired = {
                    (row["client"], row["kind"]): row["last_ts"]
                    for row in conn.execute(
                        "SELECT client, kind, MAX(ts) AS last_ts FROM anomalies GROUP BY client, kind"
                    ).fetchall()
                }

                for hit in hits:
                    client = hit["client"]
                    domain = hit["domain"]
                    if self._is_excluded(domain, excluded):
                        continue
                    ip = hit["rebinding_ip"]
                    if (domain.lower().rstrip("."), (ip or "").strip()) in fp_pairs:
                        continue
                    kind = f"rebinding:{domain}"
                    last = last_fired.get((client, kind))
                    if last is not None and now - last < cooldown_seconds:
                        continue
                    summary = f'Domain "{domain}" resolved to a local/private address ({ip}) - possible DNS rebinding'
                    details = {"domain": domain, "rebinding_ip": ip, "query_ts": hit["ts"]}
                    conn.execute(
                        "INSERT INTO anomalies (ts, client, kind, severity, summary, details_json, acknowledged) "
                        "VALUES (?, ?, ?, 'high', ?, ?, 0)",
                        (now, client, kind, summary, json.dumps(details)),
                    )
                    last_fired[(client, kind)] = now
                    found.append({"ts": now, "client": client, "kind": kind, "severity": "high", "summary": summary})

                conn.commit()
            finally:
                conn.close()

        self._rebinding_watch_last_id = max(hit["id"] for hit in hits)

        if found:
            logger.info("rebinding check: %d new alert%s flagged", len(found), "" if len(found) == 1 else "s")
            if self._on_new_anomalies is not None:
                try:
                    self._on_new_anomalies(found)
                except Exception:
                    logger.exception("on_new_anomalies callback failed")
        return found

    def check_local_tld_hits(self) -> list[dict[str, Any]]:
        if not self._config.get("dns", "local_tld_alert_enabled", default=False):
            return []
        if self._local_tld_watch_last_id is None:
            self._local_tld_watch_last_id = self._stats.max_query_id()
            return []

        hits = self._stats.local_tld_hits_since(self._local_tld_watch_last_id)
        if not hits:
            return []

        cooldown_minutes = float(self._config.get("dns", "local_tld_cooldown_minutes", default=30) or 30)
        cooldown_seconds = max(cooldown_minutes, 1.0) * 60
        now = time.time()
        found: list[dict[str, Any]] = []
        excluded = self._excluded_domains()

        with self._lock:
            conn = self._connect()
            try:
                conn.row_factory = sqlite3.Row
                last_fired = {
                    (row["client"], row["kind"]): row["last_ts"]
                    for row in conn.execute(
                        "SELECT client, kind, MAX(ts) AS last_ts FROM anomalies GROUP BY client, kind"
                    ).fetchall()
                }

                for hit in hits:
                    client = hit["client"]
                    domain = hit["domain"]
                    if self._is_excluded(domain, excluded):
                        continue
                    if _is_private_client(client):
                        continue
                    tld = hit["local_tld_match"]
                    kind = f"local_tld:{tld}"
                    last = last_fired.get((client, kind))
                    if last is not None and now - last < cooldown_seconds:
                        continue
                    summary = f'Queried local-TLD domain "{domain}" (.{tld})'
                    details = {"domain": domain, "tld": tld, "query_ts": hit["ts"]}
                    conn.execute(
                        "INSERT INTO anomalies (ts, client, kind, severity, summary, details_json, acknowledged) "
                        "VALUES (?, ?, ?, 'low', ?, ?, 0)",
                        (now, client, kind, summary, json.dumps(details)),
                    )
                    last_fired[(client, kind)] = now
                    found.append({"ts": now, "client": client, "kind": kind, "severity": "low", "summary": summary})

                conn.commit()
            finally:
                conn.close()

        self._local_tld_watch_last_id = max(hit["id"] for hit in hits)

        if found:
            logger.info("local-TLD check: %d new alert%s flagged", len(found), "" if len(found) == 1 else "s")
            if self._on_new_anomalies is not None:
                try:
                    self._on_new_anomalies(found)
                except Exception:
                    logger.exception("on_new_anomalies callback failed")
        return found

    @staticmethod
    def _kind_label(kind: str) -> str:
        if kind.startswith("watched_domain:"):
            return f"Watched domain: {kind.split(':', 1)[1]}"
        if kind.startswith("typosquat:"):
            return f"Possible typosquat of {kind.split(':', 1)[1]}"
        if kind.startswith("rebinding:"):
            return f"Possible DNS rebinding: {kind.split(':', 1)[1]}"
        if kind.startswith("local_tld:"):
            return f"Local-TLD query: .{kind.split(':', 1)[1]}"
        if kind.startswith("threat_intel:"):
            return f"Threat intel: bad reputation for {kind.split(':', 1)[1]}"
        return KIND_LABELS.get(kind, kind)

    @staticmethod
    def _kind_source(kind: str) -> str:
        if kind.startswith("watched_domain:"):
            return "alert_rule"
        if kind.startswith("threat_intel:"):
            return "threat_intel"
        return "anomaly"

    @classmethod
    def _row_to_dict(cls, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "ts": row["ts"],
            "client": row["client"],
            "kind": row["kind"],
            "kind_label": cls._kind_label(row["kind"]),
            "source": cls._kind_source(row["kind"]),
            "severity": row["severity"],
            "summary": row["summary"],
            "details": json.loads(row["details_json"]),
            "acknowledged": bool(row["acknowledged"]),
        }

    def list(self, include_acknowledged: bool = True, limit: int = 200) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            where = "" if include_acknowledged else "WHERE acknowledged = 0"
            rows = conn.execute(
                f"SELECT * FROM anomalies {where} ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        finally:
            conn.close()
        return [self._row_to_dict(row) for row in rows]

    def get(self, anomaly_id: int) -> dict[str, Any] | None:
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM anomalies WHERE id = ?", (anomaly_id,)).fetchone()
        finally:
            conn.close()
        return self._row_to_dict(row) if row else None

    def unacknowledged_count(self) -> int:
        conn = self._connect()
        try:
            return conn.execute("SELECT COUNT(*) FROM anomalies WHERE acknowledged = 0").fetchone()[0]
        finally:
            conn.close()

    def acknowledge(self, anomaly_id: int) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute("UPDATE anomalies SET acknowledged = 1 WHERE id = ?", (anomaly_id,))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def unacknowledge(self, anomaly_id: int) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute("UPDATE anomalies SET acknowledged = 0 WHERE id = ?", (anomaly_id,))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def delete(self, anomaly_id: int) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute("DELETE FROM anomalies WHERE id = ?", (anomaly_id,))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def clear(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM anomalies")
                conn.commit()
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                conn.close()
