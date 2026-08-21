"""Manual, opt-in threat-intelligence enrichment: VirusTotal, AbuseIPDB,
and AlienVault OTX domain/IP reputation lookups.

Every call here happens *only* because a user clicked "Enrich" in the
dashboard - nothing in this module is ever invoked automatically, on a
timer, or as a side effect of resolving a DNS query. It only talks to a
given service if you've configured that service's API key yourself in
Settings -> Threat intelligence; skipping a service you haven't
configured a key for is not an error, just a "not configured" result.

AbuseIPDB has no domain-lookup endpoint - it's only ever queried for an
IP target, per its own API (see enrich()).
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

import requests

logger = logging.getLogger("dnsshield.enrichment")

_SEVERITY_ORDER = ["safe", "low", "medium", "high", "critical"]
_TIMEOUT = 10.0

# One shared, connection-pooling session (same reasoning as app/upstream.py's
# DoH session) - enrichment is low-frequency (manual clicks only) but there's
# no reason to open a fresh connection every time either.
_session = requests.Session()


def _severity_max(a: str, b: str) -> str:
    ia = _SEVERITY_ORDER.index(a) if a in _SEVERITY_ORDER else -1
    ib = _SEVERITY_ORDER.index(b) if b in _SEVERITY_ORDER else -1
    return a if ia >= ib else b


def _http_error_message(exc: requests.HTTPError) -> str:
    status = exc.response.status_code if exc.response is not None else None
    if status in (401, 403):
        return "rejected - check the API key in Settings"
    if status == 404:
        return "no data on record for this indicator yet"
    if status == 429:
        return "rate limited - try again later"
    return f"HTTP {status}" if status else str(exc)


def query_virustotal(target: str, target_type: str, api_key: str) -> dict[str, Any]:
    kind = "domains" if target_type == "domain" else "ip_addresses"
    url = f"https://www.virustotal.com/api/v3/{kind}/{quote(target, safe='')}"
    try:
        resp = _session.get(url, headers={"x-apikey": api_key}, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1

        if malicious >= 5:
            verdict = "critical"
        elif malicious >= 1:
            verdict = "high"
        elif suspicious >= 1:
            verdict = "medium"
        else:
            verdict = "safe"

        gui_kind = "domain" if target_type == "domain" else "ip-address"
        return {
            "configured": True,
            "ok": True,
            "verdict": verdict,
            "score": min(100, malicious * 15 + suspicious * 5),
            "summary": f"{malicious} malicious / {suspicious} suspicious out of {total} engines",
            "details": stats,
            "link": f"https://www.virustotal.com/gui/{gui_kind}/{quote(target, safe='')}",
        }
    except requests.HTTPError as exc:
        return {"configured": True, "ok": False, "error": _http_error_message(exc)}
    except Exception as exc:  # noqa: BLE001
        logger.warning("VirusTotal lookup failed for %s: %s", target, exc)
        return {"configured": True, "ok": False, "error": str(exc)}


def query_abuseipdb(ip: str, api_key: str) -> dict[str, Any]:
    url = "https://api.abuseipdb.com/api/v2/check"
    try:
        resp = _session.get(
            url,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()["data"]
        score = int(data.get("abuseConfidenceScore", 0))
        reports = data.get("totalReports", 0)

        if score >= 75:
            verdict = "critical"
        elif score >= 50:
            verdict = "high"
        elif score >= 20:
            verdict = "medium"
        elif score > 0:
            verdict = "low"
        else:
            verdict = "safe"

        return {
            "configured": True,
            "ok": True,
            "verdict": verdict,
            "score": score,
            "summary": f"Abuse confidence {score}%, {reports} report(s) in the last 90 days",
            "details": data,
            "link": f"https://www.abuseipdb.com/check/{quote(ip, safe='')}",
        }
    except requests.HTTPError as exc:
        return {"configured": True, "ok": False, "error": _http_error_message(exc)}
    except Exception as exc:  # noqa: BLE001
        logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return {"configured": True, "ok": False, "error": str(exc)}


def query_otx(target: str, target_type: str, api_key: str) -> dict[str, Any]:
    kind = "domain" if target_type == "domain" else "IPv4"
    url = f"https://otx.alienvault.com/api/v1/indicators/{kind}/{quote(target, safe='')}/general"
    try:
        resp = _session.get(url, headers={"X-OTX-API-KEY": api_key}, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)

        if pulse_count >= 20:
            verdict = "critical"
        elif pulse_count >= 5:
            verdict = "high"
        elif pulse_count >= 1:
            verdict = "medium"
        else:
            verdict = "safe"

        return {
            "configured": True,
            "ok": True,
            "verdict": verdict,
            "score": min(100, pulse_count * 5),
            "summary": f"{pulse_count} threat intelligence pulse(s) reference this indicator",
            "details": {"pulse_count": pulse_count},
            "link": f"https://otx.alienvault.com/indicator/{kind}/{quote(target, safe='')}",
        }
    except requests.HTTPError as exc:
        return {"configured": True, "ok": False, "error": _http_error_message(exc)}
    except Exception as exc:  # noqa: BLE001
        logger.warning("OTX lookup failed for %s: %s", target, exc)
        return {"configured": True, "ok": False, "error": str(exc)}


def enrich(target: str, target_type: str, config_store) -> dict[str, Any]:
    """target_type is "domain" or "ip". AbuseIPDB is only ever queried for
    an IP target - it has no domain-lookup endpoint, so it's reported as
    inapplicable (None) rather than "not configured" for a domain target.
    """
    target = target.strip()
    sources: dict[str, Any] = {}

    vt_key = config_store.get("enrichment", "virustotal_api_key", default="") or ""
    sources["virustotal"] = query_virustotal(target, target_type, vt_key) if vt_key else {"configured": False}

    otx_key = config_store.get("enrichment", "otx_api_key", default="") or ""
    sources["otx"] = query_otx(target, target_type, otx_key) if otx_key else {"configured": False}

    if target_type == "ip":
        abuse_key = config_store.get("enrichment", "abuseipdb_api_key", default="") or ""
        sources["abuseipdb"] = query_abuseipdb(target, abuse_key) if abuse_key else {"configured": False}
    else:
        sources["abuseipdb"] = None

    overall: str | None = None
    overall_score: int | None = None
    for src in sources.values():
        if src and src.get("ok"):
            overall = src["verdict"] if overall is None else _severity_max(overall, src["verdict"])
            score = src.get("score", 0)
            overall_score = score if overall_score is None else max(overall_score, score)

    return {
        "target": target,
        "type": target_type,
        "overall_verdict": overall or "unknown",
        "overall_score": overall_score,
        "sources": sources,
    }
