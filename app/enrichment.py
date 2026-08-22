from __future__ import annotations

import concurrent.futures
import logging
from typing import Any
from urllib.parse import quote

import requests

logger = logging.getLogger("dnsshield.enrichment")

_SEVERITY_ORDER = ["safe", "low", "medium", "high", "critical"]
_TIMEOUT = 20.0

_session = requests.Session()

THREAT_INTEL_HOSTNAMES = frozenset({"www.virustotal.com", "api.abuseipdb.com", "otx.alienvault.com"})


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


def _network_error_message(exc: Exception) -> str:
    if isinstance(exc, requests.Timeout):
        return "timed out - the service didn't respond in time"
    if isinstance(exc, requests.ConnectionError):
        return "network error - couldn't reach the service (check connectivity/DNS)"
    return str(exc)


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

        if malicious >= 10:
            verdict = "critical"
        elif malicious >= 5:
            verdict = "high"
        elif malicious >= 2:
            verdict = "medium"
        elif malicious >= 1 or suspicious >= 2:
            verdict = "low"
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
    except Exception as exc:
        logger.warning("VirusTotal lookup failed for %s: %s", target, exc)
        return {"configured": True, "ok": False, "error": _network_error_message(exc)}


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
    except Exception as exc:
        logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return {"configured": True, "ok": False, "error": _network_error_message(exc)}


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
        elif pulse_count >= 10:
            verdict = "high"
        elif pulse_count >= 3:
            verdict = "medium"
        elif pulse_count >= 1:
            verdict = "low"
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
    except Exception as exc:
        logger.warning("OTX lookup failed for %s: %s", target, exc)
        return {"configured": True, "ok": False, "error": _network_error_message(exc)}


def query_local(target: str, target_type: str, url: str, api_key: str) -> dict[str, Any]:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        resp = _session.post(url, json={"target": target, "type": target_type}, headers=headers, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        verdict = data.get("verdict")
        if verdict not in _SEVERITY_ORDER:
            return {"configured": True, "ok": False, "error": "local service returned an unrecognized verdict"}
        return {
            "configured": True,
            "ok": True,
            "verdict": verdict,
            "score": data.get("score"),
            "summary": data.get("summary") or f"local verdict: {verdict}",
            "details": data,
        }
    except requests.HTTPError as exc:
        return {"configured": True, "ok": False, "error": _http_error_message(exc)}
    except Exception as exc:
        logger.warning("Local enrichment lookup failed for %s: %s", target, exc)
        return {"configured": True, "ok": False, "error": _network_error_message(exc)}


def enrich(target: str, target_type: str, config_store) -> dict[str, Any]:
    target = target.strip()
    sources: dict[str, Any] = {}
    public_enabled = bool(config_store.get("enrichment", "public_enabled", default=False))

    jobs: dict[str, Any] = {}

    def _register(name: str, key: str, run) -> None:
        if not public_enabled:
            sources[name] = {"configured": bool(key), "enabled": False}
        elif not key:
            sources[name] = {"configured": False}
        else:
            jobs[name] = run

    vt_key = config_store.get("enrichment", "virustotal_api_key", default="") or ""
    _register("virustotal", vt_key, lambda: query_virustotal(target, target_type, vt_key))

    otx_key = config_store.get("enrichment", "otx_api_key", default="") or ""
    _register("otx", otx_key, lambda: query_otx(target, target_type, otx_key))

    if target_type == "ip":
        abuse_key = config_store.get("enrichment", "abuseipdb_api_key", default="") or ""
        _register("abuseipdb", abuse_key, lambda: query_abuseipdb(target, abuse_key))
    else:
        sources["abuseipdb"] = None

    local_enabled = bool(config_store.get("enrichment", "local_enabled", default=False))
    local_url = config_store.get("enrichment", "local_url", default="") or ""
    if local_enabled and local_url:
        local_key = config_store.get("enrichment", "local_api_key", default="") or ""
        jobs["local"] = lambda: query_local(target, target_type, local_url, local_key)
    else:
        sources["local"] = {"configured": False}

    if jobs:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs)) as pool:
            futures = {name: pool.submit(run) for name, run in jobs.items()}
            for name, future in futures.items():
                sources[name] = future.result()

    overall: str | None = None
    overall_score: int | None = None
    for src in sources.values():
        if src and src.get("ok"):
            overall = src["verdict"] if overall is None else _severity_max(overall, src["verdict"])
            score = src.get("score") or 0
            overall_score = score if overall_score is None else max(overall_score, score)

    return {
        "target": target,
        "type": target_type,
        "overall_verdict": overall or "unknown",
        "overall_score": overall_score,
        "sources": sources,
    }
