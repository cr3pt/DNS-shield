"""Manual, opt-in threat-intelligence enrichment: VirusTotal, AbuseIPDB,
AlienVault OTX, and an optional self-hosted/local reputation service.

Every call here happens *only* because a user clicked "Enrich" in the
dashboard - nothing in this module is ever invoked automatically, on a
timer, or as a side effect of resolving a DNS query.

The three public cloud services are gated by a second, explicit switch on
top of having an API key configured: `enrichment.public_enabled` in
Settings -> Threat intelligence, off by default. Saving an API key alone
does not start sending anything anywhere - a user has to deliberately
flip that switch too, since these are the one category of outbound call
in this project that leaves the local network, and this project exists
specifically because another DNS blocker made exactly that kind of call
without asking (see the README). While the switch is off, a configured
key still shows in Settings, but enrich() reports each public source as
"disabled" rather than calling it.

AbuseIPDB has no domain-lookup endpoint - it's only ever queried for an
IP target, per its own API (see enrich()).

The local option (`enrichment.local_enabled` + `enrichment.local_url`) has
no such switch, since it's a service *you* run and pointed this at
yourself - see query_local() for the request/response contract.
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

# The fixed hostnames the three public services live at - imported into
# app.upstream.protected_hostnames(), which only actually exempts them from
# blocking once enrichment.public_enabled is turned on (see that function):
# no standing blocklist hole for hosts DNS-shield has no reason to talk to
# while the switch is off.
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
    # Deliberately not str(exc) - a requests.ConnectionError's message is
    # the raw connection-pool/urllib3 repr (nested exception classes,
    # socket errors, retry counts), not something worth putting in front of
    # a user; the full detail still reaches the log via logger.warning at
    # each call site.
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

        # VirusTotal engines number in the dozens (usually 70-90) - a single
        # "malicious" hit out of that many is a weak, often false-positive
        # signal, not "high" severity on its own. These thresholds are
        # counts of engines flagging it, not percentages.
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
    except Exception as exc:  # noqa: BLE001
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
    except Exception as exc:  # noqa: BLE001
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

        # A single pulse can be a broad/low-confidence community report, not
        # confirmation of anything - give it its own "low" tier instead of
        # jumping straight to "medium" the moment any pulse exists at all.
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
    except Exception as exc:  # noqa: BLE001
        logger.warning("OTX lookup failed for %s: %s", target, exc)
        return {"configured": True, "ok": False, "error": _network_error_message(exc)}


def query_local(target: str, target_type: str, url: str, api_key: str) -> dict[str, Any]:
    """Query a self-hosted reputation service at a user-supplied URL.

    Contract: DNS-shield POSTs {"target": <domain-or-ip>, "type": "domain"|"ip"}
    as JSON (plus "Authorization: Bearer <api_key>" if a key is set), and
    expects a JSON response {"verdict": "safe"|"low"|"medium"|"high"|"critical",
    "score": <0-100, optional>, "summary": "<string, optional>"}. Anything
    else (unreachable, non-2xx, missing/unrecognized verdict) is reported as
    a failed lookup rather than guessed at.
    """
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
    except Exception as exc:  # noqa: BLE001
        logger.warning("Local enrichment lookup failed for %s: %s", target, exc)
        return {"configured": True, "ok": False, "error": _network_error_message(exc)}


def enrich(target: str, target_type: str, config_store) -> dict[str, Any]:
    """target_type is "domain" or "ip". AbuseIPDB is only ever queried for
    an IP target - it has no domain-lookup endpoint, so it's reported as
    inapplicable (None) rather than "not configured" for a domain target.

    The three public sources are additionally gated by
    enrichment.public_enabled (default off) - see the module docstring.
    """
    target = target.strip()
    sources: dict[str, Any] = {}
    public_enabled = bool(config_store.get("enrichment", "public_enabled", default=False))

    def _public(name: str, key: str, run) -> dict[str, Any]:
        if not public_enabled:
            return {"configured": bool(key), "enabled": False}
        if not key:
            return {"configured": False}
        return run()

    vt_key = config_store.get("enrichment", "virustotal_api_key", default="") or ""
    sources["virustotal"] = _public("virustotal", vt_key, lambda: query_virustotal(target, target_type, vt_key))

    otx_key = config_store.get("enrichment", "otx_api_key", default="") or ""
    sources["otx"] = _public("otx", otx_key, lambda: query_otx(target, target_type, otx_key))

    if target_type == "ip":
        abuse_key = config_store.get("enrichment", "abuseipdb_api_key", default="") or ""
        sources["abuseipdb"] = _public("abuseipdb", abuse_key, lambda: query_abuseipdb(target, abuse_key))
    else:
        sources["abuseipdb"] = None

    local_enabled = bool(config_store.get("enrichment", "local_enabled", default=False))
    local_url = config_store.get("enrichment", "local_url", default="") or ""
    if local_enabled and local_url:
        local_key = config_store.get("enrichment", "local_api_key", default="") or ""
        sources["local"] = query_local(target, target_type, local_url, local_key)
    else:
        sources["local"] = {"configured": False}

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
