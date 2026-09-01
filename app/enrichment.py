from __future__ import annotations

import concurrent.futures
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import requests

logger = logging.getLogger("dnsshield.enrichment")

_SEVERITY_ORDER = ["safe", "low", "medium", "high", "critical"]
# Per-source HTTP timeout. Sources run concurrently (one thread each), so the
# worst-case wall-clock time for a whole enrich() call is bounded by this,
# not by the number of sources - keep it tight enough that one slow/unreachable
# source doesn't make every manual "Enrich" click feel stuck.
_TIMEOUT = 10.0

_session = requests.Session()

THREAT_INTEL_HOSTNAMES = frozenset({
    "www.virustotal.com",
    "api.abuseipdb.com",
    "otx.alienvault.com",
    "api.greynoise.io",
    "api.shodan.io",
    "urlhaus-api.abuse.ch",
    "crt.sh",
    "rdap.org",
    "ipinfo.io",
})


def _severity_max(a: str, b: str) -> str:
    ia = _SEVERITY_ORDER.index(a) if a in _SEVERITY_ORDER else -1
    ib = _SEVERITY_ORDER.index(b) if b in _SEVERITY_ORDER else -1
    return a if ia >= ib else b


def _http_error_message(exc: requests.HTTPError) -> str:
    resp = exc.response
    status = resp.status_code if resp is not None else None
    if status in (401, 403):
        return "rejected - check the API key in Settings"
    if status == 404:
        return "no data on record for this indicator yet"
    if status == 429:
        retry_after = resp.headers.get("Retry-After") if resp is not None else None
        return f"rate limited - try again in {retry_after}s" if retry_after else "rate limited - try again later"
    if status is not None and 500 <= status < 600:
        return f"service error (HTTP {status}) - try again later"
    return f"HTTP {status}" if status else str(exc)


def _network_error_message(exc: Exception) -> str:
    # Order matters: requests.exceptions.SSLError subclasses ConnectionError, so it
    # must be checked first or it'd always be reported as a plain network error.
    if isinstance(exc, requests.Timeout):
        return "timed out - the service didn't respond in time"
    if isinstance(exc, requests.exceptions.SSLError):
        return "TLS/certificate error - couldn't verify the service's identity"
    if isinstance(exc, requests.ConnectionError):
        return "network error - couldn't reach the service (check connectivity/DNS)"
    if isinstance(exc, requests.exceptions.TooManyRedirects):
        return "too many redirects - the service's response looked wrong"
    if isinstance(exc, ValueError):
        # resp.json() raises a ValueError subclass (json.JSONDecodeError, or
        # requests' own JSONDecodeError on newer versions) when the body isn't JSON.
        return "the service returned an invalid (non-JSON) response"
    if isinstance(exc, (KeyError, TypeError, IndexError, AttributeError)):
        # The response was valid JSON but not shaped the way this integration
        # expects - most often the service changed its API.
        return "the service returned an unexpected response format"
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


def query_greynoise(ip: str, api_key: str) -> dict[str, Any]:
    url = f"https://api.greynoise.io/v3/community/{quote(ip, safe='')}"
    try:
        resp = _session.get(url, headers={"key": api_key, "Accept": "application/json"}, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        riot = bool(data.get("riot"))
        noise = bool(data.get("noise"))
        classification = data.get("classification") or "unknown"
        name = data.get("name") or "unclassified"

        if riot:
            verdict = "safe"
            summary = f"Known benign business service ({name})"
            score = 0
        elif not noise:
            verdict = "safe"
            summary = "Not observed scanning the internet (no GreyNoise data on record)"
            score = 0
        elif classification == "malicious":
            verdict = "high"
            summary = f"Observed scanning the internet, classified malicious ({name})"
            score = 70
        elif classification == "benign":
            verdict = "safe"
            summary = f"Observed scanning the internet but classified benign ({name})"
            score = 0
        else:
            verdict = "low"
            summary = "Observed scanning the internet, unclassified"
            score = 20

        return {
            "configured": True,
            "ok": True,
            "verdict": verdict,
            "score": score,
            "summary": summary,
            "details": data,
            "link": data.get("link") or f"https://viz.greynoise.io/ip/{quote(ip, safe='')}",
        }
    except requests.HTTPError as exc:
        return {"configured": True, "ok": False, "error": _http_error_message(exc)}
    except Exception as exc:
        logger.warning("GreyNoise lookup failed for %s: %s", ip, exc)
        return {"configured": True, "ok": False, "error": _network_error_message(exc)}


def query_shodan(ip: str, api_key: str) -> dict[str, Any]:
    url = f"https://api.shodan.io/shodan/host/{quote(ip, safe='')}"
    try:
        resp = _session.get(url, params={"key": api_key}, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        ports = data.get("ports") or []
        vulns = data.get("vulns") or []
        tags = data.get("tags") or []

        if any(t in tags for t in ("malware", "compromised", "botnet")):
            verdict = "critical"
        elif len(vulns) >= 5:
            verdict = "high"
        elif len(vulns) >= 1:
            verdict = "medium"
        else:
            verdict = "safe"

        summary = f"{len(ports)} open port(s), {len(vulns)} known vulnerabilit{'y' if len(vulns) == 1 else 'ies'}"
        if tags:
            summary += f" - tags: {', '.join(tags)}"

        return {
            "configured": True,
            "ok": True,
            "verdict": verdict,
            "score": min(100, len(vulns) * 15),
            "summary": summary,
            "details": {"ports": ports, "vulns": vulns, "tags": tags, "org": data.get("org")},
            "link": f"https://www.shodan.io/host/{quote(ip, safe='')}",
        }
    except requests.HTTPError as exc:
        return {"configured": True, "ok": False, "error": _http_error_message(exc)}
    except Exception as exc:
        logger.warning("Shodan lookup failed for %s: %s", ip, exc)
        return {"configured": True, "ok": False, "error": _network_error_message(exc)}


def query_urlhaus(target: str, target_type: str, api_key: str) -> dict[str, Any]:
    url = "https://urlhaus-api.abuse.ch/v1/host/"
    try:
        resp = _session.post(url, data={"host": target}, headers={"Auth-Key": api_key}, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        status = data.get("query_status")

        if status == "no_results":
            return {
                "configured": True,
                "ok": True,
                "verdict": "safe",
                "score": 0,
                "summary": "No known malware URLs hosted here",
                "details": data,
                "link": f"https://urlhaus.abuse.ch/host/{quote(target, safe='')}/",
            }
        if status != "ok":
            return {"configured": True, "ok": False, "error": f"unrecognized response ({status or 'no status'})"}

        urls = data.get("urls") or []
        online = sum(1 for u in urls if u.get("url_status") == "online")
        if online >= 3:
            verdict = "critical"
        elif online >= 1:
            verdict = "high"
        else:
            verdict = "medium"

        return {
            "configured": True,
            "ok": True,
            "verdict": verdict,
            "score": min(100, online * 25 + 10),
            "summary": f"{len(urls)} malware URL(s) on record ({online} currently online)",
            "details": {"url_count": len(urls), "online": online},
            "link": f"https://urlhaus.abuse.ch/host/{quote(target, safe='')}/",
        }
    except requests.HTTPError as exc:
        return {"configured": True, "ok": False, "error": _http_error_message(exc)}
    except Exception as exc:
        logger.warning("URLhaus lookup failed for %s: %s", target, exc)
        return {"configured": True, "ok": False, "error": _network_error_message(exc)}


def _rdap_event_date(data: dict[str, Any], action: str) -> str | None:
    return next(
        (ev.get("eventDate") for ev in data.get("events", []) if ev.get("eventAction") == action),
        None,
    )


def _rdap_entity_name(data: dict[str, Any], role: str) -> str | None:
    """Pull a human-readable name for the entity with the given RDAP role
    (e.g. "registrar") out of its vCard - registrant name/email is almost
    always redacted for privacy, but the registrar itself is public."""
    for entity in data.get("entities", []) or []:
        if role not in (entity.get("roles") or []):
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1:
            for field in vcard[1]:
                if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                    return field[3]
        handle = entity.get("handle")
        if handle:
            return str(handle)
    return None


def query_rdap(domain: str) -> dict[str, Any]:
    """Full WHOIS-equivalent domain lookup via RDAP (the modern, structured
    replacement for the WHOIS protocol - same registry data, no need to parse
    free-text WHOIS responses)."""
    url = f"https://rdap.org/domain/{quote(domain, safe='')}"
    try:
        resp = _session.get(url, headers={"Accept": "application/rdap+json"}, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        registration_date = _rdap_event_date(data, "registration")
        expiration_date = _rdap_event_date(data, "expiration")
        last_changed_date = _rdap_event_date(data, "last changed")
        registrar = _rdap_entity_name(data, "registrar")
        statuses = data.get("status") or []
        nameservers = sorted(
            (ns.get("ldhName") or "").lower() for ns in data.get("nameservers", []) if ns.get("ldhName")
        )

        age_days: int | None = None
        if registration_date:
            try:
                reg_dt = datetime.fromisoformat(registration_date.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - reg_dt).days
            except ValueError:
                age_days = None

        if age_days is None:
            verdict, age_note = "safe", "no registration date on record"
        elif age_days < 7:
            verdict, age_note = "high", f"registered {age_days} day(s) ago - very recently registered"
        elif age_days < 30:
            verdict, age_note = "medium", f"registered {age_days} day(s) ago - recently registered"
        elif age_days < 90:
            verdict, age_note = "low", f"registered {age_days} day(s) ago"
        else:
            verdict, age_note = "safe", f"registered {age_days} day(s) ago"

        summary_parts = [age_note.capitalize()]
        if registrar:
            summary_parts.append(f"registrar: {registrar}")
        if expiration_date:
            summary_parts.append(f"expires: {expiration_date[:10]}")
        if nameservers:
            summary_parts.append(f"{len(nameservers)} nameserver(s)")
        summary = ", ".join(summary_parts)

        score = {"safe": 0, "low": 20, "medium": 45, "high": 75}[verdict]
        return {
            "configured": True,
            "ok": True,
            "verdict": verdict,
            "score": score,
            "summary": summary,
            "details": {
                "age_days": age_days,
                "registration_date": registration_date,
                "expiration_date": expiration_date,
                "last_changed_date": last_changed_date,
                "registrar": registrar,
                "status": statuses,
                "nameservers": nameservers,
            },
            "link": f"https://who.is/whois/{quote(domain, safe='')}",
        }
    except requests.HTTPError as exc:
        return {"configured": True, "ok": False, "error": _http_error_message(exc)}
    except Exception as exc:
        logger.warning("RDAP lookup failed for %s: %s", domain, exc)
        return {"configured": True, "ok": False, "error": _network_error_message(exc)}


def query_ipinfo(ip: str, api_key: str) -> dict[str, Any]:
    """IP geolocation/ASN/ownership lookup (city, region, country, org/ISP,
    hostname) - purely informational, not a reputation signal, so it never
    contributes to the overall verdict."""
    url = f"https://ipinfo.io/{quote(ip, safe='')}/json"
    try:
        resp = _session.get(
            url, params={"token": api_key} if api_key else None, timeout=_TIMEOUT
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("bogon"):
            return {
                "configured": True,
                "ok": True,
                "verdict": "safe",
                "score": 0,
                "summary": "Private/reserved IP address - no geolocation data",
                "details": data,
                "link": f"https://ipinfo.io/{quote(ip, safe='')}",
            }

        city = data.get("city") or ""
        region = data.get("region") or ""
        country = data.get("country") or ""
        org = data.get("org") or ""
        location = ", ".join(part for part in (city, region, country) if part) or "unknown location"
        summary = f"{location}" + (f" - {org}" if org else "")

        return {
            "configured": True,
            "ok": True,
            "verdict": "safe",
            "score": 0,
            "summary": summary,
            "details": {
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country"),
                "loc": data.get("loc"),
                "org": data.get("org"),
                "postal": data.get("postal"),
                "timezone": data.get("timezone"),
                "hostname": data.get("hostname"),
            },
            "link": f"https://ipinfo.io/{quote(ip, safe='')}",
        }
    except requests.HTTPError as exc:
        return {"configured": True, "ok": False, "error": _http_error_message(exc)}
    except Exception as exc:
        logger.warning("ipinfo lookup failed for %s: %s", ip, exc)
        return {"configured": True, "ok": False, "error": _network_error_message(exc)}


def query_crtsh(domain: str) -> dict[str, Any]:
    url = "https://crt.sh/"
    try:
        resp = _session.get(url, params={"q": domain, "output": "json"}, timeout=_TIMEOUT)
        resp.raise_for_status()
        entries = resp.json()
        subdomains: set[str] = set()
        for entry in entries:
            for name in (entry.get("name_value") or "").split("\n"):
                name = name.strip().lower()
                if name:
                    subdomains.add(name)

        return {
            "configured": True,
            "ok": True,
            "verdict": "safe",
            "score": 0,
            "summary": f"{len(entries)} certificate(s) logged, {len(subdomains)} distinct name(s) seen",
            "details": {"certificate_count": len(entries), "distinct_names": len(subdomains)},
            "link": f"https://crt.sh/?q={quote(domain, safe='')}",
        }
    except requests.HTTPError as exc:
        return {"configured": True, "ok": False, "error": _http_error_message(exc)}
    except Exception as exc:
        logger.warning("crt.sh lookup failed for %s: %s", domain, exc)
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

    def _register_toggle(name: str, enabled: bool, run) -> None:
        if not public_enabled:
            sources[name] = {"configured": enabled, "enabled": False}
        elif not enabled:
            sources[name] = {"configured": False}
        else:
            jobs[name] = run

    vt_key = config_store.get("enrichment", "virustotal_api_key", default="") or ""
    _register("virustotal", vt_key, lambda: query_virustotal(target, target_type, vt_key))

    otx_key = config_store.get("enrichment", "otx_api_key", default="") or ""
    _register("otx", otx_key, lambda: query_otx(target, target_type, otx_key))

    urlhaus_key = config_store.get("enrichment", "urlhaus_api_key", default="") or ""
    _register("urlhaus", urlhaus_key, lambda: query_urlhaus(target, target_type, urlhaus_key))

    if target_type == "ip":
        abuse_key = config_store.get("enrichment", "abuseipdb_api_key", default="") or ""
        _register("abuseipdb", abuse_key, lambda: query_abuseipdb(target, abuse_key))

        greynoise_key = config_store.get("enrichment", "greynoise_api_key", default="") or ""
        _register("greynoise", greynoise_key, lambda: query_greynoise(target, greynoise_key))

        shodan_key = config_store.get("enrichment", "shodan_api_key", default="") or ""
        _register("shodan", shodan_key, lambda: query_shodan(target, shodan_key))

        ipinfo_enabled = bool(config_store.get("enrichment", "ipinfo_enabled", default=False))
        ipinfo_key = config_store.get("enrichment", "ipinfo_api_key", default="") or ""
        _register_toggle("ipinfo", ipinfo_enabled, lambda: query_ipinfo(target, ipinfo_key))
    else:
        sources["abuseipdb"] = None
        sources["greynoise"] = None
        sources["shodan"] = None
        sources["ipinfo"] = None

    if target_type == "domain":
        rdap_enabled = bool(config_store.get("enrichment", "rdap_enabled", default=False))
        _register_toggle("rdap", rdap_enabled, lambda: query_rdap(target))

        crtsh_enabled = bool(config_store.get("enrichment", "crtsh_enabled", default=False))
        _register_toggle("crtsh", crtsh_enabled, lambda: query_crtsh(target))
    else:
        sources["rdap"] = None
        sources["crtsh"] = None

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


_VERDICT_RANK = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def maybe_alert_on_verdict(result: dict[str, Any], config_store, anomaly) -> None:
    """Turn a bad-enough enrich() result into an Alerts-tab entry, shared by
    both the manual Enrich endpoint and the auto-enrich background worker so
    the two never diverge in what counts as "bad enough"."""
    if anomaly is None:
        return
    enr_cfg = config_store.get("enrichment", default={}) or {}
    if not bool(enr_cfg.get("alert_enabled", True)):
        return
    threshold = _VERDICT_RANK.get(enr_cfg.get("alert_min_severity", "medium") or "medium", 2)
    verdict = result.get("overall_verdict", "unknown")
    if _VERDICT_RANK.get(verdict, -1) < threshold:
        return
    flagged = [
        name for name, src in result.get("sources", {}).items()
        if src and src.get("ok") and src.get("verdict") not in (None, "safe")
    ]
    summary = f'{result["target"]} flagged {verdict} by threat-intel' + (
        f" ({', '.join(sorted(flagged))})" if flagged else ""
    )
    anomaly.record_threat_intel_alert(
        result["target"], result["type"], verdict, summary,
        {"overall_score": result.get("overall_score"), "flagged_sources": flagged},
    )
