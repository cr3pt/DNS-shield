from __future__ import annotations

import re
import socket
from typing import Any

_REFERRAL_RE = re.compile(r"^\s*(?:refer|whois):\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_STATUS_RE = re.compile(r"^\s*Domain Status:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_NS_RE = re.compile(r"^\s*Name Server:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_FIELD_PATTERNS = {
    "registrar": re.compile(r"^\s*Registrar:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    "registrant_org": re.compile(r"^\s*Registrant Organization:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    "registrant_name": re.compile(r"^\s*Registrant Name:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    "registrant_country": re.compile(r"^\s*Registrant Country:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    "creation_date": re.compile(
        r"^\s*(?:Creation Date|Created On|Domain Registration Date|created):\s*(.+)$", re.IGNORECASE | re.MULTILINE
    ),
    "expiration_date": re.compile(
        r"^\s*(?:Registry Expiry Date|Expiration Date|Expiry Date|paid-till):\s*(.+)$", re.IGNORECASE | re.MULTILINE
    ),
    "referral_server": re.compile(r"^\s*Registrar WHOIS Server:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
}


def _query_whois_server(server: str, query: str, timeout: float = 8.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode("utf-8", errors="ignore"))
        chunks: list[bytes] = []
        sock.settimeout(timeout)
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")


def find_whois_server(tld: str, timeout: float = 6.0) -> str | None:
    try:
        text = _query_whois_server("whois.iana.org", tld, timeout=timeout)
    except OSError:
        return None
    match = _REFERRAL_RE.search(text)
    return match.group(1).strip() if match else None


def _parse_whois_text(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, pattern in _FIELD_PATTERNS.items():
        match = pattern.search(text)
        if match:
            result[key] = match.group(1).strip()
    result["status"] = sorted({s.strip().lower() for s in _STATUS_RE.findall(text)})
    result["nameservers"] = sorted({s.strip().lower() for s in _NS_RE.findall(text)})
    return result


def whois_lookup(domain: str, timeout: float = 8.0) -> dict[str, Any] | None:
    domain = domain.strip().rstrip(".").lower()
    labels = domain.split(".")
    if len(labels) < 2:
        return None
    server = find_whois_server(labels[-1], timeout=timeout)
    if not server:
        return None
    try:
        text = _query_whois_server(server, domain, timeout=timeout)
    except OSError:
        return None

    parsed = _parse_whois_text(text)
    referral = parsed.pop("referral_server", None)
    if referral and referral.lower() != server.lower():
        try:
            deeper_text = _query_whois_server(referral, domain, timeout=timeout)
        except OSError:
            deeper_text = None
        if deeper_text:
            deeper = _parse_whois_text(deeper_text)
            deeper.pop("referral_server", None)
            for key, value in deeper.items():
                if value:
                    parsed[key] = value
            server = referral

    has_data = any(
        parsed.get(key) for key in ("registrar", "creation_date", "expiration_date", "registrant_org", "registrant_name")
    )
    if not has_data:
        return None
    parsed["server"] = server
    return parsed
