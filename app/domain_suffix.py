# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import functools
import re
from urllib.parse import urlparse

import tldextract

_extractor = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def registrable_domain(hostname: str) -> str:
    hostname = (hostname or "").strip().rstrip(".").lower()
    if not hostname:
        return hostname
    result = _extractor(hostname)
    if result.domain and result.suffix:
        return f"{result.domain}.{result.suffix}"
    return result.domain or hostname


_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


def normalize_domain(value: str) -> str:
    """Turn what someone typed into an allow/deny/ignore list into the
    lowercase ASCII domain DNS queries arrive as, or raise ValueError.

    Accepts "Example.COM.", "*.example.com" (subdomains are always covered
    anyway), an IDN ("żółw.pl" -> "xn--w-uga1v8h.pl") and a pasted URL
    ("https://ads.example.com/path" -> "ads.example.com"). Anything else that
    isn't a domain name - a path like "user/model-0.6b", spaces, an IP:port -
    is refused, so it can't end up as a rule that never matches."""
    text = (value or "").strip()
    if "://" in text:
        host = urlparse(text).hostname
        if not host:
            raise ValueError(f'"{value}" is not a valid domain name')
        text = host
    text = text.strip().rstrip(".").lower()
    if text.startswith("*."):
        text = text[2:]
    if not text:
        raise ValueError("Enter a domain name")
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError(f'"{value}" is not a valid domain name') from None
    labels = text.split(".")
    if len(text) > 253 or not all(_LABEL_RE.match(label) for label in labels):
        raise ValueError(f'"{value}" is not a valid domain name (only letters, digits, "-", "_" and dots)')
    return text


@functools.lru_cache(maxsize=4096)
def _rule_domain(value: str) -> str:
    try:
        return normalize_domain(value)
    except ValueError:
        text = (value or "").strip().rstrip(".").lower()
        return text[2:] if text.startswith("*.") else text


def rule_domains(rule: dict) -> list[str]:
    """The domains a per-domain upstream rule covers, in the form queries
    arrive in (lowercase ASCII, no trailing dot, no "*."). Tolerates rules
    edited by hand: "domains" given as one comma/space separated string, or
    the singular "domain" key."""
    raw = rule.get("domains")
    if raw is None or raw == []:
        raw = rule.get("domain")
    if isinstance(raw, str):
        raw = re.split(r"[,\s]+", raw)
    result = []
    for value in raw or []:
        if not isinstance(value, str):
            continue
        domain = _rule_domain(value)
        if domain:
            result.append(domain)
    return result
