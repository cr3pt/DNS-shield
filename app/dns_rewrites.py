"""Custom local DNS records ("rewrites"): answer a hostname with an IP you
choose yourself, entirely locally - no upstream query, no blocklist
involvement. Handy for internal hostnames your public DNS obviously has no
idea about (e.g. "nas.home" -> 192.168.1.10).

Checked after block_reason() and before the cache/upstream path (see
FilteringResolver.resolve() in app/dns_server.py) - a rewrite is an answer,
not an exemption, so a fully blocked client or an already-blocked domain
behaves exactly as blocked regardless of any rewrite entry.

A/AAAA only, matched exactly or as a subdomain of the configured name (the
same rule used everywhere else in this app for domain matching) - no CNAME
chasing, to keep this a flat, always-terminates lookup.
"""

from __future__ import annotations

RECORD_TYPES = ("A", "AAAA")


def find_rewrite(qname: str, qtype_name: str, config_store) -> str | None:
    """Returns the configured IP for the first matching entry of this exact
    record type, or None if nothing matches (including when qtype_name isn't
    A/AAAA - there is nothing to rewrite for any other query type).
    """
    if qtype_name not in RECORD_TYPES:
        return None
    for entry in config_store.get("dns_rewrites", default=[]) or []:
        name = (entry.get("name") or "").rstrip(".").lower()
        value = entry.get("value")
        if not name or not value or entry.get("type") != qtype_name:
            continue
        if qname == name or qname.endswith("." + name):
            return value
    return None
