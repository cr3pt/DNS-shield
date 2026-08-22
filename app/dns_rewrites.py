from __future__ import annotations

RECORD_TYPES = ("A", "AAAA")


def find_rewrite(qname: str, qtype_name: str, config_store) -> str | None:
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
