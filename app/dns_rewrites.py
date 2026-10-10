# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

import fnmatch

RECORD_TYPES = ("A", "AAAA", "CNAME", "TXT")
DEFAULT_TTL = 300


def find_rewrite(qname: str, qtype_name: str, config_store) -> tuple[str, int] | None:
    if qtype_name not in RECORD_TYPES:
        return None
    for entry in config_store.get("dns_rewrites", default=[]) or []:
        name = (entry.get("name") or "").rstrip(".").lower()
        value = entry.get("value")
        if not name or not value or entry.get("type") != qtype_name:
            continue
        ttl = int(entry.get("ttl") or DEFAULT_TTL)
        if "*" in name or "?" in name:
            if fnmatch.fnmatchcase(qname, name):
                return value, ttl
        elif qname == name or qname.endswith("." + name):
            return value, ttl
    return None
