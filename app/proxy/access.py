# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

from typing import Any


def is_hostname_allowed(user: dict[str, Any] | None, hostname: str) -> bool:
    if user is None or user.get("role") == "admin":
        return True
    allowed = (user.get("permissions") or {}).get("allowed_domains") or []
    base = hostname.lower()
    return any(base == d or base.endswith("." + d) for d in allowed)


def is_domain_allowed(user: dict[str, Any] | None, hostnames: list[str]) -> bool:
    if user is None or user.get("role") == "admin":
        return True
    return all(is_hostname_allowed(user, h) for h in hostnames or [])
