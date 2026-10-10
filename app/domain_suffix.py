# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

from __future__ import annotations

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
