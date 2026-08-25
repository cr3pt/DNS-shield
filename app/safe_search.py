from __future__ import annotations

_GOOGLE_TLDS = (
    "com", "co.uk", "de", "fr", "ca", "com.au", "co.in", "it", "es", "nl",
    "pl", "com.br", "co.jp", "ru", "com.mx", "co.id", "com.tr", "co.kr",
    "com.hk", "com.sg", "co.za", "com.tw", "se", "no", "dk", "fi", "at",
    "ch", "be", "pt", "gr", "cz", "hu", "ro", "ie", "co.nz", "com.ar",
)

_SAFE_SEARCH_TARGETS: dict[str, str] = {}
for _tld in _GOOGLE_TLDS:
    _SAFE_SEARCH_TARGETS[f"google.{_tld}"] = "forcesafesearch.google.com"
    _SAFE_SEARCH_TARGETS[f"www.google.{_tld}"] = "forcesafesearch.google.com"

for _host in ("bing.com", "www.bing.com", "cn.bing.com"):
    _SAFE_SEARCH_TARGETS[_host] = "strict.bing.com"

for _host in ("duckduckgo.com", "www.duckduckgo.com", "lite.duckduckgo.com", "html.duckduckgo.com"):
    _SAFE_SEARCH_TARGETS[_host] = "safe.duckduckgo.com"

for _host in (
    "youtube.com",
    "www.youtube.com",
    "m.youtube.com",
    "youtubei.googleapis.com",
    "youtube.googleapis.com",
    "www.youtube-nocookie.com",
):
    _SAFE_SEARCH_TARGETS[_host] = "restrict.youtube.com"

for _host in ("yandex.ru", "www.yandex.ru", "yandex.com", "www.yandex.com"):
    _SAFE_SEARCH_TARGETS[_host] = "familysearch.yandex.ru"


def find_safe_search_target(qname: str) -> str | None:
    return _SAFE_SEARCH_TARGETS.get(qname.rstrip(".").lower())
