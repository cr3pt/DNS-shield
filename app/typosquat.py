from __future__ import annotations

import re

_MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset(
    {
        "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk", "nhs.uk",
        "com.pl", "net.pl", "org.pl", "info.pl", "edu.pl", "gov.pl", "mil.pl", "waw.pl", "biz.pl",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
        "co.nz", "net.nz", "org.nz", "govt.nz",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
        "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in",
        "com.br", "net.br", "org.br",
        "com.mx", "com.tr", "com.cn", "net.cn", "org.cn", "com.hk", "org.hk", "net.hk",
        "co.za", "org.za", "co.il", "org.il", "net.il",
        "com.sg", "com.my", "co.kr", "or.kr", "co.id", "or.id",
        "com.ar", "com.co", "com.ve",
    }
)

DEFAULT_PROTECTED_DOMAINS: tuple[str, ...] = (
    "google.com",
    "gmail.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "tiktok.com",
    "amazon.com",
    "ebay.com",
    "microsoft.com",
    "outlook.com",
    "live.com",
    "office.com",
    "apple.com",
    "icloud.com",
    "netflix.com",
    "spotify.com",
    "adobe.com",
    "dropbox.com",
    "github.com",
    "steampowered.com",
    "paypal.com",
    "stripe.com",
    "coinbase.com",
    "binance.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "americanexpress.com",
    "dhl.com",
    "fedex.com",
    "ups.com",
    "usps.com",
    "irs.gov",
    "allegro.pl",
    "olx.pl",
    "inpost.pl",
    "poczta-polska.pl",
    "mbank.pl",
    "pkobp.pl",
    "ing.pl",
    "santander.pl",
    "millenniumbank.pl",
    "orange.pl",
    "play.pl",
    "plus.pl",
    "t-mobile.pl",
)

_MIN_PROTECTED_LABEL_LENGTH_FOR_SUBSTRING = 4


def _base_domain(qname: str) -> str:
    labels = qname.rstrip(".").lower().split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else qname.rstrip(".").lower()


def _second_level_label(domain: str) -> str:
    labels = domain.rstrip(".").lower().split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return labels[-3]
    return labels[-2] if len(labels) >= 2 else labels[0]


def _is_embedded_token(candidate_label: str, protected_label: str) -> bool:
    """True only if protected_label appears as a distinct hyphen/edge-bounded
    token inside candidate_label - not merely as a substring. This avoids
    flagging legitimate compound domains like "googleapis", "amazonaws", or
    "canalplus" just because they happen to contain a protected brand name."""
    if protected_label == candidate_label:
        return False
    pattern = r"(?:^|-)" + re.escape(protected_label) + r"(?:$|-)"
    return re.search(pattern, candidate_label) is not None


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def find_typosquat_match(
    qname: str, protected_domains, max_distance: int = 2
) -> tuple[str, str, int] | None:
    qname = qname.rstrip(".").lower()
    if not qname:
        return None
    candidate = _base_domain(qname)
    candidate_label = _second_level_label(candidate)

    best: tuple[str, str, int] | None = None
    for protected in protected_domains:
        protected = protected.strip().rstrip(".").lower()
        if not protected:
            continue

        if candidate == protected or qname == protected or qname.endswith("." + protected):
            return None

        protected_label = _second_level_label(protected)

        if len(protected_label) >= _MIN_PROTECTED_LABEL_LENGTH_FOR_SUBSTRING:
            if _is_embedded_token(candidate_label, protected_label):
                return (protected, "embedded", 0)

        distance = _levenshtein(candidate_label, protected_label)
        # A fuzzy match that's almost as long as either label isn't a meaningful "close
        # spelling" anymore - it just means one of the labels is short (e.g. "x" from
        # x.com, or "wp" from wp.pl), so nearly every short candidate/protected pairing
        # ends up within max_distance of each other by pure chance.
        shortest = min(len(protected_label), len(candidate_label))
        if 0 < distance <= max_distance and distance < shortest and (best is None or distance < best[2]):
            best = (protected, "typo", distance)

    return best
