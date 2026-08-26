from __future__ import annotations

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
    return ".".join(labels[-2:]) if len(labels) >= 2 else qname.rstrip(".").lower()


def _second_level_label(domain: str) -> str:
    labels = domain.rstrip(".").lower().split(".")
    return labels[-2] if len(labels) >= 2 else labels[0]


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
            if protected_label != candidate_label and protected_label in candidate_label:
                return (protected, "embedded", 0)

        distance = _levenshtein(candidate_label, protected_label)
        if 0 < distance <= max_distance and (best is None or distance < best[2]):
            best = (protected, "typo", distance)

    return best
