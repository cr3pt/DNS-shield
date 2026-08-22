"""A short, static list of well-known public blocklists you can add with
one click from the dashboard's Blocklists section, instead of having to
go find and paste a URL yourself.

This is a fixed list baked into DNS-shield itself - fetched from nowhere,
checked against nothing at runtime. Picking "Add" on an entry just POSTs
its name/url to the normal /api/blocklists endpoint, the exact same as
typing them in by hand; DNS-shield then fetches that URL on the next
refresh like any other configured source, complete with the same format
auto-detection, fetch-failure handling, and disable/remove controls.

Every Firebog entry here is one of that site's (https://firebog.net)
"ticked" lists - the subset their own picker marks safe for a default
setup, as opposed to the site's more aggressive or narrowly-scoped
options - plus StevenBlack's Unified Hosts (this project's own example
config has shipped with it since day one) and AdGuard's own DNS filter
straight from AdGuard's registry. Tick/cross status and exact URLs can
change over time on any of these upstream projects; if a list here stops
looking right for you, Disable or Remove it from the Blocklists table
like any other source - nothing about picking it from this catalog is
special or hard to undo.
"""

from __future__ import annotations

BLOCKLIST_CATALOG: list[dict[str, str]] = [
    {
        "name": "StevenBlack Unified Hosts",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "category": "Ads, tracking & malware",
        "description": "General-purpose, widely used hosts-file merge of several ad/tracking/malware sources.",
    },
    {
        "name": "AdGuard DNS filter",
        "url": "https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/master/assets/filter_1.txt",
        "category": "Ads, tracking & malware",
        "description": "AdGuard's own general-purpose DNS filter, straight from their HostlistsRegistry - the default list AdGuard Home itself ships with.",
    },
    {
        "name": "Firebog - AdguardDNS",
        "url": "https://v.firebog.net/hosts/AdguardDNS.txt",
        "category": "Ads & tracking",
        "description": "AdGuard's own DNS filter, mirrored by Firebog in plain hosts format.",
    },
    {
        "name": "Firebog - Admiral",
        "url": "https://v.firebog.net/hosts/Admiral.txt",
        "category": "Ads & tracking",
        "description": "Anti anti-adblock and additional ad-serving domains.",
    },
    {
        "name": "Firebog - Prigent-Ads",
        "url": "https://v.firebog.net/hosts/Prigent-Ads.txt",
        "category": "Ads & tracking",
        "description": "Ad-serving domains, one of Firebog's longest-standing entries.",
    },
    {
        "name": "Firebog - Easyprivacy",
        "url": "https://v.firebog.net/hosts/Easyprivacy.txt",
        "category": "Tracking & telemetry",
        "description": "EasyList's tracking/analytics companion list, mirrored in hosts format.",
    },
    {
        "name": "Firebog - Prigent-Malware",
        "url": "https://v.firebog.net/hosts/Prigent-Malware.txt",
        "category": "Malicious",
        "description": "Known malware-distribution and command-and-control domains.",
    },
    {
        "name": "Firebog - Prigent-Crypto",
        "url": "https://v.firebog.net/hosts/Prigent-Crypto.txt",
        "category": "Malicious",
        "description": "Cryptojacking and malicious cryptomining domains.",
    },
    {
        "name": "Firebog - W3KBL",
        "url": "https://v.firebog.net/hosts/static/w3kbl.txt",
        "category": "Ads & tracking",
        "description": "A smaller, conservative general-purpose ad/tracking list.",
    },
    {
        "name": "HaGeZi Multi PRO",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
        "category": "Ads, tracking & malware",
        "description": "HaGeZi's actively maintained, extended general-purpose list - ads, affiliate links, trackers, telemetry, fake sites, phishing, malware and scams. Recommended tier of a very popular, frequently updated project.",
    },
    {
        "name": "HaGeZi Threat Intelligence Feeds",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt",
        "category": "Malicious",
        "description": "HaGeZi's aggregation of live threat-intel feeds - malware, cryptojacking, spam, scam and phishing domains. Very large and refreshed frequently; heavier than the other lists here.",
    },
    {
        "name": "1Hosts (Lite)",
        "url": "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/hosts.txt",
        "category": "Ads, tracking & malware",
        "description": "Actively maintained, curated general-purpose blocklist (badmojr/1Hosts) aimed at low false positives.",
    },
    {
        "name": "DurableNapkin Scam Blocklist",
        "url": "https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt",
        "category": "Malicious",
        "description": "Focused list of scam/fraud domains, updated regularly.",
    },
]
