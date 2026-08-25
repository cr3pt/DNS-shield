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
    {
        "name": "HaGeZi NSFW",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt",
        "category": "Parental control",
        "description": "HaGeZi's actively maintained adult-content list (~113k domains). Meant for a client group's own extra blocklist source (e.g. a kids' devices group), not the global list.",
    },
    {
        "name": "HaGeZi Gambling",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling-onlydomains.txt",
        "category": "Parental control",
        "description": "HaGeZi's actively maintained online gambling/betting list - very large (~460k domains). Meant for a client group's own extra blocklist source, not the global list.",
    },
    {
        "name": "HaGeZi Social Networks",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/social-onlydomains.txt",
        "category": "Parental control",
        "description": "Major social-media platforms (X/Twitter, TikTok, Instagram, Facebook, Snapchat, Reddit and more). Meant for a client group's own extra blocklist source, not the global list.",
    },
    {
        "name": "HaGeZi Anti-Piracy",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/anti.piracy-onlydomains.txt",
        "category": "Parental control",
        "description": "Torrent, streaming-piracy, and warez sites. Meant for a client group's own extra blocklist source, not the global list.",
    },
    {
        "name": "HaGeZi Fake/Scam Sites",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt",
        "category": "Parental control",
        "description": "Fake online stores, fake streaming sites, subscription traps and similar scams - protects kids (or anyone) from getting scammed, not just from unwanted content. Meant for a client group's own extra blocklist source, not the global list.",
    },
]
