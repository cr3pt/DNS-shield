# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""Popular services that can be blocked with one switch, globally
(`blocked_services`) or per client group (`client_groups[].blocked_services`).

Each service lists the domains its apps and sites need; a query for one of
them or any of its subdomains is blocked. The lists cover the main apps and
their CDNs, not every partner domain, so a service may keep working in part
(an embedded video on another site, say)."""

from __future__ import annotations

from collections.abc import Iterable

SERVICES: dict[str, dict] = {
    "youtube": {
        "name": "YouTube",
        "domains": [
            "youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "youtube-nocookie.com",
            "youtubei.googleapis.com", "youtube.googleapis.com", "yt.be", "youtubekids.com",
        ],
    },
    "tiktok": {
        "name": "TikTok",
        "domains": [
            "tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokcdn-us.com", "tiktokv.us", "tiktokw.us",
            "byteoversea.com", "ibytedtos.com", "ibyteimg.com", "ttwstatic.com", "musical.ly",
        ],
    },
    "instagram": {
        "name": "Instagram",
        "domains": ["instagram.com", "cdninstagram.com", "ig.me", "instagr.am"],
    },
    "facebook": {
        "name": "Facebook",
        "domains": ["facebook.com", "facebook.net", "fbcdn.net", "fb.com", "fb.me", "fbsbx.com", "messenger.com"],
    },
    "whatsapp": {
        "name": "WhatsApp",
        "domains": ["whatsapp.com", "whatsapp.net", "wa.me"],
    },
    "snapchat": {
        "name": "Snapchat",
        "domains": ["snapchat.com", "snap.com", "snapkit.com", "sc-cdn.net", "snapads.com", "sc-static.net", "feelinsonice-hrd.appspot.com"],
    },
    "twitter": {
        "name": "X (Twitter)",
        "domains": ["twitter.com", "x.com", "twimg.com", "t.co", "twttr.com", "twitter.co"],
    },
    "reddit": {
        "name": "Reddit",
        "domains": ["reddit.com", "redd.it", "redditmedia.com", "redditstatic.com", "reddituploads.com"],
    },
    "pinterest": {
        "name": "Pinterest",
        "domains": ["pinterest.com", "pinimg.com", "pin.it"],
    },
    "discord": {
        "name": "Discord",
        "domains": [
            "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com",
            "discord.new", "discord.gift", "dis.gd",
        ],
    },
    "telegram": {
        "name": "Telegram",
        "domains": ["telegram.org", "telegram.me", "t.me", "telegra.ph", "telesco.pe", "tdesktop.com"],
    },
    "twitch": {
        "name": "Twitch",
        "domains": ["twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net", "twitchsvc.net", "twitch.a2z.com"],
    },
    "netflix": {
        "name": "Netflix",
        "domains": ["netflix.com", "netflix.net", "nflxext.com", "nflximg.com", "nflximg.net", "nflxso.net", "nflxvideo.net"],
    },
    "disneyplus": {
        "name": "Disney+",
        "domains": ["disneyplus.com", "disney-plus.net", "dssott.com", "bamgrid.com", "disneystreaming.com"],
    },
    "primevideo": {
        "name": "Prime Video",
        "domains": ["primevideo.com", "aiv-cdn.net", "aiv-delivery.net", "amazonvideo.com"],
    },
    "spotify": {
        "name": "Spotify",
        "domains": ["spotify.com", "scdn.co", "spotifycdn.com", "spotifycdn.net", "spoti.fi", "pscdn.co", "audio-ak-spotify-com.akamaized.net"],
    },
    "roblox": {
        "name": "Roblox",
        "domains": ["roblox.com", "rbxcdn.com", "rbx.com", "robloxlabs.com", "roblox.cn"],
    },
    "fortnite": {
        "name": "Fortnite / Epic Games",
        "domains": ["epicgames.com", "fortnite.com", "unrealengine.com", "epicgames.dev", "static-assets-prod.epicgames.com"],
    },
    "minecraft": {
        "name": "Minecraft",
        "domains": ["minecraft.net", "mojang.com", "minecraftservices.com", "minecraft-services.net"],
    },
    "steam": {
        "name": "Steam",
        "domains": ["steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com", "steamserver.net", "steam-chat.com", "steamgames.com"],
    },
    "xbox": {
        "name": "Xbox Live",
        "domains": ["xboxlive.com", "xbox.com", "xboxservices.com", "xboxab.com"],
    },
    "playstation": {
        "name": "PlayStation Network",
        "domains": ["playstation.com", "playstation.net", "sonyentertainmentnetwork.com", "psn.com"],
    },
    "tinder": {
        "name": "Tinder",
        "domains": ["tinder.com", "gotinder.com"],
    },
    "chatgpt": {
        "name": "ChatGPT",
        "domains": ["chatgpt.com", "chat.openai.com", "oaistatic.com", "oaiusercontent.com"],
    },
    "kick": {
        "name": "Kick",
        "domains": ["kick.com"],
    },
    "9gag": {
        "name": "9GAG",
        "domains": ["9gag.com", "9cache.com"],
    },
}

# domain -> service id, for the per-query lookup.
_DOMAIN_TO_SERVICE: dict[str, str] = {
    domain: service_id for service_id, service in SERVICES.items() for domain in service["domains"]
}


def catalog() -> list[dict]:
    """The services the dashboard offers, sorted by name."""
    return sorted(
        ({"id": service_id, "name": service["name"], "domains": list(service["domains"])} for service_id, service in SERVICES.items()),
        key=lambda item: item["name"].lower(),
    )


def known_ids(ids: Iterable[str]) -> list[str]:
    """The given ids that exist, deduplicated, in catalogue order."""
    wanted = {str(i).strip().lower() for i in ids or []}
    return [service_id for service_id in SERVICES if service_id in wanted]


def service_for(qname: str) -> str | None:
    """The service a domain belongs to (itself or a parent domain), if any."""
    name = qname.rstrip(".").lower()
    while name:
        service_id = _DOMAIN_TO_SERVICE.get(name)
        if service_id is not None:
            return service_id
        _, _, name = name.partition(".")
    return None


def blocked_service(qname: str, blocked_ids: Iterable[str] | None) -> str | None:
    """The blocked service qname belongs to, or None."""
    if not blocked_ids:
        return None
    service_id = service_for(qname)
    if service_id is not None and service_id in blocked_ids:
        return service_id
    return None


def service_name(service_id: str) -> str:
    service = SERVICES.get(service_id)
    return service["name"] if service else service_id
